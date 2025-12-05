#![allow(clippy::too_many_arguments)]
use cryptomator_rs_crypto::{CryptoEntry, CryptoEntryType, CryptoError, Cryptomator, DirId, Seekable, SeekableRo, SeekableRw};
use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, ReplyXattr, Request, TimeOrNow};
use libc::{c_int, EBADF, EEXIST, EIO, ENOENT, O_CREAT, O_EXCL};
use lru::LruCache;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::fs::{File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::debug;
use tracing::Level;
use tracing_attributes::instrument;

static UID: Lazy<u32> = Lazy::new(getuid);
static GID: Lazy<u32> = Lazy::new(getgid);

const BLOCK_SIZE: u32 = 512;
const PERMISSIONS: u16 = 0o777;
type FuseResult<T> = Result<T, c_int>;


struct FileHandle {
    _ino: u64,
    _flags: i32,
    seekable: cryptomator_rs_crypto::FileHandle<Seekable<File, File>>,
    fuse_open_options: FuseOpenOptions,
}

pub struct CryptoFuse {
    pub crypto: Cryptomator,
    cache: LruCache<u64, CryptoEntryType>,
    handles: HashMap<u64, FileHandle>,
    handle_counter: u64,
}

impl CryptoFuse {
    fn next_handle(&mut self) -> u64 {
        self.handle_counter += 1;
        self.handle_counter
    }

    fn insert_in_cache(&mut self, ino: u64, entry: CryptoEntryType) {
        self.cache.push(ino, entry);
    }

    pub fn new(crypto: Cryptomator) -> Self {
        Self {
            crypto,
            cache: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            handles: HashMap::new(),
            handle_counter: 1000,
        }
    }
}

impl Deref for CryptoFuse {
    type Target = Cryptomator;

    fn deref(&self) -> &Self::Target {
        &self.crypto
    }
}
impl DerefMut for CryptoFuse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.crypto
    }
}

trait IntoErrorErrno<T> {
    fn to_errno(self) -> FuseResult<T>;
}
impl<T> IntoErrorErrno<T> for Result<T, CryptoError> {
    fn to_errno(self) -> FuseResult<T> {
        self.map_err(|e| e.to_errno().unwrap_or(EIO))
    }
}

impl<T> IntoErrorErrno<T> for Option<T> {
    fn to_errno(self) -> FuseResult<T> {
        self.ok_or(EIO)
    }
}

fn ino_from_entry(entry: &CryptoEntryType) -> u64 {
    if let CryptoEntryType::Directory { dir_id } = entry && dir_id.is_empty() {
        return 1;
    }
    let mut hasher = DefaultHasher::new();
    entry.hash(&mut hasher);
    hasher.finish()
}


fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

fn getgid() -> u32 {
    unsafe { libc::getgid() }
}


fn dir_to_file_attr(path: &CryptoEntryType) -> FuseResult<FileAttr> {
    if let CryptoEntryType::Directory { .. } = path {
        let ino = ino_from_entry(path);
        Ok(FileAttr {
            ino,
            size: 16384,
            blocks: 32,
            kind: FileType::Directory,
            nlink: 2,

            blksize: 4096,
            perm: PERMISSIONS,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            uid: *UID,
            gid: *GID,
            rdev: 0,
            flags: 0,
        })
    } else {
        unreachable!()
    }
}
fn sym_to_file_attr(path: &CryptoEntryType) -> FuseResult<FileAttr> {
    if let CryptoEntryType::Symlink { target } = path {
        let ino = ino_from_entry(path);
        Ok(FileAttr {
            ino,
            size: target.len() as u64,
            blocks: (target.len() as u64).div_ceil(BLOCK_SIZE as u64),
            kind: FileType::Symlink,
            nlink: 1,

            perm: PERMISSIONS,
            blksize: BLOCK_SIZE,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            uid: *UID,
            gid: *GID,
            rdev: 0,
            flags: 0,
        })
    } else {
        unreachable!()
    }
}

fn file_to_file_attr(mator: &Cryptomator, path: &CryptoEntryType) -> FuseResult<FileAttr> {
    if let CryptoEntryType::File { abs_path } = path {
        let abs_path = mator.vault_root().join(abs_path);
        let metadata = fs::metadata(&abs_path).map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        let ino = ino_from_entry(path);
        let size = Cryptomator::encrypted_file_size(&abs_path).to_errno()?;
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(BLOCK_SIZE as u64),
            kind: FileType::RegularFile,
            nlink: 1,

            perm: PERMISSIONS,
            blksize: BLOCK_SIZE,
            atime: metadata.accessed().unwrap_or_else(|_| SystemTime::now()),
            mtime: metadata.modified().unwrap_or_else(|_| SystemTime::now()),
            ctime: metadata.created().unwrap_or_else(|_| SystemTime::now()),
            crtime: metadata.created().unwrap_or_else(|_| SystemTime::now()),
            uid: *UID,
            gid: *GID,
            rdev: 0,
            flags: 0,
        })
    } else {
        unreachable!()
    }
}

fn entry_to_file_attr(vault_root: &Cryptomator, entry: &CryptoEntryType) -> FuseResult<FileAttr> {
    match entry {
        CryptoEntryType::Symlink { .. } => { sym_to_file_attr(entry) }
        CryptoEntryType::Directory { .. } => { dir_to_file_attr(entry) }
        CryptoEntryType::File { .. } => { file_to_file_attr(vault_root, entry) }
    }
}
#[instrument(skip(fuse), level=Level::DEBUG,ret,err(level=Level::DEBUG))]
fn getattr(fuse: &mut CryptoFuse, ino: u64, _fh: Option<u64>) -> Result<FileAttr, c_int> {
    if let Some(x) = fuse.cache.get(&ino) {
        let attr = entry_to_file_attr(&fuse.crypto, x)?;
        Ok(attr)
    } else if ino == 1 {
        let entry = CryptoEntryType::Directory { dir_id: Box::new([]) };
        let x = entry_to_file_attr(&fuse.crypto, &entry)?;
        fuse.insert_in_cache(x.ino, entry);
        Ok(x)
    } else {
        Err(EIO)
    }
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err(level=Level::DEBUG))]
fn lookup(fuse: &mut CryptoFuse, parent: u64, name: &OsStr) -> Result<FileAttr, c_int> {
    let x = fuse.cache.get(&parent).to_errno()?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).to_errno()?;
    let name = name.to_str().to_errno()?;
    let child = parent.lookup(name).to_errno()?;
    let child = child.ok_or(ENOENT)?;
    let attr = entry_to_file_attr(&fuse.crypto, &child.entry_type)?;
    fuse.insert_in_cache(attr.ino, child.entry_type);
    Ok(attr)
}

#[derive(Debug)]
struct ReadDirEntry {
    ino: u64,
    index: i64,
    file_type: FileType,
    name: Box<str>,
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn readdir(fuse: &mut CryptoFuse, ino: u64, _fh: u64, offset: i64) -> Result<Vec<ReadDirEntry>, c_int> {
    let x = fuse.cache.get(&ino).to_errno()?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).to_errno()?;
    let mut files = parent.list_files().to_errno()?;
    files.sort_unstable_by(|o1, o2| o1.name.cmp(&o2.name));
    let mut v = Vec::new();
    for (idx, file) in files.iter().enumerate().skip(offset as usize) {
        let ino = entry_to_file_attr(&fuse.crypto, &file.entry_type)?;
        let CryptoEntry { name, entry_type } = file.clone();
        fuse.cache.push(ino.ino, entry_type);
        v.push(ReadDirEntry {
            ino: ino.ino,
            index: idx as i64 + 1,
            file_type: ino.kind,
            name,
        });
    }
    Ok(v)
}


#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn readlink(fuse: &mut CryptoFuse, ino: u64) -> Result<Vec<u8>, c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    let target = k.symlink();
    Ok(target.as_bytes().to_vec())
}

#[instrument(skip(fuse), level=Level::DEBUG,err)]
fn read(fuse: &mut CryptoFuse, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>) -> Result<Vec<u8>, c_int> {
    let FileHandle { seekable, fuse_open_options, .. } = fuse.handles.get_mut(&fh).ok_or(EBADF)?;
    if !fuse_open_options.read { return Err(EBADF); }
    let read = seekable.read_data(offset as usize, size as usize).to_errno()?;
    Ok(read)
}
#[derive(Copy, Clone, Debug, Default)]
struct FuseOpenOptions {
    write: bool,
    read: bool,
    append: bool,
    create: bool,
    create_new: bool,
    truncate: bool,
}
impl FuseOpenOptions {
    fn to_file_options(self) -> OpenOptions {
        let mut options = File::options();
        if self.write { options.write(true); }
        if self.read || self.write { options.read(true); }
        options
    }
    fn from_flags(flags: i32) -> Self {
        let mut options = FuseOpenOptions::default();
        if flags & libc::O_APPEND != 0 {
            options.append = true;
        }
        if flags & O_CREAT != 0 {
            options.create = true;
            if flags & O_EXCL != 0 {
                options.create_new = true;
            }
        }
        if flags & libc::O_TRUNC != 0 {
            options.truncate = true;
        }
        if flags & libc::O_ACCMODE == libc::O_WRONLY {
            options.write = true;
        }
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            options.read = true;
        }
        if flags & libc::O_ACCMODE == libc::O_RDWR {
            options.write = true;
            options.read = true;
        }
        options
    }
}
#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn open(fuse: &mut CryptoFuse, ino: u64, flags: i32) -> Result<u64, c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    let path = fuse.crypto.vault_root().join(k.file());
    let options = FuseOpenOptions::from_flags(flags);

    if options.create_new {
        return Err(EEXIST);
    }

    if options.truncate {
        fuse.crypto.truncate_to_size(&path, 0).to_errno()?;
    }

    let x = options.to_file_options().open(path).map_err(|x| {
        match x.raw_os_error() {
            None => EIO,
            Some(x) => x,
        }
    })?;
    let handle = fuse.next_handle();
    let seekable = if options.write {
        Seekable::Rw(SeekableRw::from_file(x).to_errno()?)
    } else {
        Seekable::Ro(SeekableRo::from_file(x))
    };
    fuse.handles.insert(handle, FileHandle {
        _ino: ino,
        _flags: flags,
        seekable: fuse.file_handle(seekable).to_errno()?,
        fuse_open_options: options,
    });
    Ok(handle)
}

#[instrument(skip(fuse,data), level=Level::DEBUG,ret,err)]
fn write(fuse: &mut CryptoFuse, _ino: u64, fh: u64, mut offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>) -> Result<u32, c_int> {
    let FileHandle { seekable, fuse_open_options, .. } = fuse.handles.get_mut(&fh).ok_or(EBADF)?;
    if !fuse_open_options.write { return Err(EBADF); }
    if fuse_open_options.append {
        offset = seekable.file_size().to_errno()? as i64;
    }
    seekable.write_data(offset as usize, data).to_errno()?;
    Ok(data.len() as u32)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn create(fuse: &mut CryptoFuse, parent: u64, name: &OsStr, _mode: u32, _umask: u32, flags: i32, open_file: bool) -> Result<(FileAttr, u64), c_int> {
    let fuse_flags = FuseOpenOptions::from_flags(flags);
    let flags = flags & (!(O_CREAT | O_EXCL));
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let name = name.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_file(&dir_id, name, fuse_flags.create_new).to_errno()?;
    let attr = entry_to_file_attr(&fuse.crypto, &entry.entry_type)?;
    fuse.insert_in_cache(attr.ino, entry.entry_type);
    let fd = if open_file { open(fuse, attr.ino, flags)? } else { 0 };
    Ok((attr, fd))
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn setattr(fuse: &mut CryptoFuse, ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, _size: Option<u64>, _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>, _fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>) -> Result<FileAttr, c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    entry_to_file_attr(&fuse.crypto, k)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn mkdir(fuse: &mut CryptoFuse, parent: u64, name: &OsStr, _mode: u32, _umask: u32) -> Result<FileAttr, c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let name = name.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_directory(&dir_id, name).to_errno()?;
    let attr = entry_to_file_attr(&fuse.crypto, &entry.entry_type)?;
    fuse.insert_in_cache(attr.ino, entry.entry_type);
    Ok(attr)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn symlink(fuse: &mut CryptoFuse, parent: u64, link_name: &OsStr, target: &Path) -> Result<FileAttr, c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let link_name = link_name.to_str().to_errno()?;
    let target = target.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_symlink(&dir_id, link_name, target).to_errno()?;
    let attr = entry_to_file_attr(&fuse.crypto, &entry.entry_type)?;
    fuse.insert_in_cache(attr.ino, entry.entry_type);
    Ok(attr)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn mknod(fuse: &mut CryptoFuse, parent: u64, name: &OsStr, mode: u32, umask: u32, _rdev: u32) -> Result<FileAttr, c_int> {
    if mode & libc::S_IFREG != libc::S_IFREG {
        return Err(libc::ENOTSUP);
    }
    create(fuse, parent, name, mode, umask, 0, false).map(|(a, _)| a)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn unlink(fuse: &mut CryptoFuse, parent: u64, name: &OsStr) -> Result<(), c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let name = name.to_str().to_errno()?;
    let v = fuse.crypto.delete_entry(&dir_id, name).to_errno()?;
    v.ok_or(ENOENT)
}

#[instrument(skip(fuse), level=Level::DEBUG,ret,err)]
fn rename(fuse: &mut CryptoFuse, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, flags: u32) -> Result<(), c_int> {
    if flags & (libc::RENAME_EXCHANGE | libc::RENAME_WHITEOUT) != 0 {
        return Err(libc::EINVAL);
    }
    let old_parent = fuse.cache.get(&parent).to_errno()?.directory();
    let old_dir_id = DirId::from_str(old_parent, &fuse.crypto).to_errno()?;
    let new_parent = fuse.cache.get(&newparent).to_errno()?.directory();
    let new_dir_id = DirId::from_str(new_parent, &fuse.crypto).to_errno()?;
    let old_name = name.to_str().to_errno()?;
    let new_name = newname.to_str().to_errno()?;
    fuse.crypto.rename(&old_dir_id, old_name, &new_dir_id, new_name, flags & libc::RENAME_NOREPLACE != 0).to_errno()?;
    Ok(())
}

#[allow(unused_variables)]
impl Filesystem for CryptoFuse {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let res = lookup(self, parent, name);
        match res {
            Ok(x) => reply.entry(&Duration::from_secs(2), &x, 0),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        let res = getattr(self, ino, fh);
        match res {
            Ok(x) => reply.attr(&Duration::from_secs(2), &x),
            Err(e) => reply.error(e),
        }
    }
    fn setattr(&mut self, _req: &Request<'_>, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>, _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>, fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, flags: Option<u32>, reply: ReplyAttr) {
        let res = setattr(self, ino, mode, uid, gid, size, _atime, _mtime, _ctime, fh, _crtime, _chgtime, _bkuptime, flags);
        match res {
            Ok(attr) => reply.attr(&Duration::from_secs(2), &attr),
            Err(e) => reply.error(e),
        }
    }
    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let res = readlink(self, ino);
        match res {
            Ok(x) => reply.data(&x),
            Err(e) => reply.error(e),
        }
    }

    fn mknod(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
        let res = mknod(self, parent, name, mode, umask, rdev);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(2), &attr, 0),
            Err(e) => reply.error(e),
        }
    }
    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        let res = mkdir(self, parent, name, mode, umask);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(2), &attr, 0),
            Err(e) => reply.error(e),
        }
    }
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let res = unlink(self, parent, name);
        match res {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let res = unlink(self, parent, name);
        match res {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn symlink(&mut self, _req: &Request<'_>, parent: u64, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        let res = symlink(self, parent, link_name, target);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(2), &attr, 0),
            Err(e) => reply.error(e),
        }
    }
    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, flags: u32, reply: ReplyEmpty) {
        let res = rename(self, parent, name, newparent, newname, flags);
        match res {
            Ok(x) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let res = open(self, ino, flags);
        match res {
            Ok(x) => reply.opened(x, 0),
            Err(e) => reply.error(e),
        }
    }

    fn read(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, size: u32, flags: i32, lock_owner: Option<u64>, reply: ReplyData) {
        let res = read(self, ino, fh, offset, size, flags, lock_owner);
        match res {
            Ok(x) => {
                debug!("read {} bytes on fh {fh}, offset {offset}, size {size}", x.len());
                reply.data(x.as_slice())
            }
            Err(e) => reply.error(e),
        }
    }

    fn write(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, data: &[u8], write_flags: u32, flags: i32, lock_owner: Option<u64>, reply: ReplyWrite) {
        let res = write(self, ino, fh, offset, data, write_flags, flags, lock_owner);
        match res {
            Ok(x) => reply.written(x),
            Err(e) => reply.error(e),
        }
    }


    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        // flushed after each R/W operation
        reply.ok();
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        self.handles.remove(&fh);
        reply.ok();
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        reply.ok()
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let res = readdir(self, ino, fh, offset);
        match res {
            Ok(x) => {
                for ReadDirEntry { ino, index, file_type, name } in x {
                    if reply.add(ino, index, file_type, name.as_ref()) { break; }
                }
                reply.ok();
            }
            Err(e) => reply.error(e),
        }
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn fsyncdir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        reply.ok()
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn getxattr(&mut self, _req: &Request<'_>, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        reply.error(libc::ENOTSUP)
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        // xattr not supported in cryptomator
        reply.error(libc::ENOTSUP)
    }

    #[instrument(skip(self,_req,reply),level = Level::DEBUG)]
    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        // 0777 perm always
        reply.ok();
    }

    fn create(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, flags: i32, reply: ReplyCreate) {
        let res = create(self, parent, name, mode, umask, flags, true);
        match res {
            Ok((attr, fd)) => reply.created(&Duration::from_secs(2), &attr, 0, fd, 0),
            Err(e) => reply.error(e),
        }
    }
}