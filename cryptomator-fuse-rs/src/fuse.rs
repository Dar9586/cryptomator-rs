use cryptomator_crypto::{CryptoEntry, CryptoEntryType, CryptoError, Cryptomator, DirId, Seekable};
use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen, ReplyWrite, ReplyXattr, Request, TimeOrNow};
use libc::{c_int, EBADF, EIO, ENOENT, O_CREAT, O_EXCL};
use lru::LruCache;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::info;

const BLOCK_SIZE: u32 = 512;
const DIRECTORY_BLOCK_COUNT: u64 = 8;
const PERMISSIONS: u16 = 0o777;
type FuseResult<T> = Result<T, c_int>;
struct FileHandle {
    ino: u64,
    flags: i32,
    seekable: Seekable<File>,
    offset: i64,
}

pub struct CryptoFuse {
    pub crypto: Cryptomator,
    cache: LruCache<u64, CryptoEntryType>,
    handles: HashMap<u64, FileHandle>,
    ino_counter: u64,
    handle_counter: u64,
    uid: u32,
    gid: u32,
}

impl CryptoFuse {
    fn next_ino(&mut self) -> u64 {
        self.ino_counter += 1;
        self.ino_counter
    }

    fn next_handle(&mut self) -> u64 {
        self.handle_counter += 1;
        self.ino_counter
    }

    fn insert_in_cache(&mut self, ino: Option<u64>, entry: CryptoEntryType) {
        let ino = ino.unwrap_or_else(|| self.next_ino());
        self.cache.push(ino, entry);
    }
}

impl CryptoFuse {
    pub fn new(crypto: Cryptomator) -> Self {
        Self {
            crypto,
            cache: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            handles: HashMap::new(),
            handle_counter: 1000,
            ino_counter: 1000,
            uid: getuid(),
            gid: getgid(),
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
        self.ok_or(libc::EIO)
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
            size: BLOCK_SIZE as u64 * DIRECTORY_BLOCK_COUNT,
            blocks: DIRECTORY_BLOCK_COUNT,
            kind: FileType::Directory,
            nlink: 2,

            blksize: BLOCK_SIZE,
            perm: PERMISSIONS,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            uid: 1000,
            gid: 1000,
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
            uid: 1000,
            gid: 1000,
            rdev: 0,
            flags: 0,
        })
    } else {
        unreachable!()
    }
}

fn file_to_file_attr(path: &CryptoEntryType) -> FuseResult<FileAttr> {
    if let CryptoEntryType::File { abs_path } = path {
        let ino = ino_from_entry(path);
        let size = cryptomator_crypto::encrypted_file_size(abs_path).to_errno()?;
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(BLOCK_SIZE as u64),
            kind: FileType::RegularFile,
            nlink: 1,

            perm: PERMISSIONS,
            blksize: BLOCK_SIZE,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            uid: 1000,
            gid: 1000,
            rdev: 0,
            flags: 0,
        })
    } else {
        unreachable!()
    }
}

fn entry_to_file_attr(entry: &CryptoEntryType) -> FuseResult<FileAttr> {
    match entry {
        CryptoEntryType::Symlink { .. } => { sym_to_file_attr(entry) },
        CryptoEntryType::Directory { .. } => { dir_to_file_attr(entry) },
        CryptoEntryType::File { .. } => { file_to_file_attr(entry) },
    }
}

fn getattr(fuse: &mut CryptoFuse, ino: u64, fh: Option<u64>) -> Result<FileAttr, c_int> {
    if let Some(x) = fuse.cache.get(&ino) {
        let attr = entry_to_file_attr(x)?;
        Ok(attr)
    } else if ino == 1 {
        let entry = CryptoEntryType::Directory { dir_id: vec![] };
        let x = entry_to_file_attr(&entry)?;
        fuse.insert_in_cache(Some(ino), entry);
        Ok(x)
    } else {
        Err(EIO)
    }
}

fn lookup(fuse: &mut CryptoFuse, parent: u64, name: &OsStr) -> Result<FileAttr, c_int> {
    let x = fuse.cache.get(&parent).to_errno()?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).to_errno()?;
    let name = name.to_str().unwrap();
    let child = parent.lookup(name).to_errno()?;
    let child = child.ok_or_else(|| ENOENT)?;
    let attr = entry_to_file_attr(&child.entry_type)?;
    fuse.insert_in_cache(None, child.entry_type);
    Ok(attr)
}

fn readdir(fuse: &mut CryptoFuse, ino: u64, fh: u64, offset: i64) -> Result<Vec<(u64, i64, FileType, String)>, c_int> {
    let x = fuse.cache.get(&ino).to_errno()?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).to_errno()?;
    let mut files = parent.list_files().to_errno()?;
    files.sort_unstable_by(|o1, o2| o1.name.cmp(&o2.name));
    let mut v = Vec::new();
    for (idx, file) in files.iter().enumerate().skip(offset as usize) {
        let ino = entry_to_file_attr(&file.entry_type)?;
        let CryptoEntry { name, entry_type } = file.clone();
        fuse.cache.push(ino.ino, entry_type);
        v.push((ino.ino, idx as i64 + 1, ino.kind, name));
    }
    Ok(v)
}


fn readlink(fuse: &mut CryptoFuse, ino: u64) -> Result<&[u8], c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    let target = k.symlink();
    Ok(target.as_bytes())
}

fn read(fuse: &mut CryptoFuse, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>) -> Result<Vec<u8>, c_int> {
    let FileHandle { ino, flags, seekable, offset } = fuse.handles.get_mut(&fh).ok_or_else(|| EBADF)?;
    assert_eq!(*ino, _ino);
    assert_eq!(*flags, _flags);
    let mut x = fuse.crypto.read_seek(seekable).to_errno()?;
    let read = x.read(*offset as usize, size as usize).to_errno()?;
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
    fn to_file_options(&self) -> OpenOptions {
        let mut options = File::options();
        if self.write { options.write(true); }
        if self.read { options.read(true); }
        if self.append { options.append(true); }
        if self.create { options.create(true); }
        if self.create_new { options.create_new(true); }
        if self.truncate { options.truncate(true); }
        options
    }
    fn from_flags(flags: i32) -> Self {
        let mut options = FuseOpenOptions::default();
        if flags & libc::O_APPEND != 0 {
            options.append = true;
        }
        if flags & libc::O_CREAT != 0 {
            options.create = true;
            if flags & libc::O_EXCL != 0 {
                options.create_new = true;
            }
        }
        if flags & libc::O_TRUNC != 0 {
            options.truncate = true;
        }
        if flags & 0x3 == libc::O_WRONLY {
            options.write = true;
        }
        if flags & 0x3 == libc::O_RDONLY {
            options.read = true;
        }
        if flags & 0x3 == libc::O_RDWR {
            options.write = true;
            options.read = true;
        }
        options
    }
}
fn open(fuse: &mut CryptoFuse, ino: u64, flags: i32) -> Result<u64, c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    let path = k.file();
    let options = FuseOpenOptions::from_flags(flags);

    if options.create || options.create_new {
        todo!("Find parent file and call create");
    }

    let x = options.to_file_options().open(path).map_err(|x| {
        match x.raw_os_error() {
            None => EIO,
            Some(x) => x,
        }
    })?;
    let handle = fuse.next_handle();
    let seekable = if options.write {
        Seekable::from_file(x).to_errno()?
    } else {
        Seekable::new(x, None)
    };
    fuse.handles.insert(handle, FileHandle {
        ino,
        flags,
        seekable,
        offset: 0,
    });
    Ok(handle)
}

fn write(fuse: &mut CryptoFuse, _ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>) -> Result<u32, c_int> {
    let FileHandle { ino, flags, seekable, offset } = fuse.handles.get_mut(&fh).ok_or_else(|| EBADF)?;
    let mut writer = fuse.crypto.file_writer(seekable).to_errno()?;
    writer.write(*offset as usize, data).to_errno()?;
    Ok(data.len() as u32)
}

fn create(fuse: &mut CryptoFuse, parent: u64, name: &OsStr, mode: u32, umask: u32, flags: i32, open_file: bool) -> Result<(FileAttr, u64), c_int> {
    let flags = flags & (!(O_CREAT | O_EXCL));
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let name = name.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_file(&dir_id, name).to_errno()?;
    let attr = entry_to_file_attr(&entry.entry_type)?;
    let fd = if open_file { open(fuse, attr.ino, flags)? } else { 0 };
    Ok((attr, fd))
}

fn setattr(fuse: &mut CryptoFuse, _req: &Request<'_>, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>, _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>, fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, flags: Option<u32>) -> Result<FileAttr, c_int> {
    let k = fuse.cache.get(&ino).to_errno()?;
    entry_to_file_attr(k)
}

fn mkdir(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32) -> Result<FileAttr, c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let name = name.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_directory(&dir_id, name).to_errno()?;
    let attr = entry_to_file_attr(&entry.entry_type)?;
    Ok(attr)
}

fn symlink(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, link_name: &OsStr, target: &Path) -> Result<FileAttr, c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let link_name = link_name.to_str().to_errno()?;
    let target = target.to_str().to_errno()?;
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let entry = fuse.crypto.create_symlink(&dir_id, link_name, target).to_errno()?;
    let attr = entry_to_file_attr(&entry.entry_type)?;
    Ok(attr)
}

fn mknod(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32) -> Result<FileAttr, c_int> {
    if mode & libc::S_IFREG != libc::S_IFREG {
        return Err(libc::ENOTSUP);
    }
    create(fuse, parent, name, mode, umask, 0, false).map(|(a, b)| a)
}

fn unlink(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, name: &OsStr) -> Result<(), c_int> {
    let parent = fuse.cache.get(&parent).to_errno()?.directory();
    let dir_id = DirId::from_str(parent, &fuse.crypto).to_errno()?;
    let name = name.to_str().to_errno()?;
    let v = fuse.crypto.delete_entry(&dir_id, name).to_errno()?;
    v.ok_or_else(|| libc::ENOENT)
}

fn rename(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, flags: u32) -> Result<(), c_int> {
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


fn lseek(fuse: &mut CryptoFuse, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, whence: i32) -> Result<i64, c_int> {
    let FileHandle { ino, flags, seekable, offset: fd_offset } = fuse.handles.get_mut(&fh).ok_or_else(|| EBADF)?;
    let new_offset = match whence {
        libc::SEEK_SET => 0,
        libc::SEEK_END => cryptomator_crypto::encrypted_file_size_from_seekable(seekable).to_errno()? as i64,
        libc::SEEK_CUR => *fd_offset,
        libc::SEEK_DATA | libc::SEEK_HOLE => return Err(libc::ENOSYS),
        _ => unreachable!()
    } + offset;
    *fd_offset = new_offset;
    Ok(new_offset)
}

impl Filesystem for CryptoFuse {

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // info!"lookup(parent: {parent:#x?}, name {name:?})");
        let res = lookup(self, parent, name);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.entry(&Duration::from_secs(0), &x, 0),
            Err(e) => reply.error(e),
        }
    }
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        // info!"getattr(ino: {ino:#x?}, fh: {fh:x?})");
        let res = getattr(self, ino, fh);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.attr(&Duration::from_secs(0), &x),
            Err(e) => reply.error(e),
        }
    }
    fn setattr(&mut self, _req: &Request<'_>, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>, _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>, fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, flags: Option<u32>, reply: ReplyAttr) {
        let res = setattr(self, _req, ino, mode, uid, gid, size, _atime, _mtime, _ctime, fh, _crtime, _chgtime, _bkuptime, flags);
        match res {
            Ok(attr) => reply.attr(&Duration::from_secs(0), &attr),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        // info!"readlink(ino: {ino:#x?})");
        let res = readlink(self, ino);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.data(&x),
            Err(e) => reply.error(e),
        }
    }
    fn mknod(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
        let res = mknod(self, _req, parent, name, mode, umask, rdev);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(0), &attr, 0),
            Err(e) => reply.error(e),
        }
    }
    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        let res = mkdir(self, _req, parent, name, mode, umask);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(0), &attr, 0),
            Err(e) => reply.error(e),
        }
    }
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let res = unlink(self, _req, parent, name);
        match res {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let res = unlink(self, _req, parent, name);
        match res {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn symlink(&mut self, _req: &Request<'_>, parent: u64, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        let res = symlink(self, _req, parent, link_name, target);
        match res {
            Ok(attr) => reply.entry(&Duration::from_secs(0), &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, flags: u32, reply: ReplyEmpty) {
        let res = rename(self, _req, parent, name, newparent, newname, flags);
        match res {
            Ok(x) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        // info!"open(ino: {ino:#x?}, flags: {flags:#x?})");
        let res = open(self, ino, flags);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.opened(x, 0),
            Err(e) => reply.error(e),
        }
    }
    fn read(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, size: u32, flags: i32, lock_owner: Option<u64>, reply: ReplyData) {
        info!(
            "read(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
            size: {size}, flags: {flags:#x?}, lock_owner: {lock_owner:?})"
        );
        let res = read(self, ino, fh, offset, size, flags, lock_owner);
        match res {
            Ok(x) => reply.data(x.as_slice()),
            Err(e) => reply.error(e),
        }
    }


    fn write(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, data: &[u8], write_flags: u32, flags: i32, lock_owner: Option<u64>, reply: ReplyWrite) {
        // info!
        //    "[Not Implemented] write(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
        //    data.len(): {}, write_flags: {write_flags:#x?}, flags: {flags:#x?}, \
        //    lock_owner: {lock_owner:?})",
        //    data.len()
        //);

        let res = write(self, ino, fh, offset, data, write_flags, flags, lock_owner);
        match res {
            Ok(x) => reply.written(x),
            Err(e) => reply.error(e),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        // flushed after each R/W operation
        // info!"flush(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner:?})");
        reply.ok();
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        // info!"release(ino: {_ino:#x?}, fh: {fh:#x?}, flags: {_flags:#x?}, lock_owner: {_lock_owner:?}, flush: {_flush})");
        self.handles.remove(&fh);
        reply.ok();
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
        // info!"readdir(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
        let res = readdir(self, ino, fh, offset);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => {
                for (ino, offset, kind, name) in x {
                    if reply.add(ino, offset, kind, name) { break }
                }
                reply.ok();
            },
            Err(e) => reply.error(e),
        }
    }

    fn getxattr(&mut self, _req: &Request<'_>, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        // xattr not supported in cryptomator
        // info!"getxattr(ino: {ino:#x?}, name: {name:?}, size: {size})");
        if size == 0 {
            reply.size(0)
        } else {
            reply.data(&[]);
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        // xattr not supported in cryptomator
        // info!"listxattr(ino: {ino:#x?}, size: {size})");
        if size==0{
            reply.size(0)
        }else {
            reply.data(&[]);
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        // 0777 perm always
        // info!"access(ino: {ino:#x?}, mask: {mask})");
        reply.ok();
    }

    fn create(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, mode: u32, umask: u32, flags: i32, reply: ReplyCreate) {
        let res = create(self, parent, name, mode, umask, flags, true);
        match res {
            Ok((attr, fd)) => reply.created(&Duration::from_secs(0), &attr, 0, fd, 0),
            Err(e) => reply.error(e),
        }
    }

    fn lseek(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, whence: i32, reply: ReplyLseek) {
        let res = lseek(self, _req, ino, fh, offset, whence);
        match res {
            Ok(v) => reply.offset(v),
            Err(e) => reply.error(e),
        }
    }
}