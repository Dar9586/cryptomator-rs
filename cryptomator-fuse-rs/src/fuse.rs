use anyhow::{anyhow, Error, Result};
use cryptomator_crypto::{CryptoEntry, CryptoEntryType, Cryptomator, DirId};
use fuser::{fuse_forget_one, FileAttr, FileType, Filesystem, KernelConfig, PollHandle, ReplyAttr, ReplyBmap, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock, ReplyLseek, ReplyOpen, ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow};
use libc::{c_int, EBADF, EINVAL, EIO, ENOENT, ENOSYS};
use lru::LruCache;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufReader, ErrorKind};
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::info;
use tracing_attributes::instrument;

const BLOCK_SIZE: u32 = 512;
const DIRECTORY_BLOCK_COUNT: u64 = 8;
const PERMISSIONS: u16 = 0o777;

pub struct CryptoFuse {
    pub crypto: Cryptomator,
    cache: LruCache<u64, CryptoEntryType>,
    handles: HashMap<u64, (u64, i32, BufReader<File>)>,
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

fn entry_hash(entry: &CryptoEntryType) -> u64 {
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



fn dir_to_file_attr(path: &CryptoEntryType) -> Result<FileAttr> {
    if let CryptoEntryType::Directory { .. } = path {
        let ino = entry_hash(path);
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
fn sym_to_file_attr(path: &CryptoEntryType) -> Result<FileAttr> {
    if let CryptoEntryType::Symlink { target } = path {
        let ino = entry_hash(path);
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

fn file_to_file_attr(path: &CryptoEntryType) -> Result<FileAttr> {
    if let CryptoEntryType::File { abs_path } = path {
        let ino = entry_hash(path);
        let size = cryptomator_crypto::encrypted_file_size(abs_path)?;
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

fn entry_to_file_attr(entry: &CryptoEntryType) -> Result<FileAttr> {
    match entry {
        CryptoEntryType::Symlink { .. } => { sym_to_file_attr(entry) },
        CryptoEntryType::Directory { .. } => { dir_to_file_attr(entry) },
        CryptoEntryType::File { .. } => { file_to_file_attr(entry) },
    }
}

fn getattr(fuse: &mut CryptoFuse, _req: &Request<'_>, ino: u64, fh: Option<u64>) -> Result<FileAttr, c_int> {
    if let Some(x) = fuse.cache.get(&ino) {
        let attr = entry_to_file_attr(x).map_err(|_| EIO)?;
        Ok(attr)
    } else if ino == 1 {
        let entry = CryptoEntryType::Directory { dir_id: "".to_string() };
        let x = entry_to_file_attr(&entry).map_err(|_| EIO)?;
        fuse.insert_in_cache(Some(ino), entry);
        Ok(x)
    } else {
        Err(EIO)
    }
}

fn lookup(fuse: &mut CryptoFuse, _req: &Request<'_>, parent: u64, name: &OsStr) -> Result<FileAttr, c_int> {
    let x = fuse.cache.get(&parent).ok_or_else(|| EIO)?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).map_err(|_| EIO)?;
    let name = name.to_str().unwrap();
    let child = parent.lookup(name).map_err(|_| EIO)?;
    let child = child.ok_or_else(|| ENOENT)?;
    let attr = entry_to_file_attr(&child.entry_type).map_err(|_| EIO)?;
    fuse.insert_in_cache(None, child.entry_type);
    Ok(attr)
}

fn readdir(fuse: &mut CryptoFuse, _req: &Request<'_>, ino: u64, fh: u64, offset: i64) -> Result<Vec<(u64, i64, FileType, String)>, c_int> {
    let x = fuse.cache.get(&ino).ok_or_else(|| EIO)?;
    let dir_id = x.directory();
    let parent = DirId::from_str(dir_id, &fuse.crypto).map_err(|_| EIO)?;
    let mut files = parent.list_files().map_err(|_| EIO)?;
    files.sort_unstable_by(|o1, o2| o1.name.cmp(&o2.name));
    let mut v = Vec::new();
    for (idx, file) in files.iter().enumerate().skip(offset as usize) {
        let ino = entry_to_file_attr(&file.entry_type).map_err(|_| EIO)?;
        let CryptoEntry { name, entry_type } = file.clone();
        fuse.cache.push(ino.ino, entry_type);
        v.push((ino.ino, idx as i64 + 1, ino.kind, name));
    }
    Ok(v)
}


fn readlink<'a>(fuse: &'a mut CryptoFuse, _req: &Request<'_>, ino: u64) -> Result<&'a [u8], c_int> {
    let k = fuse.cache.get(&ino).ok_or_else(|| EIO)?;
    let target = k.symlink();
    Ok(target.as_bytes())
}

fn read(fuse: &mut CryptoFuse, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>) -> Result<Vec<u8>, c_int> {
    let (ino, flags, file) = fuse.handles.get_mut(&fh).ok_or_else(|| EBADF)?;
    assert_eq!(*ino, _ino);
    assert_eq!(*flags, _flags);
    let mut x = fuse.crypto.read_seek(file).map_err(|_| EIO)?;
    let read = x.read(offset as usize, size as usize).map_err(|_| EIO)?;
    Ok(read)
}

fn open(fuse: &mut CryptoFuse, _req: &Request<'_>, ino: u64, flags: i32) -> Result<u64, c_int> {
    let k = fuse.cache.get(&ino).ok_or_else(|| EIO)?;
    let path = k.file();
    let mut options = File::options();
    if flags & libc::O_APPEND != 0 {
        options.append(true);
    }
    if flags & libc::O_CREAT != 0 {
        options.create(true);
        if flags & libc::O_EXCL != 0 {
            options.create_new(true);
        }
    }
    if flags & libc::O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & 0x3 == libc::O_WRONLY {
        options.write(true);
    }
    if flags & 0x3 == libc::O_RDONLY {
        options.read(true);
    }
    if flags & 0x3 == libc::O_RDWR {
        options.write(true);
        options.read(true);
    }
    options.open(path).map(|x| {
        let reader = BufReader::new(x);
        let handle = fuse.next_handle();
        fuse.handles.insert(handle, (ino, flags, reader));
        handle
    }).map_err(|x| {
        match x.raw_os_error() {
            None => EIO,
            Some(x) => x,
        }
    })
}

impl Filesystem for CryptoFuse {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        info!("lookup(parent: {parent:#x?}, name {name:?})");
        let res = lookup(self, _req, parent, name);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.entry(&Duration::from_secs(0), &x, 0),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        info!("getattr(ino: {ino:#x?}, fh: {fh:x?})");
        let res = getattr(self, _req, ino, fh);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.attr(&Duration::from_secs(0), &x),
            Err(e) => reply.error(e),
        }
    }
    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        info!("readlink(ino: {ino:#x?})");
        let res = readlink(self, _req, ino);
        //info!("getattr(response: {res:?}");
        match res {
            Ok(x) => reply.data(&x),
            Err(e) => reply.error(e),
        }
    }


    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        info!("open(ino: {ino:#x?}, flags: {flags:#x?})");
        let res = open(self, _req, ino, flags);
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
        let res = read(self, _req, ino, fh, offset, size, flags, lock_owner);
        match res {
            Ok(x) => reply.data(x.as_slice()),
            Err(e) => reply.error(e),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        // flushed after each R/W operation
        info!("flush(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner:?})");
        reply.ok();
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        info!("release(ino: {_ino:#x?}, fh: {fh:#x?}, flags: {_flags:#x?}, lock_owner: {_lock_owner:?}, flush: {_flush})");
        self.handles.remove(&fh);
        reply.ok();
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: ReplyDirectory) {
        info!("readdir(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
        let res = readdir(self, _req, ino, fh, offset);
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

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        // xattr not supported in cryptomator
        info!("listxattr(ino: {ino:#x?}, size: {size})");
        if size==0{
            reply.size(0)
        }else {
            reply.data(&[]);
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        // 0777 perm always
        info!("access(ino: {ino:#x?}, mask: {mask})");
        reply.ok();
    }
}