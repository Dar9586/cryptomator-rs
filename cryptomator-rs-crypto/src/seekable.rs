use crate::errors::Result;
use crate::CryptoError;
use libc::EBADF;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub struct SeekableRw<R: Read + Seek, W: Write + Seek> {
    writer: BufWriter<W>,
    reader: BufReader<R>,
}

impl SeekableRw<File, File> {
    pub fn from_path(f1: &Path) -> Result<Self> {
        let file = File::options().read(true).write(true).create(true).truncate(false).open(f1)?;
        Self::from_file(file)
    }
    pub fn from_file(f1: File) -> Result<Self> {
        let f2 = f1.try_clone()?;
        Ok(Self::new(f1, f2))
    }
}

impl<R: Read + Seek, W: Write + Seek> SeekableRw<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            writer: BufWriter::new(writer),
            reader: BufReader::new(reader),
        }
    }
    pub fn into_inner(self) -> Result<(R, W)> {
        let inner = self.writer.into_inner()
            .map_err(|_| CryptoError::IO(std::io::Error::other("flush")))?;
        Ok((self.reader.into_inner(), inner))
    }
}
impl<R: Read + Seek, W: Write + Seek> Read for SeekableRw<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}
impl<R: Read + Seek, W: Write + Seek> Write for SeekableRw<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl<R: Read + Seek, W: Write + Seek> Seek for SeekableRw<R, W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.writer.seek(pos)?;
        self.reader.seek(pos)
    }
}

pub struct SeekableRo<R: Read + Seek> {
    reader: BufReader<R>,
}


impl SeekableRo<File> {
    pub fn from_path(f1: &Path) -> Result<Self> {
        let file = File::options().read(true).open(f1)?;
        Ok(Self::from_file(file))
    }
    pub fn from_file(f1: File) -> Self {
        Self::new(f1)
    }
}
impl<R: Read + Seek> SeekableRo<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }

    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }
}
impl<R: Read + Seek> Read for SeekableRo<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read + Seek> Seek for SeekableRo<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)
    }
}

pub enum Seekable<R: Read + Seek, W: Write + Seek> {
    Rw(SeekableRw<R, W>),
    Ro(SeekableRo<R>),
}
impl<R: Read + Seek, W: Write + Seek> Read for Seekable<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Seekable::Rw(v) => { v.read(buf) },
            Seekable::Ro(v) => { v.read(buf) },
        }
    }
}
impl<R: Read + Seek, W: Write + Seek> Write for Seekable<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Seekable::Rw(v) = self {
            v.write(buf)
        } else {
            Err(std::io::Error::from_raw_os_error(EBADF))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Seekable::Rw(v) = self {
            v.flush()
        } else {
            Err(std::io::Error::from_raw_os_error(EBADF))
        }
    }
}
impl<R: Read + Seek, W: Write + Seek> Seek for Seekable<R, W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Seekable::Rw(v) => { v.seek(pos) },
            Seekable::Ro(v) => { v.seek(pos) },
        }
    }
}