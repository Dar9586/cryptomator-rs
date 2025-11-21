use crate::errors::Result;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

pub struct Seekable<T: Read + Write + Seek> {
    writer: Option<BufWriter<T>>,
    reader: BufReader<T>,
}

impl Seekable<File> {
    pub fn from_file(f1: File) -> Result<Self> {
        let f2 = f1.try_clone()?;
        Ok(Self::new(f1, Some(f2)))
    }
}
impl<T: Read + Write + Seek> Seekable<T> {
    pub fn new(reader: T, writer: Option<T>) -> Self {
        Self {
            writer: writer.map(|x| BufWriter::new(x)),
            reader: BufReader::new(reader),
        }
    }
}
impl<T: Read + Write + Seek> Read for Seekable<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<T: Read + Write + Seek> Write for Seekable<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(writer) = self.writer.as_mut() {
            writer.write(buf)
        } else {
            panic!("Write called on read only Seekable");
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(writer) = self.writer.as_mut() {
            writer.flush()
        } else {
            panic!("Write called on read only Seekable");
        }
    }
}

impl<T: Read + Write + Seek> Seek for Seekable<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        if let Some(writer) = self.writer.as_mut() {
            writer.seek(pos)?;
        }
        self.reader.seek(pos)
    }
}
