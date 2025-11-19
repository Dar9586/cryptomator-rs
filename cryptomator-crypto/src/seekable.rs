use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

pub struct Seekable<T: Read + Write + Seek> {
    writer: BufWriter<T>,
    reader: BufReader<T>,
}

impl Seekable<File> {
    pub fn from_file(f1: File) -> anyhow::Result<Self> {
        let f2 = f1.try_clone()?;
        Ok(Self::new(f1, f2))
    }
}
impl<T: Read + Write + Seek> Seekable<T> {
    pub fn new(reader: T, writer: T) -> Self {
        Self {
            writer: BufWriter::new(reader),
            reader: BufReader::new(writer),
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
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl<T: Read + Write + Seek> Seek for Seekable<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)?;
        self.writer.seek(pos)
    }
}
