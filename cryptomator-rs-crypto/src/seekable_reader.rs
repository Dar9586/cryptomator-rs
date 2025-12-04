use crate::errors::Result;
use crate::{encrypted_file_size_from_seekable, FileHeader};
use log::debug;
use std::io::{Read, Seek, SeekFrom};

pub struct SeekableReader<'b, T: Read + Seek> {
    pub(crate) reader: &'b mut T,
    pub(crate) header: FileHeader,
    pub(crate) content_key: crate::utils::CryptoAes256Key,
    pub(crate) offset: u64,
}

impl<'b, T: Read + Seek> Read for SeekableReader<'b, T>{

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_len = self.read_buf(self.offset as usize, buf).map_err(std::io::Error::other)?;
        Ok(read_len)
    }
}

pub(crate) fn calc_offset(old_offset: u64, offset: i64) -> std::io::Result<u64> {
    let new_offset = (old_offset as i64) + offset;
    if new_offset.is_negative() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
    Ok(new_offset as u64)
}

impl<'b, T: Read + Seek> Seek for SeekableReader<'b, T>{

    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(v) => { self.offset = v }
            SeekFrom::End(v) => {
                let size = encrypted_file_size_from_seekable(self.reader).map_err(std::io::Error::other)?;
                self.offset = calc_offset(size, v)?
            }
            SeekFrom::Current(v) => { self.offset = calc_offset(self.offset, v)?; }
        }
        Ok(self.offset)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.offset = 0;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.offset)
    }

    fn seek_relative(&mut self, offset: i64) -> std::io::Result<()> {
        self.offset = calc_offset(self.offset, offset)?;
        Ok(())
    }
}

impl<'b, T: Read + Seek> SeekableReader<'b, T> {
    pub fn read_buf(&mut self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let x = self.read_buf_inner(pos, buf);
        self.seek(SeekFrom::Start(pos as u64 + match x {
            Ok(len) => { len as u64 },
            Err(_) => { 0 }
        }))?;
        x
    }

    fn read_buf_inner(&mut self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let buf_len = buf.len();
        debug!("Reading {} bytes from offset {}", buf_len, pos);
        if buf.is_empty() { return Ok(0); }
        let block_start = pos / crate::utils::CLEAR_FILE_CHUNK_SIZE;
        let block_end = (pos + buf_len) / crate::utils::CLEAR_FILE_CHUNK_SIZE;
        let block_count = (block_end - block_start)+1;
        let block_start_off = crate::utils::FILE_HEADER_SIZE + block_start * crate::utils::FILE_CHUNK_SIZE;
        let pos_within_chunk_start = pos % crate::utils::CLEAR_FILE_CHUNK_SIZE;
        self.reader.seek(SeekFrom::Start(block_start_off as u64))?;
        let mut buf_pos = 0;
        for i in 0..block_count {
            let counter = block_start + i;
            let v=crate::cryptomator::read_and_decrypt_chunk(&mut self.reader, &self.content_key, counter as u64, &self.header.nonce)?;
            if let Some(mut v)=v {
                if i == 0 {
                    v.drain(..pos_within_chunk_start.min(v.len()));
                }
                if buf_pos + v.len() > buf_len {
                    v.truncate(buf_len - buf_pos);
                }
                buf[buf_pos..buf_pos + v.len()].copy_from_slice(&v);
                buf_pos += v.len();
            }else{
                break;
            }
        }
        debug!("Read {} bytes from offset {}", buf_pos, pos);
        Ok(buf_pos)
    }
    pub fn read_data(&mut self, pos: usize, length: usize) -> Result<Vec<u8>> {
        debug!("Reading {} bytes from offset {}", length, pos);
        let mut x = vec![0; length];
        self.read_buf(pos, &mut x)?;
        Ok(x)
    }
}
