use crate::errors::Result;
use crate::utils::{CLEAR_FILE_CHUNK_SIZE, FILE_CHUNK_SIZE, FILE_HEADER_SIZE};
use crate::{encrypted_file_size_from_seekable, FileHeader};
use itertools::repeat_n;
use log::debug;
use std::io::{Read, Seek, SeekFrom, Write};

const HOLE_BLOCKS_PER_ITER: usize = 2;


pub struct FileHandle<T: Read + Seek> {
    pub(crate) handle: T,
    pub(crate) header: FileHeader,
    pub(crate) content_key: crate::utils::CryptoAes256Key,
    pub(crate) offset: u64,
}

impl<T: Read + Write + Seek> Write for FileHandle<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_data(self.offset as usize, buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<T: Read + Seek> Read for FileHandle<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_len = self.read_buf(self.offset as usize, buf).map_err(std::io::Error::other)?;
        Ok(read_len)
    }
}

pub(crate) fn calc_offset(old_offset: u64, offset: i64) -> std::io::Result<u64> {
    let new_offset = (old_offset as i64) + offset;
    if new_offset.is_negative() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(new_offset as u64)
}

impl<T: Read + Seek> Seek for FileHandle<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(v) => { self.offset = v }
            SeekFrom::End(v) => {
                let size = encrypted_file_size_from_seekable(&mut self.handle).map_err(std::io::Error::other)?;
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

impl<T: Read + Seek> FileHandle<T> {
    pub fn read_buf(&mut self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let x = self.read_buf_inner(pos, buf);
        self.seek(SeekFrom::Start(pos as u64 + match x {
            Ok(len) => { len as u64 }
            Err(_) => { 0 }
        }))?;
        x
    }

    fn read_buf_inner(&mut self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let buf_len = buf.len();
        debug!("Reading {} bytes from offset {}", buf_len, pos);
        if buf.is_empty() { return Ok(0); }
        let block_start = pos / CLEAR_FILE_CHUNK_SIZE;
        let block_end = (pos + buf_len) / CLEAR_FILE_CHUNK_SIZE;
        let block_count = (block_end - block_start) + 1;
        let block_start_off = FILE_HEADER_SIZE + block_start * FILE_CHUNK_SIZE;
        let pos_within_chunk_start = pos % CLEAR_FILE_CHUNK_SIZE;
        self.handle.seek(SeekFrom::Start(block_start_off as u64))?;
        let mut buf_pos = 0;
        for i in 0..block_count {
            let counter = block_start + i;
            let v = crate::cryptomator::read_and_decrypt_chunk(&mut self.handle, &self.content_key, counter as u64, &self.header.nonce)?;
            if let Some(mut v) = v {
                if i == 0 {
                    v.drain(..pos_within_chunk_start.min(v.len()));
                }
                if buf_pos + v.len() > buf_len {
                    v.truncate(buf_len - buf_pos);
                }
                buf[buf_pos..buf_pos + v.len()].copy_from_slice(&v);
                buf_pos += v.len();
            } else {
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


impl<T: Read + Write + Seek> FileHandle<T> {
    pub fn write_data(&mut self, start_pos: usize, data: &[u8]) -> Result<()> {
        let x = self.write_data_inner(start_pos, data);
        self.seek(SeekFrom::Start(start_pos as u64 + match x {
            Ok(_) => { data.len() as u64 }
            Err(_) => { 0 }
        }))?;
        x
    }

    fn write_data_inner(&mut self, start_pos: usize, data: &[u8]) -> Result<()> {
        debug!("Writing {} bytes from offset {}", data.len(), start_pos);
        if data.is_empty() { return Ok(()); }
        let mut total_size = encrypted_file_size_from_seekable(&mut self.handle)? as usize;
        let end_pos = start_pos + data.len() - 1;
        while total_size < start_pos {
            let count = (HOLE_BLOCKS_PER_ITER * CLEAR_FILE_CHUNK_SIZE).min(start_pos - total_size);
            let data = vec![0; count];
            self.write_data(total_size, &data)?;
            total_size += data.len();
        }
        let block_start = start_pos / CLEAR_FILE_CHUNK_SIZE;
        let write_start_pos = block_start * CLEAR_FILE_CHUNK_SIZE;
        let block_start_off = FILE_HEADER_SIZE + block_start * FILE_CHUNK_SIZE;
        let pos_within_start_chunk = start_pos % CLEAR_FILE_CHUNK_SIZE;
        let pos_within_end_chunk = end_pos % CLEAR_FILE_CHUNK_SIZE;


        let mut before = if start_pos.is_multiple_of(CLEAR_FILE_CHUNK_SIZE) && data.len() >= CLEAR_FILE_CHUNK_SIZE { vec![] } else {
            self.read_data(write_start_pos, pos_within_start_chunk)?
        };
        before.extend(repeat_n(0u8, pos_within_start_chunk.saturating_sub(before.len())));
        let after = if
        end_pos > total_size ||
            ((data.len() + start_pos).is_multiple_of(CLEAR_FILE_CHUNK_SIZE) && data.len() >= CLEAR_FILE_CHUNK_SIZE) { vec![] } else {
            self.read_data(end_pos + 1, CLEAR_FILE_CHUNK_SIZE - pos_within_end_chunk - 1)?
        };
        let mut write_buffer = Vec::with_capacity(before.len() + data.len() + after.len());
        write_buffer.extend(before);
        write_buffer.extend(data);
        write_buffer.extend(after);

        self.handle.seek(SeekFrom::Start(block_start_off as u64))?;
        for (idx, chunk) in write_buffer.chunks(CLEAR_FILE_CHUNK_SIZE).enumerate() {
            let c = crate::cryptomator::encrypt_chunk(chunk, (block_start + idx) as u64, &self.header.nonce, &self.content_key)?;
            self.handle.write_all(&c.nonce)?;
            self.handle.write_all(&c.encrypted_payload)?;
            self.handle.write_all(&c.tag)?;
        }
        self.handle.flush()?;
        debug!("Written {} bytes from offset {}", data.len(), start_pos);
        Ok(())
    }
}

