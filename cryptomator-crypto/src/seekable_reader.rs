use crate::errors::Result;
use crate::FileHeader;
use log::debug;
use std::io::{Read, Seek, SeekFrom};

pub struct SeekableReader<'b, T: Read + Seek> {
    pub(crate) reader: &'b mut T,
    pub(crate) header: FileHeader,
    pub(crate) content_key: crate::utils::CryptoAes256Key,
}

impl<'b, T: Read + Seek> SeekableReader<'b, T> {
    pub fn read(&mut self, pos: usize, length: usize) -> Result<Vec<u8>> {
        debug!("Reading {} bytes from offset {}", length, pos);
        if length == 0 { return Ok(vec![]); }
        let block_start = pos / crate::utils::CLEAR_FILE_CHUNK_SIZE;
        let block_count = length.div_ceil(crate::utils::CLEAR_FILE_CHUNK_SIZE);
        let block_start_off = crate::utils::FILE_HEADER_SIZE + block_start * crate::utils::FILE_CHUNK_SIZE;
        let pos_within_chunk = pos % crate::utils::CLEAR_FILE_CHUNK_SIZE;
        self.reader.seek(SeekFrom::Start(block_start_off as u64))?;
        let mut x = Vec::with_capacity(block_count * crate::utils::CLEAR_FILE_CHUNK_SIZE - pos_within_chunk);
        for i in 0..block_count {
            let counter = block_start + i;
            let v = crate::cryptomator::read_and_decrypt_chunk(&mut self.reader, &self.content_key, counter as u64, &self.header.nonce)?;
            if v.is_none() {
                debug!("Read {} bytes from offset {}", length, pos);
                return Ok(x);
            }
            let mut v = v.unwrap();
            if i == 0 {
                v.drain(..pos_within_chunk.min(v.len()));
            }
            x.extend_from_slice(&v);
        }
        x.truncate(length);
        debug!("Read {} bytes from offset {}", length, pos);
        Ok(x)
    }
}
