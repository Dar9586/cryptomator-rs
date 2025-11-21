use crate::errors::Result;
use crate::seekable_reader::SeekableReader;
use crate::utils::{CLEAR_FILE_CHUNK_SIZE, FILE_CHUNK_SIZE, FILE_HEADER_SIZE};
use crate::{encrypted_file_size_from_seekable, FileHeader};
use itertools::repeat_n;
use log::debug;
use std::io::{Read, Seek, SeekFrom, Write};

pub struct SeekableWriter<'b, T: Read + Write + Seek> {
    pub(crate) writer: &'b mut T,
    pub(crate) header: FileHeader,
    pub(crate) content_key: crate::utils::CryptoAes256Key,
}

const HOLE_BLOCKS_PER_ITER: usize = 2;

impl<'a, 'b, T: Read + Write + Seek> SeekableWriter<'b, T> {
    pub fn write(&mut self, start_pos: usize, data: &[u8]) -> Result<()> {
        debug!("Writing {} bytes from offset {}", data.len(), start_pos);
        if data.len() == 0 { return Ok(()); }
        let mut total_size = encrypted_file_size_from_seekable(&mut self.writer)? as usize;
        let end_pos = start_pos + data.len() - 1;
        while total_size < start_pos {
            let count = (HOLE_BLOCKS_PER_ITER * CLEAR_FILE_CHUNK_SIZE).min(start_pos - total_size);
            let data = vec![0; count];
            self.write(total_size, &data)?;
            total_size += data.len();
        }
        let block_start = start_pos / CLEAR_FILE_CHUNK_SIZE;
        let write_start_pos = block_start * CLEAR_FILE_CHUNK_SIZE;
        let block_start_off = FILE_HEADER_SIZE + block_start * FILE_CHUNK_SIZE;
        let pos_within_start_chunk = start_pos % CLEAR_FILE_CHUNK_SIZE;
        let pos_within_end_chunk = end_pos % CLEAR_FILE_CHUNK_SIZE;

        let mut reader = SeekableReader {
            reader: self.writer,
            header: self.header,
            content_key: self.content_key,
        };
        let mut before = if start_pos % CLEAR_FILE_CHUNK_SIZE == 0 && data.len() >= CLEAR_FILE_CHUNK_SIZE { vec![] } else {
            reader.read(write_start_pos, pos_within_start_chunk)?
        };
        before.extend(repeat_n(0u8, pos_within_start_chunk.saturating_sub(before.len())));
        let after = if
        end_pos > total_size ||
            ((data.len() + start_pos) % CLEAR_FILE_CHUNK_SIZE == 0 && data.len() >= CLEAR_FILE_CHUNK_SIZE) { vec![] } else {
            reader.read(end_pos + 1, CLEAR_FILE_CHUNK_SIZE - pos_within_end_chunk - 1)?
        };
        let mut write_buffer = Vec::with_capacity(before.len() + data.len() + after.len());
        write_buffer.extend(before);
        write_buffer.extend(data);
        write_buffer.extend(after);

        self.writer.seek(SeekFrom::Start(block_start_off as u64))?;
        for (idx, chunk) in write_buffer.chunks(CLEAR_FILE_CHUNK_SIZE).enumerate() {
            let c = crate::cryptomator::encrypt_chunk(chunk, (block_start + idx) as u64, &self.header.nonce, &self.content_key)?;
            self.writer.write(&c.nonce)?;
            self.writer.write(&c.encrypted_payload)?;
            self.writer.write(&c.tag)?;
        }
        self.writer.flush()?;
        debug!("Written {} bytes from offset {}", data.len(), start_pos);

        Ok(())
    }
}

