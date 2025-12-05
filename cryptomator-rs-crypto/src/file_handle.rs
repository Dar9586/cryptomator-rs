use crate::errors::Result;
use crate::utils::*;
use crate::{EncryptedFileChunk, FileHeader};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{KeyInit, Nonce};
use itertools::repeat_n;
use log::debug;
use rand::rand_core::OsRng;
use rand::TryRngCore;
use std::io::{Read, Seek, SeekFrom, Write};

const HOLE_BLOCKS_PER_ITER: usize = 2;


pub struct FileHandle<T: Read + Seek> {
    pub(crate) handle: T,
    pub(crate) header: FileHeader,
    pub(crate) content_key: CryptoAes256Key,
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

impl<T: Read + Seek> Seek for FileHandle<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(v) => { self.offset = v }
            SeekFrom::End(v) => {
                let size = self.file_size().map_err(std::io::Error::other)?;
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

fn calc_offset(old_offset: u64, offset: i64) -> std::io::Result<u64> {
    let new_offset = (old_offset as i64) + offset;
    if new_offset.is_negative() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(new_offset as u64)
}

fn encrypt_chunk(data: &[u8], offset: u64, header_nonce: &CryptoNonce, content_key: &CryptoAes256Key) -> Result<EncryptedFileChunk> {
    let be_offset = offset.to_be_bytes();
    let mut tag = uninit::<[u8; TAG_SIZE]>();
    let mut chunk_nonce = uninit::<[u8; NONCE_SIZE]>();
    let mut aad = uninit::<[u8; U64_BYTES + NONCE_SIZE]>();
    fill_array(&mut aad, &be_offset, header_nonce);
    OsRng.try_fill_bytes(&mut chunk_nonce)?;

    let v = aes_gcm::Aes256Gcm::new_from_slice(content_key)?;
    let payload = Payload {
        msg: data,
        aad: &aad,
    };
    let mut dec = v.encrypt(<&Nonce<_>>::from(&chunk_nonce), payload)?;
    assert_eq!(dec.len(), data.len() + TAG_SIZE);
    tag.copy_from_slice(&dec[dec.len() - TAG_SIZE..]);
    dec.truncate(dec.len() - TAG_SIZE);
    Ok(EncryptedFileChunk {
        nonce: chunk_nonce,
        encrypted_payload: dec.into(),
        tag,
    })
}

fn decrypt_chunk(chunk: EncryptedFileChunk, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Vec<u8>> {
    let be_counter = counter.to_be_bytes();
    let mut aad = uninit::<[u8; U64_BYTES + NONCE_SIZE]>();
    fill_array(&mut aad, &be_counter, nonce);
    let v = aes_gcm::Aes256Gcm::new_from_slice(content_key)?;
    let mut msg_and_tag = Vec::new();
    msg_and_tag.extend_from_slice(&chunk.encrypted_payload);
    msg_and_tag.extend_from_slice(&chunk.tag);
    let payload = Payload {
        msg: &msg_and_tag,
        aad: &aad,
    };
    let dec = v.decrypt(Nonce::from_slice(&chunk.nonce), payload)?;
    Ok(dec)
}

fn read_chunk<T: Read>(reader: &mut T) -> Result<Option<EncryptedFileChunk>> {
    let mut chunk = uninit::<[u8; FILE_CHUNK_SIZE]>();
    let mut reached = 0;
    loop {
        let r = reader.read(&mut chunk[reached..])?;
        if r == 0 {
            if reached == 0 { return Ok(None); }
            return Ok(Some(EncryptedFileChunk::from(&chunk[..reached])));
        }
        reached += r;
        if reached == chunk.len() {
            return Ok(Some(EncryptedFileChunk::from(&chunk[..reached])));
        }
    }
}

fn read_and_decrypt_chunk<T: Read>(reader: &mut T, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Option<Vec<u8>>> {
    let chunk = read_chunk(reader)?;
    if chunk.is_none() { return Ok(None); }
    let chunk = chunk.unwrap();
    let dec = decrypt_chunk(chunk, content_key, counter, nonce)?;
    Ok(Some(dec))
}

impl<T: Read + Seek> FileHandle<T> {
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
            let v = read_and_decrypt_chunk(&mut self.handle, &self.content_key, counter as u64, &self.header.nonce)?;
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
    pub fn read_buf(&mut self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let x = self.read_buf_inner(pos, buf);
        self.seek(SeekFrom::Start(pos as u64 + match x {
            Ok(len) => { len as u64 }
            Err(_) => { 0 }
        }))?;
        x
    }
    pub fn read_data(&mut self, pos: usize, length: usize) -> Result<Vec<u8>> {
        debug!("Reading {} bytes from offset {}", length, pos);
        let mut x = vec![0; length];
        self.read_buf(pos, &mut x)?;
        Ok(x)
    }
    pub fn file_size(&mut self) -> Result<u64> {
        let total_size = self.handle.seek(SeekFrom::End(0))?;
        file_size_from_size(total_size)
    }
}


impl<T: Read + Write + Seek> FileHandle<T> {
    fn write_data_inner(&mut self, start_pos: usize, data: &[u8]) -> Result<()> {
        debug!("Writing {} bytes from offset {}", data.len(), start_pos);
        if data.is_empty() { return Ok(()); }
        let mut total_size = self.file_size()? as usize;
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
            let c = encrypt_chunk(chunk, (block_start + idx) as u64, &self.header.nonce, &self.content_key)?;
            self.handle.write_all(&c.nonce)?;
            self.handle.write_all(&c.encrypted_payload)?;
            self.handle.write_all(&c.tag)?;
        }
        self.handle.flush()?;
        debug!("Written {} bytes from offset {}", data.len(), start_pos);
        Ok(())
    }
    pub fn write_data(&mut self, start_pos: usize, data: &[u8]) -> Result<()> {
        let x = self.write_data_inner(start_pos, data);
        self.seek(SeekFrom::Start(start_pos as u64 + match x {
            Ok(_) => { data.len() as u64 }
            Err(_) => { 0 }
        }))?;
        x
    }
}

