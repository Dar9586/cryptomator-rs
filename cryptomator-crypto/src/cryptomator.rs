use crate::dir_id::DirId;
use crate::seekable_reader::SeekableReader;
use crate::seekable_writer::SeekableWriter;
use crate::utils;
use crate::utils::{CryptoAes256Key, CryptoNonce, CryptoTag, AES256KEY_BYTES, CLEAR_FILE_CHUNK_SIZE, ENCRYPTED_CONTENT_KEY, ENC_KEY_LENGTH, FILE_CHUNK_HEADERS_SIZE_U64, FILE_CHUNK_SIZE, FILE_HEADER_SIZE, KEK_KEY_LENGTH, MAC_KEY_LENGTH, NONCE_SIZE, SCRYPT_KEY_LENGTH, SCRYPT_PARALLELISM, TAG_SIZE, U64_BYTES, UNUSED_CONTENT, UNUSED_SIZE};
use aes_gcm::aes::Aes256;
use aes_gcm::{aead::{Aead, KeyInit}, Nonce};
use aes_kw::Kek;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::Payload;
use anyhow::{anyhow, Result};
use cmac::digest::consts::U64;
use fallible_iterator::FallibleIterator;
use hmac::digest::core_api::CoreWrapper;
use hmac::{Hmac, Mac};
use jwt::{Header, Token, VerifyWithKey};
use rand::rngs::OsRng;
use rand::TryRngCore;
use scrypt::Params;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha2::Sha256;
use std::fmt::Debug;
use std::fs;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

pub struct CryptomatorOpen{
    pub vault_path: PathBuf,
    pub password: String,
}

#[derive(Clone)]
pub struct Cryptomator {
    encryption_master: [u8; SCRYPT_KEY_LENGTH],
    mac_master: [u8; SCRYPT_KEY_LENGTH],
    siv_key: GenericArray<u8, U64>,
    metadata: VaultMetadata,
    pub(crate) vault_root: PathBuf,
}

impl Debug for Cryptomator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cryptomator")
            .field("metadata", &self.metadata)
            .field("vault_root", &self.vault_root)
            .finish()
    }
}

fn file_size_from_size(mut total_size: u64) -> Result<u64> {
    total_size = total_size.checked_sub_signed(FILE_HEADER_SIZE as i64).ok_or_else(|| anyhow!("Invalid file"))?;
    let blocks = total_size / FILE_CHUNK_SIZE as u64;
    let remainder = total_size - (blocks * FILE_CHUNK_SIZE as u64);
    match remainder {
        0 => { Ok(blocks * CLEAR_FILE_CHUNK_SIZE as u64) }
        1..FILE_CHUNK_HEADERS_SIZE_U64 => { Err(anyhow!("Invalid file")) }
        _ => { Ok(blocks * CLEAR_FILE_CHUNK_SIZE as u64 + remainder - FILE_CHUNK_HEADERS_SIZE_U64) }
    }

}

pub fn encrypted_file_size_from_seekable<T: Seek>(reader: &mut T) -> Result<u64> {
    let total_size = reader.seek(SeekFrom::End(0))?;
    Ok(file_size_from_size(total_size)?)
}

pub fn encrypted_file_size(path: &Path) -> Result<u64> {
    let total_size = path.metadata()?.len();
    Ok(file_size_from_size(total_size)?)
}

#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
    pub nonce: CryptoNonce,
    enc_content_key: [u8; ENCRYPTED_CONTENT_KEY],
    tag: CryptoTag,
}



pub struct FileDecrypt<'a, T: Read> {
    header: FileHeader,
    reader: &'a mut T,
    key: CryptoAes256Key,
    counter: u64,
    failed: bool,
}

#[derive(Clone, Debug)]
pub enum EncryptedFilename {
    Encrypted(String),
    Compressed(String),
}

impl EncryptedFilename {
    pub(crate) fn to_path_name(&self) -> String {
        match self {
            EncryptedFilename::Encrypted(s) => format!("{}.c9r", s),
            EncryptedFilename::Compressed(s) => format!("{}.c9s", s),
        }
    }
    fn is_compressed(&self) -> bool {
        matches!(self, EncryptedFilename::Compressed(_))
    }
    fn get_compressed(&self) -> &str {
        match self {
            EncryptedFilename::Encrypted(_) => panic!(),
            EncryptedFilename::Compressed(e) => e,
        }
    }
    fn get_encrypted(&self) -> &str {
        match self {
            EncryptedFilename::Encrypted(e) => e,
            EncryptedFilename::Compressed(_) => panic!(),
        }
    }
}

#[derive(Debug, Default)]
pub struct EncryptedFileChunk {
    pub(crate) nonce: CryptoNonce,
    pub(crate) encrypted_payload: Vec<u8>,
    pub(crate) tag: CryptoTag,
}



#[serde_as]
#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(rename_all = "camelCase")]
struct SerdeMasterKey{
    version:u32,
    #[serde_as(as = "Base64")]
    scrypt_salt:Vec<u8>,
    scrypt_cost_param:u64,
    scrypt_block_size:u32,
    #[serde_as(as = "Base64")]
    primary_master_key:Vec<u8>,
    #[serde_as(as = "Base64")]
    hmac_master_key:Vec<u8>,
    #[serde_as(as = "Base64")]
    version_mac:Vec<u8>,
}

#[derive(Serialize,Deserialize,Clone,Debug)]
#[serde(rename_all = "camelCase")]
struct VaultMetadata{
    jti:String,
    format:u64,
    cipher_combo:String,
    shortening_threshold:u64
}

pub fn decrypt_chunk(chunk: EncryptedFileChunk, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Vec<u8>> {
    let be_counter = counter.to_be_bytes();
    let mut aad = [0; U64_BYTES + NONCE_SIZE];
    utils::fill_array(&mut aad, &be_counter, nonce);
    let v = aes_gcm::Aes256Gcm::new_from_slice(content_key)?;
    let mut msg_and_tag = Vec::new();
    msg_and_tag.extend_from_slice(&chunk.encrypted_payload);
    msg_and_tag.extend_from_slice(&chunk.tag);
    let payload = Payload {
        msg: &msg_and_tag,
        aad: &aad,
    };
    let dec = v.decrypt(Nonce::from_slice(&chunk.nonce), payload).map_err(|e| anyhow!(e))?;
    Ok(dec)
}

pub fn encrypt_chunk(data: &[u8], offset: u64, header_nonce: &CryptoNonce, content_key: &CryptoAes256Key) -> Result<EncryptedFileChunk> {
    let be_offset = offset.to_be_bytes();
    let mut tag = [0u8; TAG_SIZE];
    let mut chunk_nonce = [0u8; NONCE_SIZE];
    let mut aad = [0u8; U64_BYTES + NONCE_SIZE];
    utils::fill_array(&mut aad, &be_offset, header_nonce);
    OsRng.try_fill_bytes(&mut chunk_nonce)?;

    let v = aes_gcm::Aes256Gcm::new_from_slice(content_key)?;
    let payload = Payload {
        msg: data,
        aad: &aad,
    };
    let mut dec = v.encrypt(<&Nonce<_>>::from(&chunk_nonce), payload).map_err(|e| anyhow!(e))?;
    assert_eq!(dec.len(), data.len() + TAG_SIZE);
    tag.copy_from_slice(&dec[dec.len() - TAG_SIZE..]);
    dec.truncate(dec.len() - TAG_SIZE);
    Ok(EncryptedFileChunk {
        nonce: chunk_nonce,
        encrypted_payload: dec,
        tag,
    })
}
impl CryptomatorOpen{
    pub fn open(&self)->Result<Cryptomator>{
        let masterkey_path=self.vault_path.join("masterkey.cryptomator");
        let x=fs::read_to_string(&masterkey_path)?;
        let masterkey:SerdeMasterKey=serde_json::from_str(&x)?;
        let vault_path=self.vault_path.join("vault.cryptomator");
        let vault_content=fs::read_to_string(vault_path.as_path())?;
        // todo: parse header for non H256 and kid
        // let (header,_)=vault_content.split_once(".").unwrap();
        // let header=Header::from_base64(header)?;
        let kek_param=Params::new(masterkey.scrypt_cost_param.ilog2() as u8,masterkey.scrypt_block_size,SCRYPT_PARALLELISM,SCRYPT_KEY_LENGTH)?;
        let mut kek_key = [0u8; KEK_KEY_LENGTH];
        let mut encryption_master = [0u8; ENC_KEY_LENGTH];
        let mut mac_master = [0u8; MAC_KEY_LENGTH];
        scrypt::scrypt(self.password.as_bytes(), &masterkey.scrypt_salt, &kek_param, &mut kek_key)?;
        let kek=Kek::from(kek_key);
        kek.unwrap(&masterkey.primary_master_key,&mut encryption_master).unwrap();
        kek.unwrap(&masterkey.hmac_master_key,&mut mac_master).unwrap();
        let supreme_key = utils::concat_vec(&encryption_master, &mac_master);
        let key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
        let token: Token<Header, VaultMetadata, _> = vault_content.verify_with_key(&key)?;
        let mut siv_key = [0u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH];
        utils::fill_array(&mut siv_key, &mac_master, &encryption_master);
        Ok(Cryptomator{
            siv_key:GenericArray::from(siv_key),
            encryption_master,
            mac_master,
            metadata:token.claims().clone(),
            vault_root:self.vault_path.clone()
        })
    }
}

impl Cryptomator {
    pub(crate) fn aes_siv_enc(&self, data: &[u8], dir_id: Option<&DirId>) -> Result<Vec<u8>> {
        let mut siv: aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>> = aes_siv::siv::Siv::new(&self.siv_key); //::new(&GenericArray::from(supreme_key));
        Ok(match dir_id {
            Some(dir_id) => { siv.encrypt::<_, _>(&[dir_id.unencrypted.as_bytes()], data) }
            None => { siv.encrypt::<&[&[u8]], _>(&[], data) }
        }.map_err(|e| anyhow!(e))?)
    }

    fn aes_siv_dec(&self, data: &[u8], dir_id: Option<&DirId>) -> Result<Vec<u8>> {
        let mut siv: aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>> = aes_siv::siv::Siv::new(&self.siv_key); //::new(&GenericArray::from(supreme_key));
        Ok(match dir_id {
            Some(dir_id) => { siv.decrypt::<_, _>(&[dir_id.unencrypted.as_bytes()], data) }
            None => { siv.decrypt::<&[&[u8]], _>(&[], data) }
        }.map_err(|e| anyhow!(e))?)
    }

    pub fn filename_encrypt(&self, name: &str, parent: &DirId, force_enc: bool) -> Result<EncryptedFilename> {
        let siv = self.aes_siv_enc(name.nfc().to_string().as_bytes(), Some(parent))?;
        let name = utils::base64_enc(&siv);
        Ok(if !force_enc && name.len() + EXTENSION_LENGTH > self.metadata.shortening_threshold as usize {
            let xx = format!("{}.c9r", name);
            let n = utils::sha1(xx.as_bytes());
            EncryptedFilename::Compressed(utils::base64_enc(&n))
        } else {
            EncryptedFilename::Encrypted(name)
        })
    }

    pub fn filename_decrypt(&self, name: &str, parent: &DirId) -> Result<String> {
        let x = utils::base64_dec(name)?;
        let siv = self.aes_siv_dec(&x, Some(parent))?;
        let sss = String::from_utf8(siv)?;
        Ok(sss)
    }

    pub fn get_root(&self) -> Result<DirId<'_>> {
        Ok(DirId::from_str("", self)?)
    }

    fn decrypt_header(&self, header: &FileHeader) -> Result<([u8; UNUSED_SIZE], CryptoAes256Key)> {
        let v = aes_gcm::Aes256Gcm::new_from_slice(&self.encryption_master)?;
        let mut payload = [0u8; ENCRYPTED_CONTENT_KEY + TAG_SIZE];
        utils::fill_array(&mut payload, &header.enc_content_key, &header.tag);
        let payload = Payload::from(payload.as_slice());
        let dec = v.decrypt(<&Nonce<_>>::from(&header.nonce), payload).map_err(|e| anyhow!(e))?;
        let mut unused = [0; UNUSED_SIZE];
        let mut content_key = [0; AES256KEY_BYTES];
        utils::split_array(&dec, &mut unused, &mut content_key);
        Ok((unused, content_key))
    }

    pub fn read_file_content<'a, T: Read>(&self, reader: &'a mut T) -> Result<FileDecrypt<'a, T>> {
        let header = read_file_header(reader)?;
        let (_, content_key) = self.decrypt_header(&header)?;
        Ok(FileDecrypt::new(header, reader, content_key))
    }

    pub(crate) fn read_entire_content<T: Read>(&self, reader: &mut T) -> Result<Vec<u8>> {
        let x = self.read_file_content(reader)?;
        let mut v = Vec::new();
        for x in x.iterator() {
            v.extend_from_slice(&x?);
        }
        Ok(v)
    }

    pub fn read_seek<'a, 'b, T: Read + Seek>(&'a self, reader: &'b mut T) -> Result<SeekableReader<'a, 'b, T>> {
        reader.seek(SeekFrom::Start(0))?;
        let header = read_file_header(reader)?;
        let (_, content_key) = self.decrypt_header(&header)?;
        Ok(SeekableReader {
            reader,
            header,
            content_key,
            crypto: self,
        })
    }

    pub fn create_file_header(&self) -> Result<(FileHeader, CryptoAes256Key)> {
        let mut tag = [0u8; TAG_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        let mut content_key = [0u8; AES256KEY_BYTES];
        let mut cleartext_payload = [0u8; AES256KEY_BYTES + UNUSED_SIZE];
        OsRng.try_fill_bytes(&mut nonce)?;
        OsRng.try_fill_bytes(&mut content_key)?;
        utils::fill_array(&mut cleartext_payload, &UNUSED_CONTENT, &content_key);

        let v = aes_gcm::Aes256Gcm::new_from_slice(&self.encryption_master)?;
        let dec = v.encrypt(<&Nonce<_>>::from(&nonce), cleartext_payload.as_slice()).map_err(|e| anyhow!(e))?;
        utils::split_array(&dec, &mut cleartext_payload, &mut tag);
        Ok((FileHeader {
            nonce,
            enc_content_key: cleartext_payload,
            tag,
        }, content_key))
    }

    pub fn file_writer<'a, 'b, T: Read + Write + Seek>(&'a self, writer: &'b mut T) -> Result<SeekableWriter<'a, 'b, T>> {
        writer.seek(SeekFrom::Start(0))?;
        let header = read_file_header(writer)?;
        let (_, content_key) = self.decrypt_header(&header)?;
        Ok(SeekableWriter {
            writer,
            header,
            content_key,
            crypto: self,
        })
    }

    fn write_header<T: Write>(&self, writer: &mut T) -> Result<(FileHeader, CryptoAes256Key)> {
        let (header, content_key) = self.create_file_header()?;
        writer.write(header.nonce.as_slice())?;
        writer.write(header.enc_content_key.as_slice())?;
        writer.write(header.tag.as_slice())?;
        writer.flush()?;
        Ok((header, content_key))
    }

    fn write_uncompressed_name(&self, dir_id: &DirId, name: &str, compressed_name: &str) -> Result<()> {
        let encrypted = self.filename_encrypt(name, dir_id, true)?;
        let dir_path = dir_id.path().join(compressed_name);
        let file_name_path = dir_path.join("name.c9s");
        fs::create_dir_all(&dir_path)?;
        fs::write(&file_name_path, &encrypted.to_path_name())?;

        Ok(())
    }
    pub fn create_file(&self, dir_id: &DirId, name: &str) -> Result<CryptoEntry> {
        let v = self.filename_encrypt(name, dir_id, false)?;
        let enc_name = v.to_path_name();
        let mut path = dir_id.path().join(&enc_name);
        if v.is_compressed() {
            self.write_uncompressed_name(dir_id, name, &enc_name)?;
            path = path.join("contents.c9r");
        }
        let mut f = BufWriter::new(fs::File::create(&path)?);
        self.write_header(&mut f)?;
        Ok(CryptoEntry { name: name.to_string(), entry_type: CryptoEntryType::File { abs_path: path } })
    }
}


impl<'a, T: Read> FileDecrypt<'a, T> {
    fn new(header: FileHeader, reader: &'a mut T, key: CryptoAes256Key) -> Self {
        Self { header, reader, key, counter: 0, failed: false }
    }
}

pub(crate) fn read_and_decrypt_chunk<T: Read>(reader: &mut T, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Option<Vec<u8>>> {
    let chunk = read_chunk(reader)?;
    if chunk.is_none() { return Ok(None); }
    let chunk = chunk.unwrap();
    let dec = decrypt_chunk(chunk, content_key, counter, nonce)?;
    Ok(Some(dec))
}

impl<T: Read> Iterator for FileDecrypt<'_, T> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed { return None; }
        let chunk = read_and_decrypt_chunk(self.reader, &self.key, self.counter, &self.header.nonce);
        if chunk.is_err() {
            self.failed = true;
            return Some(Err(anyhow!(chunk.err().unwrap())));
        }
        let chunk = chunk.unwrap();
        if chunk.is_none() { return None; }
        self.counter += 1;
        Some(Ok(chunk.unwrap()))
    }
}

impl<T: Read> FallibleIterator for FileDecrypt<'_, T> {
    type Item = Vec<u8>;
    type Error = anyhow::Error;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.failed { return Ok(None); }
        let chunk = read_and_decrypt_chunk(self.reader, &self.key, self.counter, &self.header.nonce)?;
        if chunk.is_none() { return Ok(None); }
        self.counter += 1;
        Ok(Some(chunk.unwrap()))
    }
}

#[derive(Debug, Clone, Hash)]
pub enum CryptoEntryType {
    Symlink { target: String },
    Directory { dir_id: String },
    File { abs_path: PathBuf },
}

impl CryptoEntryType {
    pub fn directory(&self) -> &String {
        match self {
            CryptoEntryType::Directory { dir_id } => { dir_id }
            _ => { panic!() }
        }
    }

    pub fn file(&self) -> &PathBuf {
        match self {
            CryptoEntryType::File { abs_path } => { abs_path }
            _ => { panic!() }
        }
    }

    pub fn symlink(&self) -> &String {
        match self {
            CryptoEntryType::Symlink { target } => { target }
            _ => { panic!() }
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct CryptoEntry {
    pub name: String,
    pub entry_type: CryptoEntryType,
}
pub(crate) const EXTENSION_LENGTH: usize = ".c9s".len();


impl From<&[u8]> for EncryptedFileChunk {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() >= NONCE_SIZE + TAG_SIZE);
        let mut nonce = [0u8; NONCE_SIZE];
        let mut tag = [0u8; TAG_SIZE];
        nonce.copy_from_slice(&value[..NONCE_SIZE]);
        tag.copy_from_slice(&value[value.len() - TAG_SIZE..]);
        let encrypted_payload = value[NONCE_SIZE..value.len() - TAG_SIZE].to_vec();
        assert_eq!(encrypted_payload.len(), value.len() - NONCE_SIZE - TAG_SIZE);
        Self{nonce,encrypted_payload,tag}
    }
}


// todo: leggi chunk specifici
fn read_chunk<T: Read>(reader: &mut T) -> Result<Option<EncryptedFileChunk>> {
    let mut chunk=[0u8;FILE_CHUNK_SIZE];
    let mut reached=0;
    loop{
        let r=reader.read(&mut chunk[reached..])?;
        if r==0{
            if reached == 0 { return Ok(None); }
            return Ok(Some(EncryptedFileChunk::from(&chunk[..reached])));
        }
        reached+=r;
        if reached==chunk.len(){
            return Ok(Some(EncryptedFileChunk::from(&chunk[..reached])))
        }
    }
}



pub fn read_file_header<T: Read>(reader: &mut T) -> Result<FileHeader> {
    let mut header = FileHeader {
        nonce: [0; NONCE_SIZE],
        enc_content_key: [0; ENCRYPTED_CONTENT_KEY],
        tag: [0; TAG_SIZE],
    };
    reader.read_exact(&mut header.nonce)?;
    reader.read_exact(&mut header.enc_content_key)?;
    reader.read_exact(&mut header.tag)?;
    Ok(header)
}


