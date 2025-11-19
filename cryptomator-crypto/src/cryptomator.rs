use aes_gcm::aes::Aes256;
use aes_gcm::{aead::{Aead, KeyInit}, Nonce};
use aes_kw::Kek;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::Payload;
use anyhow::{anyhow, Result};
use base32::Alphabet;
use base64::Engine;
use cmac::digest::consts::U64;
use fallible_iterator::FallibleIterator;
use hmac::digest::core_api::CoreWrapper;
use hmac::{Hmac, Mac};
use jwt::{Header, Token, VerifyWithKey};
use scrypt::Params;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha1::digest::Output;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fmt::Debug;
use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
const CLEAR_FILE_CHUNK_SIZE: usize = 32768; //32 KiB
const FILE_CHUNK_HEADERS_SIZE: usize = NONCE_SIZE + TAG_SIZE;
const FILE_CHUNK_HEADERS_SIZE_U64: u64 = FILE_CHUNK_HEADERS_SIZE as u64;
const FILE_CHUNK_SIZE: usize = CLEAR_FILE_CHUNK_SIZE + FILE_CHUNK_HEADERS_SIZE;
const FILE_HEADER_SIZE: usize = NONCE_SIZE + ENCRYPTED_CONTENT_KEY + TAG_SIZE;
const SCRYPT_PARALLELISM: u32 = 1;
const SCRYPT_KEY_LENGTH: usize = 32;
const DIRID_NAME_LENGTH: usize = 32;
const KEK_KEY_LENGTH: usize = 32;
const MAC_KEY_LENGTH: usize = 32;
const ENC_KEY_LENGTH: usize = 32;
const NONCE_SIZE: usize = 12;
const U64_BYTES: usize = (u64::BITS / 8) as usize;
const UNUSED_SIZE: usize = 8;
const AES256KEY_BYTES: usize = 32;
const TAG_SIZE: usize = 16;
type CryptoNonce = [u8; NONCE_SIZE];
type CryptoTag = [u8; TAG_SIZE];
type CryptoAes256Key = [u8; AES256KEY_BYTES];
const ENCRYPTED_CONTENT_KEY: usize = UNUSED_SIZE + AES256KEY_BYTES;
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
    vault_root: PathBuf,
}

impl Debug for Cryptomator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cryptomator")
            .field("metadata", &self.metadata)
            .field("vault_root", &self.vault_root)
            .finish()
    }
}

pub fn encrypted_file_size(path: &Path) -> Result<u64> {
    let mut total_size = path.metadata()?.len();
    total_size = total_size.checked_sub_signed(FILE_HEADER_SIZE as i64).ok_or_else(|| anyhow!("Invalid file"))?;
    let blocks = total_size / FILE_CHUNK_SIZE as u64;
    let remainder = total_size - (blocks * FILE_CHUNK_SIZE as u64);
    match remainder {
        0 => { Ok(blocks * CLEAR_FILE_CHUNK_SIZE as u64) }
        1..FILE_CHUNK_HEADERS_SIZE_U64 => { Err(anyhow!("Invalid file")) }
        _ => { Ok(blocks * CLEAR_FILE_CHUNK_SIZE as u64 + remainder - FILE_CHUNK_HEADERS_SIZE_U64) }
    }
}

#[derive(Debug)]
pub struct FileHeader {
    nonce: CryptoNonce,
    enc_content_key: [u8; ENCRYPTED_CONTENT_KEY],
    tag: CryptoTag,
}

#[derive(Clone, Debug)]
pub struct DirId<'a> {
    pub unencrypted: String,
    prefix: String,
    suffix: String,
    crypto: &'a Cryptomator,
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
    fn to_name(&self) -> String {
        match self {
            EncryptedFilename::Encrypted(s) => {
                format!("{}.c9r", s)
            }
            EncryptedFilename::Compressed(s) => {
                format!("{}.c9s", s)
            }
        }
    }
}

#[derive(Debug, Default)]
struct EncryptedFileChunk {
    nonce: CryptoNonce,
    encrypted_payload: Vec<u8>,
    tag: CryptoTag,
}

pub struct SeekableReader<'a, 'b, T: Read + Seek> {
    reader: &'b mut T,
    header: FileHeader,
    crypto: &'a Cryptomator,
    content_key: CryptoAes256Key,
}

impl<'a, 'b, T: Read + Seek> SeekableReader<'a, 'b, T> {
    pub fn read(&mut self, pos: usize, length: usize) -> Result<Vec<u8>> {
        let block_start = pos / CLEAR_FILE_CHUNK_SIZE;
        let block_count = length.div_ceil(CLEAR_FILE_CHUNK_SIZE);
        let block_start_off = FILE_HEADER_SIZE + block_start * FILE_CHUNK_SIZE;
        let pos_within_chunk = pos % CLEAR_FILE_CHUNK_SIZE;
        self.reader.seek(SeekFrom::Start(block_start_off as u64))?;
        let mut x = Vec::with_capacity(block_count * CLEAR_FILE_CHUNK_SIZE - pos_within_chunk);
        for i in 0..block_count {
            let counter = block_start + i;
            let v = read_and_decrypt_chunk(&mut self.reader, &self.content_key, counter as u64, &self.header.nonce)?;
            if v.is_none() { return Ok(x) }
            let mut v = v.unwrap();
            if i == 0 {
                v.drain(..pos_within_chunk);
            }
            x.extend_from_slice(&v);
        }
        x.truncate(length);
        Ok(x)
    }
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

fn concat_vec<T:Clone>(v1:&[T], v2:&[T]) -> Vec<T>{
    let mut res=Vec::with_capacity(v1.len()+v2.len());
    res.extend_from_slice(v1);
    res.extend_from_slice(v2);
    res
}

fn fill_array<T: Copy>(v: &mut [T], v1: &[T], v2: &[T]) {
    v[..v1.len()].copy_from_slice(v1);
    v[v1.len()..].copy_from_slice(v2);
}

fn split_array<T: Copy>(v: &[T], v1: &mut [T], v2: &mut [T]) {
    v1.copy_from_slice(&v[..v1.len()]);
    v2.copy_from_slice(&v[v1.len()..]);
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
        let supreme_key=concat_vec(&encryption_master,&mac_master);
        let key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
        let token: Token<Header, VaultMetadata, _> = vault_content.verify_with_key(&key)?;
        let mut siv_key = [0u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH];
        fill_array(&mut siv_key, &mac_master, &encryption_master);
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
    fn aes_siv_enc(&self, data: &[u8], dir_id: Option<&DirId>) -> Result<Vec<u8>> {
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

    pub fn filename_encrypt(&self, name: &str, parent: &DirId) -> Result<EncryptedFilename> {
        let siv = self.aes_siv_enc(name.nfc().to_string().as_bytes(), Some(parent))?;
        let name = base64_enc(&siv);
        Ok(if name.len() + ".c9r".len() > self.metadata.shortening_threshold as usize {
            let xx = format!("{}.c9r", name);
            let n = sha1(xx.as_bytes());
            EncryptedFilename::Compressed(base64_enc(&n))
        } else {
            EncryptedFilename::Encrypted(name)
        })
    }

    pub fn filename_decrypt(&self, name: &str, parent: &DirId) -> Result<String> {
        let x = base64_dec(name)?;
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
        fill_array(&mut payload, &header.enc_content_key, &header.tag);
        let payload = Payload::from(payload.as_slice());
        let dec = v.decrypt(<&Nonce<_>>::from(&header.nonce), payload).map_err(|e| anyhow!(e))?;
        let mut unused = [0; UNUSED_SIZE];
        let mut content_key = [0; AES256KEY_BYTES];
        split_array(&dec, &mut unused, &mut content_key);
        Ok((unused, content_key))
    }

    pub fn read_file_content<'a, T: Read>(&self, reader: &'a mut T) -> Result<FileDecrypt<'a, T>> {
        let header = read_file_header(reader)?;
        let (_, content_key) = self.decrypt_header(&header)?;
        Ok(FileDecrypt::new(header, reader, content_key))
    }

    fn read_entire_content<T: Read>(&self, reader: &mut T) -> Result<Vec<u8>> {
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
}


impl<'a, T: Read> FileDecrypt<'a, T> {
    fn new(header: FileHeader, reader: &'a mut T, key: CryptoAes256Key) -> Self {
        Self { header, reader, key, counter: 0, failed: false }
    }
}

fn read_and_decrypt_chunk<T: Read>(reader: &mut T, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Option<Vec<u8>>> {
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

fn sha1(data: &[u8]) -> Output<Sha1> {
    let mut hasher = Sha1::new();
    hasher.update(&data);
    hasher.finalize()
}

fn base32_enc(data: &[u8]) -> String {
    base32::encode(Alphabet::Rfc4648 { padding: true }, &data)
}

fn base32_dec(data: &str) -> Result<Vec<u8>> {
    Ok(base32::decode(Alphabet::Rfc4648 { padding: true }, data)
        .ok_or_else(|| anyhow!("Base32 decode error"))?)
}

fn base64_enc(data: &[u8]) -> String {
    base64::prelude::BASE64_URL_SAFE.encode(data)
}

fn base64_dec(data: &str) -> Result<Vec<u8>> {
    Ok(base64::prelude::BASE64_URL_SAFE.decode(data)?)
}
#[derive(Debug, Clone, Hash)]
pub enum CryptoEntryType {
    Symlink { target: String },
    Directory { dir_id: String },
    File { abs_path: PathBuf },
}
#[derive(Debug, Clone, Hash)]
pub struct CryptoEntry {
    pub name: String,
    pub entry_type: CryptoEntryType,
}
const EXTENSION_LENGTH: usize = ".c9s".len();

impl<'a> DirId<'a>{
    fn try_read_dir(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let sub_dir_path = abs_path.join("dir.c9r");
        if !sub_dir_path.exists() { return Ok(None); }
        let dir_id = fs::read_to_string(sub_dir_path)?;
        Ok(Some(CryptoEntry {
            name: dec_name.to_string(),
            entry_type: CryptoEntryType::Directory { dir_id },
        }))
    }

    fn try_read_sym(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let sub_sym_path = abs_path.join("symlink.c9r");
        if !sub_sym_path.exists() { return Ok(None); }
        let mut reader = BufReader::new(fs::File::open(&sub_sym_path)?);
        let target = self.crypto.read_entire_content(&mut reader)?;
        let target = String::from_utf8(target)?;
        Ok(Some(CryptoEntry {
            name: dec_name.to_string(),
            entry_type: CryptoEntryType::Symlink { target },
        }))
    }

    fn try_read_file(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let file_file = abs_path.join("contents.c9r");
        if !file_file.exists() { return Ok(None); }
        Ok(Some(CryptoEntry {
            name: dec_name.to_string(),
            entry_type: CryptoEntryType::File { abs_path: file_file },
        }))
    }

    pub fn lookup(&self, unencrypted_name: &str) -> Result<Option<CryptoEntry>> {
        let encrypted_name = self.crypto.filename_encrypt(unencrypted_name, self)?;
        self.lookup_enc(&encrypted_name.to_name())
    }

    fn lookup_enc(&self, name: &str) -> Result<Option<CryptoEntry>> {
        let abs_path = self.path().join(&name);
        if !abs_path.exists() { return Ok(None); }
        let meta = abs_path.metadata()?;
        let entry_type = meta.file_type();
        let name_no_ext = &name[..name.len() - EXTENSION_LENGTH];
        if entry_type.is_file() {
            Ok(Some(self.parse_file(abs_path, name_no_ext)?))
        } else if entry_type.is_dir() {
            Ok(Some(self.parse_dir(&name, &abs_path, name_no_ext)?))
        } else {
            Err(anyhow!("'{}': {:?} is not a file or directory",name, entry_type))
        }
    }

    pub fn list_files(&self) -> Result<Vec<CryptoEntry>> {
        let mut entries = Vec::new();
        let dir_path = self.path();
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| anyhow!("invalid name"))?;
            if name == "dirid.c9r" {
                continue;
            }
            if let Some(entry) = self.lookup_enc(name)? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn parse_dir(&self, name: &str, abs_path: &PathBuf, name_no_ext: &str) -> Result<CryptoEntry> {
        let compressed = name.ends_with(".c9s");
        if !compressed {
            let dec_name = self.crypto.filename_decrypt(name_no_ext, self)?;
            if let Some(x) = self.try_read_dir(&abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_sym(&abs_path, &dec_name)? {
                Ok(x)
            } else {
                Err(anyhow!("invalid file '{}'",dec_name))
            }
        } else {
            let name_file = abs_path.join("name.c9s");
            let uncompressed_name = fs::read_to_string(&name_file)?;
            let dec_name = self.crypto.filename_decrypt(&uncompressed_name[..uncompressed_name.len() - EXTENSION_LENGTH], self)?;
            if let Some(x) = self.try_read_dir(&abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_sym(&abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_file(&abs_path, &dec_name)? {
                Ok(x)
            } else {
                Err(anyhow!("invalid file '{}'",dec_name))
            }
        }
    }

    fn parse_file(&self, abs_path: PathBuf, name_no_ext: &str) -> Result<CryptoEntry> {
        let name = self.crypto.filename_decrypt(name_no_ext, self)?;
        Ok(CryptoEntry {
            name,
            entry_type: CryptoEntryType::File { abs_path },
        })
    }

    pub fn path(&self) -> PathBuf{
        self.crypto.vault_root.join("d").join(&self.prefix).join(&self.suffix)
    }

    pub fn from_str(str:&str,crypto:&'a Cryptomator)->Result<Self>{
        let siv = crypto.aes_siv_enc(str.as_bytes(), None)?;
        let sha = sha1(&siv);
        let mut encoded = base32_enc(&sha);
        assert_eq!(encoded.len(),DIRID_NAME_LENGTH);
        let suffix=encoded.split_off(2);
        Ok(Self{
            unencrypted:str.to_string(),
            prefix:encoded,
            suffix,
            crypto
        })
    }
}


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

fn decrypt_chunk(chunk: EncryptedFileChunk, content_key: &CryptoAes256Key, counter: u64, nonce: &CryptoNonce) -> Result<Vec<u8>> {
    let be_counter = counter.to_be_bytes();
    let mut aad = [0; U64_BYTES + NONCE_SIZE];
    fill_array(&mut aad, &be_counter, nonce);
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

