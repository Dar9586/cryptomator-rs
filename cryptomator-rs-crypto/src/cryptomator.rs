use crate::dir_id::DirId;
use crate::errors::CryptoError;
use crate::errors::CryptoError::UnixError;
use crate::errors::Result;
use crate::utils::*;
use crate::{FileHandle, SeekableRw};
use aes_gcm::aes::Aes256;
use aes_gcm::{aead::{Aead, KeyInit}, Nonce};
use aes_kw::Kek;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::Payload;
use cmac::digest::consts::U64;
use hmac::digest::core_api::CoreWrapper;
use hmac::{Hmac, Mac};
use jwt::header::HeaderType;
use jwt::{AlgorithmType, Header, JoseHeader, SignWithKey, Token, VerifyWithKey, VerifyingAlgorithm};
use rand::rngs::OsRng;
use rand::TryRngCore;
use scrypt::Params;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha2::{Sha256, Sha384, Sha512};
use std::fmt::{Debug, Formatter};
use std::fs;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use url::Url;
use uuid::Uuid;

const SCRYPT_SALT_SIZE: usize = 8;
const SCRYPT_BLOCK_SIZE: u32 = 8;
const SCRYPT_COST_LOG: u8 = 15;
const MASTERKEY_VERSION: u32 = 999;


#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
    pub nonce: CryptoNonce,
    enc_content_key: [u8; ENCRYPTED_CONTENT_KEY],
    tag: CryptoTag,
}

#[derive(Clone, Debug)]
pub(crate) enum EncryptedFilename {
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
            EncryptedFilename::Encrypted(_) => unreachable!(),
            EncryptedFilename::Compressed(e) => e,
        }
    }
}

#[derive(Debug, Default)]
pub struct EncryptedFileChunk {
    pub(crate) nonce: CryptoNonce,
    pub(crate) encrypted_payload: RoBytes,
    pub(crate) tag: CryptoTag,
}

impl From<&[u8]> for EncryptedFileChunk {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() >= NONCE_SIZE + TAG_SIZE);
        let mut nonce = uninit::<[u8; NONCE_SIZE]>();
        let mut tag = uninit::<[u8; TAG_SIZE]>();
        nonce.copy_from_slice(&value[..NONCE_SIZE]);
        tag.copy_from_slice(&value[value.len() - TAG_SIZE..]);
        let encrypted_payload = value[NONCE_SIZE..value.len() - TAG_SIZE].to_vec();
        assert_eq!(encrypted_payload.len(), value.len() - NONCE_SIZE - TAG_SIZE);
        Self { nonce, encrypted_payload: encrypted_payload.into(), tag }
    }
}


#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct SerdeMasterKey {
    version: u32,
    #[serde_as(as = "Base64")]
    scrypt_salt: Vec<u8>,
    scrypt_cost_param: u64,
    scrypt_block_size: u32,
    #[serde_as(as = "Base64")]
    primary_master_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    hmac_master_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    version_mac: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct VaultMetadata {
    jti: String,
    format: u64,
    cipher_combo: String,
    shortening_threshold: u64,
}

#[derive(Clone)]
pub struct Cryptomator {
    encryption_master: [u8; SCRYPT_KEY_LENGTH],
    siv_key: GenericArray<u8, U64>,
    metadata: VaultMetadata,
    pub(crate) vault_root: PathBuf,
}

impl Debug for Cryptomator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cryptomator")
            .field("metadata", &self.metadata)
            .field("vault_root", &self.vault_root)
            .finish()
    }
}

impl Cryptomator {
    fn write_dirid_file(&self, parent: &DirId, child: &DirId) -> Result<()> {
        let child_dir_id_file = child.path().join(STDFILE_DIRID);
        let mut f = SeekableRw::from_path(&child_dir_id_file)?;
        self.write_header(&mut f)?;
        let mut writer = self.file_handle(f)?;
        writer.write_all(&parent.unencrypted)?;
        Ok(())
    }

    fn create_directory_with_dir_id(&self, parent: &DirId, name: &str, dir_id: &[u8]) -> Result<CryptoEntry> {
        let enc_name = self.filename_encrypt(name, parent, false)?;
        let parent_path_entry = parent.path().join(enc_name.to_path_name());
        fs::create_dir_all(&parent_path_entry)?;
        if enc_name.is_compressed() {
            self.write_uncompressed_name(parent, name, enc_name.get_compressed())?;
        }
        let child = DirId::from_str(dir_id, self)?;
        let dir_path = child.path();
        fs::create_dir_all(&dir_path)?;

        // write dir.c9r pointing to child in the parent folder
        let parent_dir_id_file = parent_path_entry.join(STDFILE_DIR);
        fs::write(&parent_dir_id_file, dir_id)?;

        // write dirid.c9r pointing to parent in the child folder
        self.write_dirid_file(parent, &child)?;

        Ok(CryptoEntry {
            name: name.into(),
            entry_type: CryptoEntryType::Directory { dir_id: dir_id.into() },
        })
    }

    fn delete_fs(&self, parent: &DirId, name: &str) -> Result<()> {
        let name = self.filename_encrypt(name, parent, false)?;
        let file_path = parent.path().join(name.to_path_name());
        delete_file(&file_path)?;
        Ok(())
    }

    fn create_file_header(&self) -> Result<(FileHeader, CryptoAes256Key)> {
        let mut tag = uninit::<[u8; TAG_SIZE]>();
        let mut nonce = uninit::<[u8; NONCE_SIZE]>();
        let mut content_key = uninit::<[u8; AES256KEY_BYTES]>();
        let mut cleartext_payload = uninit::<[u8; AES256KEY_BYTES + UNUSED_SIZE]>();
        OsRng.try_fill_bytes(&mut nonce)?;
        OsRng.try_fill_bytes(&mut content_key)?;
        fill_array(&mut cleartext_payload, &UNUSED_CONTENT, &content_key);

        let v = aes_gcm::Aes256Gcm::new_from_slice(&self.encryption_master)?;
        let dec = v.encrypt(<&Nonce<_>>::from(&nonce), cleartext_payload.as_slice())?;
        split_array(&dec, &mut cleartext_payload, &mut tag);
        Ok((FileHeader {
            nonce,
            enc_content_key: cleartext_payload,
            tag,
        }, content_key))
    }

    fn decrypt_header(&self, header: &FileHeader) -> Result<([u8; UNUSED_SIZE], CryptoAes256Key)> {
        let v = aes_gcm::Aes256Gcm::new_from_slice(&self.encryption_master)?;
        let mut payload = uninit::<[u8; ENCRYPTED_CONTENT_KEY + TAG_SIZE]>();
        fill_array(&mut payload, &header.enc_content_key, &header.tag);
        let payload = Payload::from(payload.as_slice());
        let dec = v.decrypt(<&Nonce<_>>::from(&header.nonce), payload)?;
        let mut unused = uninit::<[u8; UNUSED_SIZE]>();
        let mut content_key = uninit::<[u8; AES256KEY_BYTES]>();
        split_array(&dec, &mut unused, &mut content_key);
        Ok((unused, content_key))
    }

    fn write_header<T: Write>(&self, writer: &mut T) -> Result<(FileHeader, CryptoAes256Key)> {
        let (header, content_key) = self.create_file_header()?;
        writer.write_all(header.nonce.as_slice())?;
        writer.write_all(header.enc_content_key.as_slice())?;
        writer.write_all(header.tag.as_slice())?;
        writer.flush()?;
        Ok((header, content_key))
    }

    fn write_uncompressed_name(&self, dir_id: &DirId, name: &str, compressed_name: &str) -> Result<()> {
        let encrypted = self.filename_encrypt(name, dir_id, true)?;
        let dir_path = dir_id.path().join(compressed_name);
        let file_name_path = dir_path.join(STDFILE_NAME);
        fs::create_dir_all(&dir_path)?;
        fs::write(&file_name_path, encrypted.to_path_name())?;
        Ok(())
    }

    fn aes_siv_dec(&self, data: &[u8], dir_id: Option<&DirId>) -> Result<Vec<u8>> {
        let mut siv: aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>> = aes_siv::siv::Siv::new(&self.siv_key);
        Ok(match dir_id {
            Some(dir_id) => { siv.decrypt::<_, _>(&[&dir_id.unencrypted], data) }
            None => { siv.decrypt::<&[&[u8]], _>(&[], data) }
        }?)
    }

    pub(crate) fn aes_siv_enc(&self, data: &[u8], dir_id: Option<&DirId>) -> Result<Vec<u8>> {
        let mut siv: aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>> = aes_siv::siv::Siv::new(&self.siv_key);
        Ok(match dir_id {
            Some(dir_id) => { siv.encrypt::<_, _>(&[&dir_id.unencrypted], data) }
            None => { siv.encrypt::<&[&[u8]], _>(&[], data) }
        }?)
    }

    pub(crate) fn filename_encrypt(&self, name: &str, parent: &DirId, force_enc: bool) -> Result<EncryptedFilename> {
        let siv = self.aes_siv_enc(name.nfc().to_string().as_bytes(), Some(parent))?;
        let name = base64_enc(&siv);
        Ok(if !force_enc && name.len() + EXTENSION_SIZE > self.metadata.shortening_threshold as usize {
            let xx = format!("{}.c9r", name);
            let n = sha1(xx.as_bytes());
            EncryptedFilename::Compressed(base64_enc(&n))
        } else {
            EncryptedFilename::Encrypted(name)
        })
    }

    pub(crate) fn filename_decrypt(&self, name: &str, parent: &DirId) -> Result<RoString> {
        let x = base64_dec(name)?;
        let siv = self.aes_siv_dec(&x, Some(parent))?;
        let sss = String::from_utf8(siv).map_err(|_| CryptoError::CorruptedFilename)?;
        Ok(sss.into())
    }

    pub(crate) fn read_entire_content<T: Read + Seek>(&self, reader: &mut T) -> Result<Vec<u8>> {
        let mut x = self.file_handle(reader)?;
        let mut data = Vec::new();
        x.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn open(vault_root: &Path, password: &[u8]) -> Result<Self> {
        let vault_path = vault_root.join("vault.cryptomator");
        let vault_content = fs::read_to_string(vault_path.as_path())?;
        let token: Token<Header, VaultMetadata, _> = Token::parse_unverified(&vault_content).map_err(|_| CryptoError::CorruptedFile)?;
        let key_id = token.header().key_id().ok_or(CryptoError::CorruptedFile)?;
        let uri = Url::parse(key_id).map_err(|_| CryptoError::CorruptedFile)?;
        if uri.scheme() != "masterkeyfile" {
            return Err(CryptoError::Unsupported("scheme"));
        }
        if token.claims().format != CRYPTOMATOR_VAULT_VERSION {
            return Err(CryptoError::Unsupported("vault_version"));
        }
        if token.claims().cipher_combo != "SIV_GCM" {
            return Err(CryptoError::Unsupported("cipher_combo"));
        }
        if token.header().algorithm != AlgorithmType::Hs256 {
            return Err(CryptoError::Unsupported("algorithm"));
        }

        let masterkey_path = vault_root.join(uri.path());
        let x = fs::read_to_string(&masterkey_path)?;
        let masterkey: SerdeMasterKey = serde_json::from_str(&x)?;
        let mut kek_key = uninit::<[u8; KEK_KEY_LENGTH]>();
        let mut encryption_master = uninit::<[u8; ENC_KEY_LENGTH]>();
        let mut mac_master = uninit::<[u8; MAC_KEY_LENGTH]>();
        let mut supreme_key = uninit::<[u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH]>();
        let kek_param = Params::new(masterkey.scrypt_cost_param.ilog2() as u8, masterkey.scrypt_block_size, SCRYPT_PARALLELISM, SCRYPT_KEY_LENGTH).map_err(|_| CryptoError::InvalidParameters)?;
        scrypt::scrypt(password, &masterkey.scrypt_salt, &kek_param, &mut kek_key).map_err(|_| CryptoError::InvalidParameters)?;
        let kek = Kek::from(kek_key);
        kek.unwrap(&masterkey.primary_master_key, &mut encryption_master).map_err(|_| CryptoError::InvalidParameters)?;
        kek.unwrap(&masterkey.hmac_master_key, &mut mac_master).map_err(|_| CryptoError::InvalidParameters)?;
        fill_array(&mut supreme_key, &encryption_master, &mac_master);


        let key: Box<dyn VerifyingAlgorithm> = match token.header().algorithm {
            AlgorithmType::Hs256 => {
                let key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
                Box::new(key)
            }
            AlgorithmType::Hs384 => {
                let key: Hmac<Sha384> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
                Box::new(key)
            }
            AlgorithmType::Hs512 => {
                let key: Hmac<Sha512> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
                Box::new(key)
            }
            _ => return Err(CryptoError::CorruptedFile),
        };

        let _: Token<Header, VaultMetadata, _> = vault_content.verify_with_key(&key).map_err(|_| CryptoError::InvalidParameters)?;

        let mut mac_key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&mac_master)?;
        mac_key.update(&masterkey.version.to_be_bytes());
        mac_key.verify_slice(&masterkey.version_mac).map_err(|_| CryptoError::InvalidParameters)?;
        let mut siv_key = uninit::<[u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH]>();
        fill_array(&mut siv_key, &mac_master, &encryption_master);
        Ok(Cryptomator {
            siv_key: GenericArray::from(siv_key),
            encryption_master,
            metadata: token.claims().clone(),
            vault_root: vault_root.to_path_buf(),
        })
    }

    pub fn create_vault(vault_root: &Path, password: &[u8]) -> Result<Self> {
        fs::create_dir_all(vault_root)?;
        let mut kek_key = uninit::<[u8; KEK_KEY_LENGTH]>();
        let mut encryption_master = uninit::<[u8; ENC_KEY_LENGTH]>();
        let mut mac_master = uninit::<[u8; MAC_KEY_LENGTH]>();
        let mut scrypt_salt = uninit::<[u8; SCRYPT_SALT_SIZE]>();
        let mut wrapped_encryption_master = uninit::<[u8; ENC_KEY_LENGTH + SCRYPT_SALT_SIZE]>();
        let mut wrapped_mac_master = uninit::<[u8; MAC_KEY_LENGTH + SCRYPT_SALT_SIZE]>();
        let mut supreme_key = uninit::<[u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH]>();
        OsRng.try_fill_bytes(&mut encryption_master)?;
        OsRng.try_fill_bytes(&mut mac_master)?;
        OsRng.try_fill_bytes(&mut scrypt_salt)?;
        let params = Params::new(SCRYPT_COST_LOG, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELISM, SCRYPT_KEY_LENGTH).map_err(|_| CryptoError::InvalidParameters)?;
        scrypt::scrypt(password, &scrypt_salt, &params, &mut kek_key).map_err(|_| CryptoError::InvalidParameters)?;
        let kek = Kek::from(kek_key);
        kek.wrap(&encryption_master, &mut wrapped_encryption_master).map_err(|_| CryptoError::InvalidParameters)?;
        kek.wrap(&mac_master, &mut wrapped_mac_master).map_err(|_| CryptoError::InvalidParameters)?;
        let mut mac: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&mac_master)?;
        mac.update(&MASTERKEY_VERSION.to_be_bytes());
        let result = mac.finalize();
        let master = SerdeMasterKey {
            version: 999,
            scrypt_salt: scrypt_salt.to_vec(),
            scrypt_cost_param: 2u64.pow(SCRYPT_COST_LOG as u32),
            scrypt_block_size: SCRYPT_BLOCK_SIZE,
            primary_master_key: wrapped_encryption_master.to_vec(),
            hmac_master_key: wrapped_mac_master.to_vec(),
            version_mac: result.into_bytes().to_vec(),
        };

        let vault_payload = VaultMetadata {
            jti: Uuid::new_v4().to_string(),
            format: 8,
            cipher_combo: "SIV_GCM".to_string(),
            shortening_threshold: 220,
        };
        let header = Header {
            algorithm: AlgorithmType::Hs256,
            key_id: Some("masterkeyfile:masterkey.cryptomator".to_string()),
            type_: Some(HeaderType::JsonWebToken),
            content_type: None,
        };
        fill_array(&mut supreme_key, &encryption_master, &mac_master);
        let key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
        let token = Token::new(header, &vault_payload).sign_with_key(&key).map_err(|_| CryptoError::InvalidParameters)?;

        let masterkey_path = vault_root.join("masterkey.cryptomator");
        let masterkey_path_bak = vault_root.join("masterkey.cryptomator.bak");
        fs::write(&masterkey_path, serde_json::to_vec(&master)?)?;
        let vault_path = vault_root.join("vault.cryptomator");
        let vault_path_bak = vault_root.join("vault.cryptomator.bak");
        fs::write(&vault_path, token.as_str())?;
        fs::copy(vault_path, vault_path_bak)?;
        fs::copy(masterkey_path, masterkey_path_bak)?;

        let mut siv_key = uninit::<[u8; MAC_KEY_LENGTH + ENC_KEY_LENGTH]>();
        fill_array(&mut siv_key, &mac_master, &encryption_master);


        let mator = Cryptomator {
            encryption_master,
            siv_key: GenericArray::from(siv_key),
            metadata: vault_payload,
            vault_root: vault_root.to_path_buf(),
        };
        let id = DirId::from_str(b"", &mator)?;
        fs::create_dir_all(id.path())?;


        let child_dir_id_file = id.path().join(STDFILE_DIRID);
        let mut f = SeekableRw::from_path(&child_dir_id_file)?;
        mator.write_header(&mut f)?;
        let mut writer = mator.file_handle(f)?;
        writer.write_all(&id.unencrypted)?;
        Ok(mator)
    }

    pub fn encrypted_file_size(path: &Path) -> Result<u64> {
        let total_size = path.metadata()?.len();
        file_size_from_size(total_size)
    }

    pub fn rename(&self, old_dir: &DirId, old_name: &str, new_dir: &DirId, new_name: &str, no_replace: bool) -> Result<Option<()>> {
        let old_entry = old_dir.lookup(old_name)?;
        if old_entry.is_none() { return Ok(None); }
        let old_entry = old_entry.unwrap().entry_type;
        let new_entry = old_dir.lookup(old_name)?.map(|e| e.entry_type);
        if let Some(item) = new_entry {
            if no_replace {
                return Err(UnixError(libc::EEXIST));
            }
            match (&old_entry, item) {
                (CryptoEntryType::Directory { .. }, CryptoEntryType::Directory { .. }) => {}
                (CryptoEntryType::Directory { .. }, _) => { return Err(UnixError(libc::ENOTDIR)) }
                (_, CryptoEntryType::Directory { .. }) => { return Err(UnixError(libc::ENOTDIR)) }
                _ => {}
            }
            self.delete_entry(new_dir, new_name)?;
        }
        match old_entry {
            CryptoEntryType::Directory { dir_id } => {
                let old_dir = DirId::from_str(&dir_id, self)?;
                self.delete_fs(&old_dir, old_name)?;
                self.create_directory_with_dir_id(new_dir, new_name, &dir_id)?;
            }
            CryptoEntryType::File { abs_path: from_path } => {
                let new_file = self.create_file(new_dir, new_name, true)?;
                let to_path = new_file.entry_type.file();
                fs::rename(self.vault_root.join(from_path), self.vault_root.join(to_path))?;
                self.delete_fs(old_dir, old_name)?;
            }
            CryptoEntryType::Symlink { target } => {
                self.create_symlink(new_dir, new_name, &target)?;
                self.delete_entry(old_dir, old_name)?;
            }
        }
        Ok(Some(()))
    }

    pub fn truncate_file(&self, path: &PathBuf) -> Result<()> {
        let f = fs::File::options().write(true).open(path)?;
        f.set_len(FILE_HEADER_SIZE as u64)?;
        Ok(())
    }

    pub fn create_directory(&self, parent: &DirId, name: &str) -> Result<CryptoEntry> {
        self.create_directory_with_dir_id(parent, name, Uuid::new_v4().to_string().as_bytes())
    }

    pub fn create_symlink(&self, parent: &DirId, name: &str, target: &str) -> Result<CryptoEntry> {
        let enc_name = self.filename_encrypt(name, parent, false)?;
        let parent_path_entry = parent.path().join(enc_name.to_path_name());
        fs::create_dir_all(&parent_path_entry)?;
        if enc_name.is_compressed() {
            self.write_uncompressed_name(parent, name, enc_name.get_compressed())?;
        }
        // write symlink.c9r with the target
        let parent_dir_id_file = parent_path_entry.join(STDFILE_SYMLINK);
        let mut f = SeekableRw::from_path(&parent_dir_id_file)?;
        self.write_header(&mut f)?;
        let mut writer = self.file_handle(f)?;
        writer.write_all(target.as_bytes())?;
        Ok(CryptoEntry {
            name: name.into(),
            entry_type: CryptoEntryType::Symlink { target: target.into() },
        })
    }

    pub fn create_file(&self, dir_id: &DirId, name: &str, exclusive: bool) -> Result<CryptoEntry> {
        if let Some(e) = dir_id.lookup(name)? {
            return if exclusive {
                Err(UnixError(libc::EEXIST))
            } else {
                Ok(e)
            };
        }
        let v = self.filename_encrypt(name, dir_id, false)?;
        let enc_name = v.to_path_name();
        let mut path = dir_id.path().join(&enc_name);
        if v.is_compressed() {
            self.write_uncompressed_name(dir_id, name, &enc_name)?;
            path = path.join(STDFILE_CONTENTS);
        }
        let mut f = BufWriter::new(fs::File::create(&path)?);
        self.write_header(&mut f)?;
        Ok(CryptoEntry {
            name: name.into(),
            entry_type: CryptoEntryType::File { abs_path: path.strip_prefix(&self.vault_root).map_err(|_| CryptoError::CorruptedFilename)?.to_path_buf().into_boxed_path() },
        })
    }

    pub fn delete_entry(&self, parent: &DirId, name: &str) -> Result<Option<()>> {
        let x = parent.lookup(name)?;
        if x.is_none() { return Ok(None); }

        if let CryptoEntryType::Directory { dir_id } = x.unwrap().entry_type {
            let child_id = DirId::from_str(&dir_id, self)?;
            let path = child_id.path();
            if fs::read_dir(&path)?.filter(|e| e.is_ok()).count() > 1 {
                return Err(UnixError(libc::ENOTEMPTY));
            }
            delete_file(&path)?;
        }

        self.delete_fs(parent, name)?;
        Ok(Some(()))
    }

    pub fn file_handle<T: Read + Seek>(&self, mut reader: T) -> Result<FileHandle<T>> {
        reader.seek(SeekFrom::Start(0))?;
        let header = read_file_header(&mut reader)?;
        let (_, content_key) = self.decrypt_header(&header)?;
        Ok(FileHandle {
            handle: reader,
            header,
            content_key,
            offset: 0,
        })
    }

    pub fn vault_root(&self) -> &Path {
        &self.vault_root
    }
}

fn delete_file(file_path: &PathBuf) -> Result<()> {
    if !file_path.exists() { return Ok(()); }
    if file_path.is_dir() {
        fs::remove_dir_all(file_path)?
    } else if file_path.is_file() {
        fs::remove_file(file_path)?
    }
    Ok(())
}

fn read_file_header<T: Read>(reader: &mut T) -> Result<FileHeader> {
    let mut header = uninit::<FileHeader>();
    reader.read_exact(&mut header.nonce)?;
    reader.read_exact(&mut header.enc_content_key)?;
    reader.read_exact(&mut header.tag)?;
    Ok(header)
}

#[derive(Clone, Hash)]
pub enum CryptoEntryType {
    Symlink { target: RoString },
    Directory { dir_id: DirIdData },
    File { abs_path: RoPath },
}

impl Debug for CryptoEntryType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoEntryType::Symlink { target } => f.debug_struct("Symlink").field("target", target).finish(),
            CryptoEntryType::Directory { dir_id } => {
                let mut s = f.debug_struct("Directory");
                s.field("dir_id", &String::from_utf8_lossy(dir_id));
                s.finish()
            }
            CryptoEntryType::File { abs_path } => f.debug_struct("File").field("abs_path", abs_path).finish(),
        }
    }
}

impl CryptoEntryType {
    pub fn is_symlink(&self) -> bool {
        matches!(self, CryptoEntryType::Symlink { .. })
    }
    pub fn is_directory(&self) -> bool {
        matches!(self, CryptoEntryType::Directory { .. })
    }
    pub fn is_file(&self) -> bool {
        matches!(self, CryptoEntryType::File { .. })
    }

    pub fn directory(&self) -> &DirIdData {
        match self {
            CryptoEntryType::Directory { dir_id } => { dir_id }
            _ => { unreachable!() }
        }
    }

    pub fn file(&self) -> &Path {
        match self {
            CryptoEntryType::File { abs_path } => { abs_path }
            _ => { unreachable!() }
        }
    }

    pub fn symlink(&self) -> &str {
        match self {
            CryptoEntryType::Symlink { target } => { target }
            _ => { unreachable!() }
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct CryptoEntry {
    pub name: RoString,
    pub entry_type: CryptoEntryType,
}
