use crate::errors::CryptoError;
use crate::errors::Result;
use crate::utils::*;
use crate::{CryptoEntry, CryptoEntryType, Cryptomator};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
#[derive(Clone, Debug)]
pub struct DirId<'a> {
    pub unencrypted: DirIdData,
    prefix: RoString,
    suffix: RoString,
    crypto: &'a Cryptomator,
}
impl<'a> DirId<'a> {
    fn try_read_dir(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let sub_dir_path = abs_path.join(STDFILE_DIR);
        if !sub_dir_path.exists() { return Ok(None); }
        let dir_id = fs::read(sub_dir_path)?;
        Ok(Some(CryptoEntry {
            name: dec_name.into(),
            entry_type: CryptoEntryType::Directory { dir_id: dir_id.into() },
        }))
    }

    fn try_read_sym(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let sub_sym_path = abs_path.join(STDFILE_SYMLINK);
        if !sub_sym_path.exists() { return Ok(None); }
        let mut reader = BufReader::new(fs::File::open(&sub_sym_path)?);
        let target = self.crypto.read_entire_content(&mut reader)?;
        let target = String::from_utf8(target).map_err(|_| CryptoError::CorruptedFile)?;
        Ok(Some(CryptoEntry {
            name: dec_name.into(),
            entry_type: CryptoEntryType::Symlink { target: target.into() },
        }))
    }

    fn try_read_file(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let file_file = abs_path.join(STDFILE_CONTENTS);
        if !file_file.exists() { return Ok(None); }
        Ok(Some(CryptoEntry {
            name: dec_name.into(),
            entry_type: CryptoEntryType::File { abs_path: file_file.strip_prefix(&self.crypto.vault_root).map_err(|_| CryptoError::CorruptedFilename)?.to_path_buf().into_boxed_path() },
        }))
    }

    fn parse_dir(&self, name: &str, abs_path: &Path, name_no_ext: &str) -> Result<CryptoEntry> {
        let compressed = name.ends_with(COMPRESSED_EXTENSION);
        if !compressed {
            let dec_name = self.crypto.filename_decrypt(name_no_ext, self)?;
            if let Some(x) = self.try_read_dir(abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_sym(abs_path, &dec_name)? {
                Ok(x)
            } else {
                Err(CryptoError::CorruptedFile)
            }
        } else {
            let name_file = abs_path.join(STDFILE_NAME);
            let uncompressed_name = fs::read_to_string(&name_file)?;
            let dec_name = self.crypto.filename_decrypt(&uncompressed_name[..uncompressed_name.len() - EXTENSION_SIZE], self)?;
            if let Some(x) = self.try_read_dir(abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_sym(abs_path, &dec_name)? {
                Ok(x)
            } else if let Some(x) = self.try_read_file(abs_path, &dec_name)? {
                Ok(x)
            } else {
                Err(CryptoError::CorruptedFile)
            }
        }
    }

    fn parse_file(&self, abs_path: PathBuf, name_no_ext: &str) -> Result<CryptoEntry> {
        let name = self.crypto.filename_decrypt(name_no_ext, self)?;
        Ok(CryptoEntry {
            name,
            entry_type: CryptoEntryType::File { abs_path: abs_path.strip_prefix(&self.crypto.vault_root).map_err(|_| CryptoError::CorruptedFilename)?.to_path_buf().into_boxed_path() },
        })
    }

    pub fn lookup(&self, unencrypted_name: &str) -> Result<Option<CryptoEntry>> {
        let encrypted_name = self.crypto.filename_encrypt(unencrypted_name, self, false)?;
        self.lookup_enc(&encrypted_name.to_path_name())
    }

    fn lookup_enc(&self, name: &str) -> Result<Option<CryptoEntry>> {
        let abs_path = self.path().join(name);
        if !abs_path.exists() { return Ok(None); }
        let meta = abs_path.metadata()?;
        let entry_type = meta.file_type();
        let name_no_ext = &name[..name.len() - EXTENSION_SIZE];
        if entry_type.is_file() {
            Ok(Some(self.parse_file(abs_path, name_no_ext)?))
        } else if entry_type.is_dir() {
            Ok(Some(self.parse_dir(name, &abs_path, name_no_ext)?))
        } else {
            Err(CryptoError::CorruptedFilename)
        }
    }

    pub fn path(&self) -> PathBuf {
        self.crypto.vault_root.join("d").join(self.prefix.as_ref()).join(self.suffix.as_ref())
    }

    pub fn from_str(str: &[u8], crypto: &'a Cryptomator) -> Result<Self> {
        let siv = crypto.aes_siv_enc(str, None)?;
        let sha = sha1(&siv);
        let mut encoded = base32_enc(&sha);
        assert_eq!(encoded.len(), DIRID_NAME_LENGTH);
        let suffix = encoded.split_off(2);
        Ok(Self {
            unencrypted: str.into(),
            prefix: encoded.into(),
            suffix: suffix.into(),
            crypto,
        })
    }

    pub fn list_files(&self) -> Result<Vec<CryptoEntry>> {
        let mut entries = Vec::new();
        let dir_path = self.path();
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(CryptoError::CorruptedFilename)?;
            if name == STDFILE_DIRID {
                continue;
            }
            if let Some(entry) = self.lookup_enc(name)? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

