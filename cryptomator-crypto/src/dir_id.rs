use crate::errors::CryptoError;
use crate::errors::Result;
use crate::utils::{DirIdData, DIRID_NAME_LENGTH};
use crate::{cryptomator, utils, CryptoEntry, CryptoEntryType, Cryptomator};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
#[derive(Clone, Debug)]
pub struct DirId<'a> {
    pub unencrypted: DirIdData,
    prefix: String,
    suffix: String,
    crypto: &'a Cryptomator,
}
impl<'a> DirId<'a> {
    fn try_read_dir(&self, abs_path: &Path, dec_name: &str) -> Result<Option<CryptoEntry>> {
        let sub_dir_path = abs_path.join("dir.c9r");
        if !sub_dir_path.exists() { return Ok(None); }
        let dir_id = fs::read(sub_dir_path)?;
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
        let target = String::from_utf8(target).map_err(|_| CryptoError::CorruptedFile)?;
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
        let encrypted_name = self.crypto.filename_encrypt(unencrypted_name, self, false)?;
        self.lookup_enc(&encrypted_name.to_path_name())
    }

    fn lookup_enc(&self, name: &str) -> Result<Option<CryptoEntry>> {
        let abs_path = self.path().join(name);
        if !abs_path.exists() { return Ok(None); }
        let meta = abs_path.metadata()?;
        let entry_type = meta.file_type();
        let name_no_ext = &name[..name.len() - cryptomator::EXTENSION_LENGTH];
        if entry_type.is_file() {
            Ok(Some(self.parse_file(abs_path, name_no_ext)?))
        } else if entry_type.is_dir() {
            Ok(Some(self.parse_dir(name, &abs_path, name_no_ext)?))
        } else {
            Err(CryptoError::CorruptedFilename)
        }
    }

    pub fn list_files(&self) -> Result<Vec<CryptoEntry>> {
        let mut entries = Vec::new();
        let dir_path = self.path();
        for entry in fs::read_dir(&dir_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(CryptoError::CorruptedFilename)?;
            if name == "dirid.c9r" {
                continue;
            }
            if let Some(entry) = self.lookup_enc(name)? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn parse_dir(&self, name: &str, abs_path: &Path, name_no_ext: &str) -> Result<CryptoEntry> {
        let compressed = name.ends_with(".c9s");
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
            let name_file = abs_path.join("name.c9s");
            let uncompressed_name = fs::read_to_string(&name_file)?;
            let dec_name = self.crypto.filename_decrypt(&uncompressed_name[..uncompressed_name.len() - cryptomator::EXTENSION_LENGTH], self)?;
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
            entry_type: CryptoEntryType::File { abs_path },
        })
    }

    pub fn path(&self) -> PathBuf {
        self.crypto.vault_root.join("d").join(&self.prefix).join(&self.suffix)
    }

    pub fn from_str(str: &[u8], crypto: &'a Cryptomator) -> Result<Self> {
        let siv = crypto.aes_siv_enc(str, None)?;
        let sha = utils::sha1(&siv);
        let mut encoded = utils::base32_enc(&sha);
        assert_eq!(encoded.len(), DIRID_NAME_LENGTH);
        let suffix = encoded.split_off(2);
        Ok(Self {
            unencrypted: str.to_vec(),
            prefix: encoded,
            suffix,
            crypto,
        })
    }
}

