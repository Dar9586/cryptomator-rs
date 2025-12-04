use aes_siv::aead;
use hmac::digest::InvalidLength;
use rand::rand_core::OsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO exception")]
    IO(#[from] std::io::Error),
    #[error("corrupted file")]
    CorruptedFile,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("corrupted filename")]
    CorruptedFilename,
    #[error("error while performing crypto")]
    EncryptionError(#[from] aead::Error),
    #[error("invalid length for key/iv")]
    InvalidLength(#[from]InvalidLength),
    #[error("random generation failed")]
    OsError(#[from]OsError),
    #[error("error during serialization")]
    SerializationError(#[from]serde_json::Error),
    #[error("unix errno")]
    UnixError(i32),
    #[error("unsupported schema")]
    Unsupported(&'static str),
}

impl CryptoError {
    pub fn to_errno(&self) -> Option<i32> {
        match self {
            CryptoError::IO(e) => e.raw_os_error(),
            CryptoError::OsError(e) => e.raw_os_error(),
            CryptoError::UnixError(e) => Some(*e),
            _ => None
        }
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;