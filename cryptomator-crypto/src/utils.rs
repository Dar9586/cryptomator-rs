use crate::errors;
use crate::errors::CryptoError;
use aes_gcm::aes::cipher::crypto_common::Output;
use base32::Alphabet;
use base64::Engine;
use cmac::digest::Digest;
use sha1::Sha1;
use std::mem::MaybeUninit;

pub(crate) const UNUSED_CONTENT: [u8; 8] = [0xFF; 8];
pub(crate) const CLEAR_FILE_CHUNK_SIZE: usize = 32768; //32 KiB
pub(crate) const FILE_CHUNK_HEADERS_SIZE: usize = NONCE_SIZE + TAG_SIZE;
pub(crate) const FILE_CHUNK_HEADERS_SIZE_U64: u64 = FILE_CHUNK_HEADERS_SIZE as u64;
pub(crate) const FILE_CHUNK_SIZE: usize = CLEAR_FILE_CHUNK_SIZE + FILE_CHUNK_HEADERS_SIZE;
pub(crate) const FILE_HEADER_SIZE: usize = NONCE_SIZE + ENCRYPTED_CONTENT_KEY + TAG_SIZE;
pub(crate) const SCRYPT_PARALLELISM: u32 = 1;
pub(crate) const SCRYPT_KEY_LENGTH: usize = 32;
pub(crate) const DIRID_NAME_LENGTH: usize = 32;
pub(crate) const KEK_KEY_LENGTH: usize = 32;
pub(crate) const MAC_KEY_LENGTH: usize = 32;
pub(crate) const ENC_KEY_LENGTH: usize = 32;
pub(crate) const NONCE_SIZE: usize = 12;
pub(crate) const U64_BYTES: usize = (u64::BITS / 8) as usize;
pub(crate) const UNUSED_SIZE: usize = 8;
pub(crate) const AES256KEY_BYTES: usize = 32;
pub(crate) const TAG_SIZE: usize = 16;
pub(crate) type CryptoNonce = [u8; NONCE_SIZE];
pub(crate) type CryptoTag = [u8; TAG_SIZE];
pub(crate) type CryptoAes256Key = [u8; AES256KEY_BYTES];
pub(crate) const ENCRYPTED_CONTENT_KEY: usize = UNUSED_SIZE + AES256KEY_BYTES;
pub(crate) type RoString = Box<str>;
pub(crate) type RoBytes = Box<[u8]>;
pub(crate) type DirIdData = RoBytes;

pub(crate) const COMPRESSED_EXTENSION:&str=".c9s";
pub(crate) const ENCRYPTED_EXTENSION:&str=".c9r";
pub(crate) const EXTENSION_SIZE:usize=ENCRYPTED_EXTENSION.len();
pub(crate) const STDFILE_DIRID:&str="dirid.c9r";
pub(crate) const STDFILE_SYMLINK:&str="symlink.c9r";
pub(crate) const STDFILE_NAME:&str="name.c9s";
pub(crate) const STDFILE_DIR:&str="dir.c9r";
pub(crate) const STDFILE_CONTENTS:&str="contents.c9r";

 #[inline]
pub(crate) fn fill_array<T: Copy>(v: &mut [T], v1: &[T], v2: &[T]) {
    v[..v1.len()].copy_from_slice(v1);
    v[v1.len()..].copy_from_slice(v2);
}

#[inline]
pub(crate) fn split_array<T: Copy>(v: &[T], v1: &mut [T], v2: &mut [T]) {
    v1.copy_from_slice(&v[..v1.len()]);
    v2.copy_from_slice(&v[v1.len()..]);
}

pub(crate) fn sha1(data: &[u8]) -> Output<Sha1> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

pub(crate) fn base32_enc(data: &[u8]) -> String {
    base32::encode(Alphabet::Rfc4648 { padding: true }, data)
}

pub(crate) fn base64_enc(data: &[u8]) -> String {
    base64::prelude::BASE64_URL_SAFE.encode(data)
}

pub(crate) fn base64_dec(data: &str) -> errors::Result<Vec<u8>> {
    base64::prelude::BASE64_URL_SAFE.decode(data).map_err(|_| CryptoError::CorruptedFilename)
}

#[inline]
#[allow(clippy::uninit_assumed_init)]
pub fn uninit<T>()->T{
    unsafe{MaybeUninit::uninit().assume_init()}
}