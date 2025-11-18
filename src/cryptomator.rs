use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use aes_kw::Kek;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};
use byte_unit::{Byte, Unit};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use jwt::{FromBase64, Header, Token, VerifyWithKey, VerifyingAlgorithm};
use scrypt::Params;
use serde_with::serde_as;
use serde_with::base64::{Base64};
use sha1::{Sha1, Digest};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use aes_gcm::aes::Aes256;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::aead::Payload;
use aes_siv::{Aes256SivAead, SivAead};
use base32::Alphabet;
use cmac::digest::consts::{U18, U64};
use hmac::digest::consts::U8;
use hmac::digest::core_api::CoreWrapper;

pub struct CryptomatorOpen{
    pub vault_path: PathBuf,
    pub password: String,
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

const SCRYPT_PARALLELISM:u32=1;
const SCRYPT_KEY_LENGTH:usize=32;

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
        let mut kek_key=[0u8;SCRYPT_KEY_LENGTH];
        let mut encryption_master=[0u8;SCRYPT_KEY_LENGTH];
        let mut mac_master=[0u8;SCRYPT_KEY_LENGTH];
        scrypt::scrypt(self.password.as_bytes(), &masterkey.scrypt_salt, &kek_param, &mut kek_key)?;
        let kek=Kek::from(kek_key);
        kek.unwrap(&masterkey.primary_master_key,&mut encryption_master).unwrap();
        kek.unwrap(&masterkey.hmac_master_key,&mut mac_master).unwrap();
        let supreme_key=concat_vec(&encryption_master,&mac_master);
        let key: Hmac<Sha256> = <CoreWrapper<_> as Mac>::new_from_slice(&supreme_key)?;
        let token: Token<Header, VaultMetadata, _> = vault_content.verify_with_key(&key)?;

        let mut siv_key=[0u8;64];
        siv_key[..32].copy_from_slice(&mac_master);
        siv_key[32..].copy_from_slice(&encryption_master);

        Ok(Cryptomator{
            siv_key:GenericArray::from(siv_key),
            encryption_master,
            mac_master,
            metadata:token.claims().clone(),
            vault_root:self.vault_path.clone()
        })
    }
}
#[derive(Clone,Debug)]
pub struct Cryptomator {
    encryption_master:[u8;SCRYPT_KEY_LENGTH],
    mac_master:[u8;SCRYPT_KEY_LENGTH],
    metadata:VaultMetadata,
    vault_root:PathBuf,
    siv_key:GenericArray<u8,U64>,
}

#[derive(Debug,Default)]
struct FileHeader{
    nonce:[u8;12],
    _unused:[u8;8],
    content_key:[u8;32],
    tag:[u8;16],
}

#[derive(Clone, Debug)]
pub struct DirId<'a>{
    unencrypted:String,
    prefix:String,
    suffix:String,
    vault_root:&'a PathBuf
}


fn aes_siv(crypto:&Cryptomator,data:&[u8],dir_id: Option<DirId>)->Result<Vec<u8>>{
    let mut siv:aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>>=aes_siv::siv::Siv::new(&crypto.siv_key);//::new(&GenericArray::from(supreme_key));
    Ok(match dir_id {
        Some(dir_id) => {siv.encrypt::<_, _>(&[dir_id.unencrypted.as_bytes()], data) }
        None=>{siv.encrypt::<&[&[u8]], _>(&[], data) }
    }.map_err(|e| anyhow!(e))?)
}

impl<'a> DirId<'a>{

    pub fn path(&self) -> PathBuf{
        //dirIdHash := base32(sha1(aesSiv(dirId, null, encryptionMasterKey, macMasterKey)))
        // dirPath := vaultRoot + '/d/' + substr(dirIdHash, 0, 2) + '/' + substr(dirIdHash, 2, 30)
        self.vault_root.join("d").join(&self.prefix).join(&self.suffix)
    }

    pub fn from_str(str:&str,crypto:&'a Cryptomator)->Result<Self>{
        let mut siv:aes_siv::siv::Siv<Aes256, cmac::Cmac<Aes256>>=aes_siv::siv::Siv::new(&crypto.siv_key);//::new(&GenericArray::from(supreme_key));
        let enc=siv.encrypt::<&[&[u8]], _>([].as_slice(),str.as_bytes()).map_err(|e|anyhow!(e))?;
        let mut hasher = Sha1::new();
        hasher.update(&enc);
        let result = hasher.finalize();
        let mut encoded=base32::encode(Alphabet::Rfc4648 {padding:true},&result);
        assert_eq!(encoded.len(),32);
        let suffix=encoded.split_off(2);
        Ok(Self{
            unencrypted:str.to_string(),
            prefix:encoded,
            suffix,
            vault_root:&crypto.vault_root
        })
    }
}

fn filename_encrypt(name:&str,parent:&DirId,mator:&Cryptomator)->Result<()>{



    Ok(())
}

const FILE_CHUNK_SIZE:usize=32028;
#[derive(Debug,Default)]
struct FileChunk{
    nonce:[u8;12],
    encrypted_payload:Vec<u8>,
    tag:[u8;16],
}

impl From<&[u8]> for FileChunk {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() >= 12+16);
        let mut nonce=[0u8;12];
        let mut tag=[0u8;16];
        nonce.copy_from_slice(&value[..12]);
        tag.copy_from_slice(&value[value.len()-16..]);
        let encrypted_payload=value[12..value.len()-16].to_vec();
        assert_eq!(encrypted_payload.len(),value.len()-12-16);
        Self{nonce,encrypted_payload,tag}
    }
}

fn read_chunk<T:Read>(reader:&mut T)->Result<FileChunk>{
    let mut chunk=[0u8;FILE_CHUNK_SIZE];
    let mut reached=0;
    loop{
        let r=reader.read(&mut chunk[reached..])?;
        if r==0{
            return Ok(FileChunk::from(&chunk[..reached]));
        }
        reached+=r;
        if reached==chunk.len(){
            return Ok(FileChunk::from(&chunk[..reached]))
        }
    }
}

fn decrypt_chunk(chunk:FileChunk,content_key:[u8;32])->Result<Vec<u8>>{
    let v=aes_gcm::Aes256Gcm::new_from_slice(&content_key)?;
    let dec=v.decrypt(<&Nonce<_>>::from(&chunk.nonce), &*chunk.encrypted_payload).map_err(|e|anyhow!(e))?;
    Ok(dec)
}
fn read_file_content<T:Read>(header:FileHeader, reader:&mut T)->Result<()>{
    loop {
        let chunk=read_chunk(reader)?;
        let dec=decrypt_chunk(chunk,header.content_key)?;
        println!("Decrypted chunk:{:?}",dec);
    }
}

fn read_file_header<T:Read>(reader:&mut T) -> Result<FileHeader>{
    let mut header=FileHeader::default();
    reader.read_exact(&mut header.nonce)?;
    reader.read_exact(&mut header._unused)?;
    reader.read_exact(&mut header.content_key)?;
    reader.read_exact(&mut header.tag)?;
    Ok(header)
}

