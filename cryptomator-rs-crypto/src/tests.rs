#![cfg(test)]

use crate::{create_vault, CryptomatorOpen};
use std::path::PathBuf;

#[test]
fn create_and_open_vault() -> crate::Result<()> {
    let password = "test";
    let dir = tempdir::TempDir::new("vault")?;
    let dir_path = dir.path();
    create_vault(dir_path, password.as_bytes())?;
    CryptomatorOpen {
        vault_path: PathBuf::from(dir_path),
        password: password.to_string(),
    }.open()?;
    Ok(())
}