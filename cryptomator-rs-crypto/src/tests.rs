#![cfg(test)]

use crate::Cryptomator;

#[test]
fn create_and_open_vault() -> crate::Result<()> {
    let password = "test";
    let dir = tempdir::TempDir::new("vault")?;
    let dir_path = dir.path();
    Cryptomator::create_vault(dir_path, password.as_bytes())?;
    Cryptomator::open(dir_path, password.as_bytes())?;
    Ok(())
}