use std::path::PathBuf;
use anyhow::Result;
use crate::cryptomator::DirId;

mod cryptomator;

fn main() ->Result<()>{


    let mator=cryptomator::CryptomatorOpen{
        vault_path:PathBuf::from("/home/dar9586/Test/"),
        password: "ciaociao".to_string()
    };
    let x=mator.open()?;
    let dir_id =DirId::from_str("", &x)?;
    println!("{:?}", dir_id);

    Ok(())
}
