use crate::cryptomator::{filename_decrypt, filename_encrypt, read_file_content, read_file_header, DirId};
use anyhow::Result;
use std::fs::File;
use std::path::PathBuf;

mod cryptomator;

fn main() ->Result<()>{
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/XYywXz5hdoq9Nk4upZ2OFzGU0rM=.c9s/contents.c9r";
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/dirid.c9r";
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/BMPUk1CCusyIVdtCS05YCJCb.c9r/symlink.c9r";
    let mut reader = File::open(path)?;
    let mator=cryptomator::CryptomatorOpen{
        vault_path:PathBuf::from("/home/dar9586/Test/"),
        password: "ciaociao".to_string()
    };
    let x=mator.open()?;
    let dir_id =DirId::from_str("", &x)?;
    let s = filename_encrypt("WELCOME.rtf", &dir_id, &x)?;
    println!("{:?}", s);
    let s = filename_decrypt(&s.encrypted, &dir_id, &x)?;
    println!("{:?}", s);
    let s = filename_encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &dir_id, &x)?;
    println!("{:?}", s);
    let s = filename_encrypt("ciao", &dir_id, &x)?;
    println!("{:?}", s);

    let header = read_file_header(&mut reader)?;
    let content = read_file_content(&header, &mut reader, &x)?;
    Ok(())
}
