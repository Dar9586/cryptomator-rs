use cryptomator_crypto::DirId;
use anyhow::Result;
use fallible_iterator::FallibleIterator;
use std::fs::File;
use std::path::PathBuf;

fn main() ->Result<()>{
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/XYywXz5hdoq9Nk4upZ2OFzGU0rM=.c9s/contents.c9r";
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/dirid.c9r";
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/BMPUk1CCusyIVdtCS05YCJCb.c9r/symlink.c9r";
    let mut reader = File::open(path)?;
    let mator=cryptomator_crypto::CryptomatorOpen{
        vault_path:PathBuf::from("/home/dar9586/Test/"),
        password: "ciaociao".to_string()
    };
    let x=mator.open()?;
    let dir_id = DirId::from_str("6d5f1839-e421-4720-b491-17c97dfe9b28", &x)?;
    for x in dir_id.list_files()? {
        println!("Entry: {:?}", x);
    }
    let s = x.filename_encrypt("WELCOME.rtf", &dir_id)?;
    println!("{:?}", s);
    let s = x.filename_decrypt(&s.encrypted, &dir_id)?;
    println!("{:?}", s);
    let s = x.filename_encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &dir_id)?;
    println!("{:?}", s);
    let s = x.filename_encrypt("ciao", &dir_id)?;
    println!("{:?}", s);

    for chunk in x.read_file_content(&mut reader)?.iterator() {
        println!("{:?}", chunk?);
    }
    Ok(())
}
