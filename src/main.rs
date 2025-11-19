#![allow(dead_code, unused_variables, unused_imports)]
use anyhow::Result;
use std::path::PathBuf;
use tracing::instrument;
use tracing_subscriber::fmt::format::FmtSpan;


#[derive(Debug)]
struct MyType;

impl MyType {
    #[instrument]
    fn foo(&self, x: i32, y: String) {
        println!("Inside foo");
    }
}

fn main() ->Result<()>{
    /*
        let mator=cryptomator_crypto::CryptomatorOpen{
            vault_path:PathBuf::from("/home/dar9586/Test/"),
            password: "ciaociao".to_string()
        };
        let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/XYywXz5hdoq9Nk4upZ2OFzGU0rM=.c9s/contents.c9r";
        let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/dirid.c9r";
        let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/BMPUk1CCusyIVdtCS05YCJCb.c9r/symlink.c9r";
        let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/22jBtpPHTpUfYGbD-rH0fWRudA==.c9r";
        let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/B7UHjtZBwwlUJzdMg4sh4V3zyTRO7ew6PvWyszpTs_Xz4VVcUM1u.c9r";
        let mut reader = File::open(path)?;
        let x=mator.open()?;
        let dir_id = DirId::from_str("6d5f1839-e421-4720-b491-17c97dfe9b28", &x)?;
        for x in dir_id.list_files()? {
            println!("Entry: {:?}", x);
        }
        let s = x.filename_encrypt("WELCOME.rtf", &dir_id)?;
        println!("{:?}", s);
    
        let s = x.filename_encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &dir_id)?;
        println!("{:?}", s);
        let s = x.filename_encrypt("ciao", &dir_id)?;
        println!("{:?}", s);
    
        for chunk in x.read_file_content(&mut reader)?.iterator() {
            println!("{:?}", chunk?);
        }
    
        exit(0);
    
     */

    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER)
        .with_env_filter("info")  // or "debug", or "mycrate=trace"
        .init();    // REQUIRED: set up logging


    let mator = cryptomator_crypto::CryptomatorOpen {
        vault_path: PathBuf::from("/home/dar9586/Test/"),
        password: "ciaociao".to_string(),
    };

    let fuse = cryptomator_fuse_rs::CryptoFuse::new(mator.open()?);
    cryptomator_fuse_rs::mount2(
        fuse,
        PathBuf::from("/home/dar9586/Programmazione/Progetti/Rust/cryptomator-cli-rs/mount"),
        &[
            cryptomator_fuse_rs::MountOption::RO,
            cryptomator_fuse_rs::MountOption::AutoUnmount,
            cryptomator_fuse_rs::MountOption::AllowRoot,
        ],
    )?;
    Ok(())
}
