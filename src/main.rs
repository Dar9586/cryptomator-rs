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

use std::fs;
use clap::{Parser, ArgGroup};

/// Demo CLI that accepts a directory path and one password source.
#[derive(Debug, Parser)]
#[command(author, version, about)]
#[command(group(
    ArgGroup::new("password_source")
        .args(["password", "password_file", "password_stdin"])
        .multiple(false) // only one source allowed
        .required(true)
))]
struct Cli {
    /// Directory to operate on
    #[arg(short, long)]
    vault_root: PathBuf,

    #[arg(short, long)]
    mount_point: PathBuf,

    /// Provide password directly
    #[arg(long)]
    password: Option<String>,

    /// Read password from file
    #[arg(long)]
    password_file: Option<PathBuf>,

    /// Read password from STDIN
    #[arg(long)]
    password_stdin: bool,

    #[arg(long)]
    read_write: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let password = get_password(&cli)?;

    let mator = cryptomator_crypto::CryptomatorOpen {
        vault_path: cli.vault_root,
        password,
    }.open()?;

    let fuse = cryptomator_fuse_rs::CryptoFuse::new(mator);
    cryptomator_fuse_rs::mount2(
        fuse,
        cli.mount_point,
        &[
            if cli.read_write{cryptomator_fuse_rs::MountOption::RW}else{cryptomator_fuse_rs::MountOption::RO},
            cryptomator_fuse_rs::MountOption::AutoUnmount,
            cryptomator_fuse_rs::MountOption::AllowRoot,
        ],
    )?;

    Ok(())
}

fn get_password(cli: &Cli) -> Result<String> {
    if let Some(pwd) = &cli.password {
        return Ok(pwd.clone());
    }

    if let Some(file) = &cli.password_file {
        return Ok(fs::read_to_string(file)?.trim_end().to_owned());
    }

    if cli.password_stdin {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        return Ok(rpassword::prompt_password("Enter password: ")?);
    }
    unreachable!()
}


fn main2() -> Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER)
        .with_env_filter("info")  // or "debug", or "mycrate=trace"
        .init();    // REQUIRED: set up logging


    let mator = cryptomator_crypto::CryptomatorOpen {
        vault_path: PathBuf::from("/home/dar9586/Test/"),
        password: "ciaociao".to_string(),
    }.open()?;
    /*let (header, content_key) = mator.create_file_header()?;
    let data = [0u8; 32];
    let encrypted = encrypt_chunk(&data, 0, &header.nonce, &content_key)?;
    println!("{:?}", encrypted);
    let decrypt = decrypt_chunk(encrypted, &content_key, 0, &header.nonce)?;
    println!("{:?}", decrypt);

    let dir_id = DirId::from_str("", &mator)?;
    let filename = "foglio.txt";
    {
        let entry = mator.create_file(&dir_id, &filename)?;
        println!("{:?}", entry);
        let writer = fs::File::options().write(true).read(true).open(entry.entry_type.file())?;
        let mut seekable = Seekable::from_file(writer)?;
        let mut writer = mator.file_writer(&mut seekable)?;

        writer.write(100_000, "ciao mondo".as_bytes())?;
    }
    let path = "/home/dar9586/Test/d/T4/UCNBOMUJR5RO4IRYF6774BIUITJRGD/XntFWCI2Mnfy712X3LPpVqRkURGPO6oJf24=.c9r";
    let mut reader = File::open(path)?;
    for chunk in mator.read_file_content(&mut reader)?.into_iter() {
        chunk?;
    }
*/

    /*

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


    let fuse = cryptomator_fuse_rs::CryptoFuse::new(mator);
    cryptomator_fuse_rs::mount2(
        fuse,
        PathBuf::from("/home/dar9586/Programmazione/Progetti/Rust/cryptomator-cli-rs/mount"),
        &[
            cryptomator_fuse_rs::MountOption::RW,
            cryptomator_fuse_rs::MountOption::AutoUnmount,
            cryptomator_fuse_rs::MountOption::AllowRoot,
        ],
    )?;


    Ok(())
}
