#![allow(dead_code, unused_variables, unused_imports)]

use anyhow::Result;
use std::path::PathBuf;
use tracing::instrument;
use tracing_subscriber::fmt::format::FmtSpan;


use clap::{ArgGroup, Parser};
use log::error;
use std::fs;

#[derive(Debug, Parser)]
#[command(author, version, about)]
#[command(group(
    ArgGroup::new("password_source")
        .args(["password", "password_file", "password_stdin"])
        .multiple(false) // only one source allowed
        .required(true)
))]
struct Cli {
    #[arg(short, long)]
    vault_root: PathBuf,

    #[arg(short, long)]
    mount_point: PathBuf,

    #[arg(long)]
    password: Option<String>,

    #[arg(long)]
    password_file: Option<PathBuf>,

    #[arg(long)]
    password_stdin: bool,

    #[arg(long)]
    read_write: bool,

    #[arg(long)]
    create: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER)
        .with_env_filter("info")
        .init();
    let cli = Cli::parse();

    let password = get_password(&cli)?;

    if cli.create {
        if fs::exists(&cli.vault_root)? {
            error!("vault_root already exists");
            return Ok(());
        }
        cryptomator_rs_crypto::create_vault(&cli.vault_root, password.as_bytes())?;
    }

    let mator = cryptomator_rs_crypto::CryptomatorOpen {
        vault_path: cli.vault_root,
        password,
    }.open()?;

    let fuse = cryptomator_rs_fuse::CryptoFuse::new(mator);
    cryptomator_rs_fuse::mount2(
        fuse,
        cli.mount_point,
        &[
            if cli.read_write { cryptomator_rs_fuse::MountOption::RW } else { cryptomator_rs_fuse::MountOption::RO },
            cryptomator_rs_fuse::MountOption::AutoUnmount,
            cryptomator_rs_fuse::MountOption::AllowRoot,
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
