use std::collections::HashMap;
use std::path::PathBuf;
use std::str::from_utf8;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use crate::service::ServiceConfig;

#[derive(Debug, Parser)]
struct GenKeyArgs {
    #[clap(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ServeArgs {
    #[clap(long)]
    session_absolute_timeout_hours: Option<u64>,
    #[clap(long)]
    session_secret_key_file: Option<PathBuf>,
    #[clap(short, long)]
    address: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    GenKey(GenKeyArgs),
    Serve(ServeArgs),
}

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short, long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct Setting {
    session_absolute_timeout_hours: Option<u64>,
    session_secret_key_file: Option<PathBuf>,
    session_secret_key: Option<String>,
    address: Option<String>,
    users: Vec<User>,
}

struct ServeOptions {
    session_absolute_timeout_hours: u64,
    session_secret_key: Vec<u8>,
    address: String,
    users: HashMap<String, String>,
}

async fn read_key(path: PathBuf) -> Result<Vec<u8>> {
    let content = tokio::fs::read(path).await.context("could not read key file")?;
    let text = from_utf8(&content).context("could not parse key file")?;
    let text = text.trim_end();
    hex::decode(text).context("invalid hex string in key file")
}

impl ServeOptions {
    async fn new(args: ServeArgs, setting: Setting) -> Result<Self> {
        let session_absolute_timeout_hours = args
            .session_absolute_timeout_hours
            .or(setting.session_absolute_timeout_hours)
            .unwrap_or(720);
        let session_secret_key_file =
            args.session_secret_key_file.or(setting.session_secret_key_file);
        let session_secret_key = match (session_secret_key_file, setting.session_secret_key) {
            (Some(path), _) => read_key(path).await.context("could not parse key file")?,
            (None, Some(key)) => key.into_bytes(),
            _ => bail!("session secret key is required"),
        };
        let users: HashMap<String, String> =
            HashMap::from_iter(setting.users.into_iter().map(|u| (u.username, u.password)));
        let address = args.address.or(setting.address).unwrap_or("127.0.0.1:8080".into());

        Ok(Self { session_absolute_timeout_hours, session_secret_key, address, users })
    }

    async fn run(self) -> Result<()> {
        let config = ServiceConfig {
            session_absolute_timeout: Duration::from_secs(
                60 * 60 * self.session_absolute_timeout_hours,
            ),
            session_secret_key: self.session_secret_key,
            users: self.users,
        };
        let service = config.build();

        let address = self.address.parse().context("could not parse address")?;
        let server = axum::Server::bind(&address);
        server.serve(service.into_make_service()).await.context("error while running server")?;
        Ok(())
    }
}

struct GenKeyOptions {
    output: Option<PathBuf>,
}

impl GenKeyOptions {
    async fn new(args: GenKeyArgs, _setting: Setting) -> Result<Self> {
        Ok(Self { output: args.output })
    }

    async fn run(self) -> Result<()> {
        let key = ServiceConfig::generate_key();
        let key = hex::encode(key);
        match self.output {
            Some(path) => {
                let text = format!("{}\n", key);
                tokio::fs::write(path, text).await.context("could not write key into file")?;
            }
            None => {
                println!("{}", key);
            }
        }
        Ok(())
    }
}

pub async fn run(args: Args) -> Result<()> {
    let setting: Setting = match args.config {
        Some(path) => {
            let content =
                tokio::fs::read_to_string(path).await.context("could not read config file")?;
            toml::from_str(&content).context("could not parse config file")?
        }
        None => Default::default(),
    };

    match args.command {
        Commands::GenKey(a) => GenKeyOptions::new(a, setting).await?.run().await,
        Commands::Serve(a) => ServeOptions::new(a, setting).await?.run().await,
    }
}
