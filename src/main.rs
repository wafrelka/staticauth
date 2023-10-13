use std::collections::HashMap;
use std::path::PathBuf;
use std::str::from_utf8;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

use staticauth::app::AppConfig;

#[derive(Debug, Parser)]
struct GenerateArgs {
    #[clap(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct ServeArgs {
    #[clap(long, default_value = "720")]
    session_absolute_timeout_hours: u64,
    #[clap(long)]
    session_secret_key_file: Option<PathBuf>,
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    address: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Generate(GenerateArgs),
    Serve(ServeArgs),
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

async fn read_key(path: PathBuf) -> Result<Vec<u8>> {
    let content = tokio::fs::read(path).await?;
    let text = from_utf8(&content)?;
    let text = text.trim_end();
    Ok(hex::decode(text)?)
}

async fn serve(args: ServeArgs) -> Result<()> {
    let secret_key = match args.session_secret_key_file {
        Some(path) => read_key(path).await?,
        None => AppConfig::generate_key(),
    };
    let config = AppConfig {
        session_absolute_timeout: Duration::from_secs(
            60 * 60 * args.session_absolute_timeout_hours,
        ),
        session_secret_key: secret_key,
        users: HashMap::new(),
    };
    let app = config.build();

    axum::Server::bind(&args.address.parse()?).serve(app.into_make_service()).await.unwrap();
    Ok(())
}

async fn generate(args: GenerateArgs) -> Result<()> {
    let key = AppConfig::generate_key();
    let key = hex::encode(key);
    match args.output {
        Some(path) => {
            let text = format!("{}\n", key);
            tokio::fs::write(path, text).await?;
        }
        None => {
            println!("{}", key);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    match args.command {
        Commands::Generate(a) => generate(a).await,
        Commands::Serve(a) => serve(a).await,
    }
}
