use anyhow::Result;
use clap::Parser;

use staticauth::app::{run, Args};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    run(Args::parse()).await
}
