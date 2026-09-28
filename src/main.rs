use anyhow::Result;
use clap::Parser;

use staticauth::app::{Args, run};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    run(Args::parse()).await
}
