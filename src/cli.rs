use crate::{
    config::Config, management::ManagementServer, state_store::StateStore, status::PoolStatus,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "warpnest")]
#[command(about = "Manage a local Cloudflare WARP proxy pool")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long, default_value = "warpnest.toml")]
        config: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "warpnest.toml")]
        config: PathBuf,
        #[arg(long)]
        mock: bool,
    },
    Status {
        #[arg(long, default_value = "warpnest.toml")]
        config: PathBuf,
        #[arg(long)]
        mock: bool,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli).await
}

async fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { config } => {
            Config::write_default(&config)?;
            println!("wrote configuration to {}", config.display());
            Ok(())
        }
        Command::Status { config, mock } => {
            let config = Config::load(&config)?;
            let status = if mock {
                PoolStatus::mock(&config)
            } else {
                let store = StateStore::open(&config.state_store_path)?;
                PoolStatus::from_restored_instances(
                    config.target_serving_size,
                    config.registration_budget,
                    store.list_instances()?,
                )
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Command::Serve { config, mock } => {
            let config = Config::load(&config)?;
            let status = if mock {
                PoolStatus::mock(&config)
            } else {
                let store = StateStore::open(&config.state_store_path)?;
                PoolStatus::from_restored_instances(
                    config.target_serving_size,
                    config.registration_budget,
                    store.list_instances()?,
                )
            };
            let server = ManagementServer::bind(config.listeners.management_bind, status)
                .await
                .context("failed to bind Management API")?;
            eprintln!("Management API listening on {}", server.local_addr()?);
            server.serve().await
        }
    }
}
