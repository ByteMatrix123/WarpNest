use crate::{config::Config, management::ManagementServer, status::PoolStatus};
use anyhow::{Context, Result, bail};
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
            if !mock {
                bail!("status currently requires --mock until the State Store is implemented");
            }
            let status = PoolStatus::mock(&config);
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Command::Serve { config, mock } => {
            let config = Config::load(&config)?;
            if !mock {
                bail!("serve currently requires --mock until WARP Instances are implemented");
            }
            let status = PoolStatus::mock(&config);
            let server = ManagementServer::bind(config.listeners.management_bind, status)
                .await
                .context("failed to bind Management API")?;
            eprintln!("Management API listening on {}", server.local_addr()?);
            server.serve().await
        }
    }
}
