use crate::{
    config::Config,
    management::ManagementServer,
    observed_warp_material::read_explicit_observed_warp_material_path,
    pool::{PoolConfig, ProxyPool},
    state_store::StateStore,
    status::PoolStatus,
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
    ImportObserved {
        #[arg(long, default_value = "warpnest.toml")]
        config: PathBuf,
        #[arg(long)]
        material: PathBuf,
        #[arg(long, default_value = "default")]
        group: String,
        #[arg(long)]
        label: Option<String>,
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
                restored_pool_status(&config, &store)?
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
                restored_pool_status(&config, &store)?
            };
            let server = ManagementServer::bind(config.listeners.management_bind, status)
                .await
                .context("failed to bind Management API")?;
            eprintln!("Management API listening on {}", server.local_addr()?);
            server.serve().await
        }
        Command::ImportObserved {
            config,
            material,
            group,
            label,
        } => {
            let config = Config::load(&config)?;
            let store = StateStore::open(&config.state_store_path)?;
            let observed = read_explicit_observed_warp_material_path(&material)?;
            let imported = observed.import_into_store(&store, group, label.clone())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "instance_id": imported.instance_id,
                    "group": imported.group,
                    "label": label,
                }))?
            );
            Ok(())
        }
    }
}

fn restored_pool_status(config: &Config, store: &StateStore) -> Result<PoolStatus> {
    let pool_config = PoolConfig::new(config.target_serving_size, config.registration_budget);
    let pool = ProxyPool::from_instances(pool_config, store.list_instances()?);
    Ok(pool.status())
}
