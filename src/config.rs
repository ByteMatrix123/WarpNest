use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub target_serving_size: u16,
    pub registration_budget: u16,
    pub listeners: ListenerConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerConfig {
    pub management_bind: SocketAddr,
    pub socks5_bind: SocketAddr,
    pub http_bind: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    pub shared_secret: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_serving_size: 1,
            registration_budget: 3,
            listeners: ListenerConfig {
                management_bind: "127.0.0.1:0".parse().expect("valid default address"),
                socks5_bind: "127.0.0.1:1080".parse().expect("valid default address"),
                http_bind: "127.0.0.1:8080".parse().expect("valid default address"),
            },
            auth: AuthConfig {
                shared_secret: String::new(),
            },
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration file {}", path.display()))?;
        let config = toml::from_str::<Self>(&contents)
            .with_context(|| format!("failed to parse configuration file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn write_default(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create configuration directory {}",
                    parent.display()
                )
            })?;
        }

        let contents = toml::to_string_pretty(&Self::default())
            .context("failed to render default configuration")?;
        fs::write(path, contents)
            .with_context(|| format!("failed to write configuration file {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.target_serving_size == 0 {
            bail!("target_serving_size must be greater than zero");
        }

        if self.registration_budget < self.target_serving_size {
            bail!("registration_budget must be greater than or equal to target_serving_size");
        }

        if !is_local(self.listeners.management_bind) && self.auth.shared_secret.is_empty() {
            bail!("public Management API exposure requires a shared secret");
        }

        if (!is_local(self.listeners.socks5_bind) || !is_local(self.listeners.http_bind))
            && self.auth.shared_secret.is_empty()
        {
            bail!("public Proxy Endpoint exposure requires a shared secret");
        }

        Ok(())
    }
}

fn is_local(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}
