use anyhow::{Context, Result};
use serde_json::Value;
use std::{error::Error, fmt};

pub const MOCK_ADAPTER_KIND: &str = "mock";
pub const PUBLIC_WARP_WIREGUARD_OBSERVED_V1: &str = "public_warp_wireguard_observed_v1";

#[derive(Clone, PartialEq, Eq)]
pub struct PublicWarpAdapterConfig {
    pub kind: String,
    pub version: u16,
    config_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicWarpAdapterError {
    UnsupportedAdapter {
        kind: String,
        version: u16,
    },
    UnsupportedAdapterConfig {
        kind: String,
        version: u16,
        reason: String,
    },
    Blocked(String),
}

impl PublicWarpAdapterConfig {
    pub fn mock() -> Self {
        Self {
            kind: MOCK_ADAPTER_KIND.to_string(),
            version: 1,
            config_json: "{}".to_string(),
        }
    }

    pub fn public_warp_wireguard_observed_v1(config: Value) -> Result<Self> {
        Self::new(PUBLIC_WARP_WIREGUARD_OBSERVED_V1, 1, config)
    }

    pub fn new(kind: impl Into<String>, version: u16, config: Value) -> Result<Self> {
        let config_json =
            serde_json::to_string(&config).context("failed to encode normalized adapter config")?;
        Self::from_storage(kind, version, config_json)
    }

    pub fn from_storage(
        kind: impl Into<String>,
        version: u16,
        config_json: impl Into<String>,
    ) -> Result<Self> {
        let config_json = config_json.into();
        serde_json::from_str::<Value>(&config_json)
            .context("failed to parse normalized adapter config")?;
        Ok(Self {
            kind: kind.into(),
            version,
            config_json,
        })
    }

    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    pub fn redacted_config(&self) -> &'static str {
        "[redacted]"
    }

    pub fn ensure_supported(&self) -> Result<(), PublicWarpAdapterError> {
        match (self.kind.as_str(), self.version) {
            (MOCK_ADAPTER_KIND, 1) | (PUBLIC_WARP_WIREGUARD_OBSERVED_V1, 1) => Ok(()),
            _ => Err(PublicWarpAdapterError::UnsupportedAdapter {
                kind: self.kind.clone(),
                version: self.version,
            }),
        }
    }
}

impl fmt::Debug for PublicWarpAdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicWarpAdapterConfig")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("config", &self.redacted_config())
            .finish()
    }
}

impl fmt::Display for PublicWarpAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAdapter { kind, version } => {
                write!(
                    formatter,
                    "unsupported Public WARP Adapter {kind} v{version}"
                )
            }
            Self::UnsupportedAdapterConfig {
                kind,
                version,
                reason,
            } => {
                write!(
                    formatter,
                    "unsupported Public WARP Adapter {kind} v{version}: {reason}"
                )
            }
            Self::Blocked(reason) => write!(formatter, "Public WARP Adapter blocked: {reason}"),
        }
    }
}

impl Error for PublicWarpAdapterError {}
