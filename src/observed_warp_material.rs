use crate::{
    public_warp_adapter::PublicWarpAdapterConfig,
    state_store::{
        InstanceLifecycleState, PoolMembershipPreference, StateStore, StoredWarpInstance,
    },
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt, fs, path::Path};

#[derive(Clone, PartialEq, Eq)]
pub struct ObservedWarpMaterial {
    raw_material: String,
    adapter_config: PublicWarpAdapterConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedObservedWarpMaterial {
    pub instance_id: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedWarpMaterialError {
    UnsupportedShape(String),
    ReadFailed(String),
    Store(String),
}

#[derive(Debug, Deserialize, Serialize)]
struct ObservedWireGuardMaterial {
    private_key: String,
    interface_addresses: Vec<String>,
    peer_public_key: String,
    peer_endpoint: String,
    allowed_ips: Vec<String>,
    dns_servers: Vec<String>,
    #[serde(default)]
    device_id: Option<String>,
}

impl ObservedWarpMaterial {
    pub fn from_json(raw_material: impl Into<String>) -> Result<Self, ObservedWarpMaterialError> {
        let raw_material = raw_material.into();
        let parsed: Value = serde_json::from_str(&raw_material).map_err(|error| {
            ObservedWarpMaterialError::UnsupportedShape(format!(
                "observed Public WARP material is not valid JSON: {error}"
            ))
        })?;

        let wireguard = parsed
            .get("wireguard")
            .cloned()
            .ok_or_else(|| {
                ObservedWarpMaterialError::UnsupportedShape(
                    "observed Public WARP material must contain a wireguard object".to_string(),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<ObservedWireGuardMaterial>(value).map_err(|error| {
                    ObservedWarpMaterialError::UnsupportedShape(format!(
                        "observed Public WARP wireguard material has an unsupported shape: {error}"
                    ))
                })
            })?;

        wireguard.validate()?;

        let normalized = serde_json::to_value(&wireguard).map_err(|error| {
            ObservedWarpMaterialError::UnsupportedShape(format!(
                "failed to normalize observed Public WARP material: {error}"
            ))
        })?;
        let adapter_config = PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(normalized)
            .map_err(|error| {
                ObservedWarpMaterialError::UnsupportedShape(format!(
                    "failed to create normalized Public WARP Adapter config: {error}"
                ))
            })?;

        Ok(Self {
            raw_material,
            adapter_config,
        })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ObservedWarpMaterialError> {
        let path = path.as_ref();
        let raw_material = fs::read_to_string(path).map_err(|error| {
            ObservedWarpMaterialError::ReadFailed(format!(
                "failed to read observed Public WARP material {}: {error}",
                path.display()
            ))
        })?;
        Self::from_json(raw_material)
    }

    pub fn import_into_store(
        &self,
        store: &StateStore,
        group: impl Into<String>,
        label: Option<String>,
    ) -> Result<ImportedObservedWarpMaterial, ObservedWarpMaterialError> {
        let mut instance = StoredWarpInstance::new_with_adapter(
            group,
            None,
            PoolMembershipPreference::Standby,
            InstanceLifecycleState::Registered,
            self.raw_material.clone(),
            self.adapter_config.clone(),
        );
        instance.label = label;
        store.upsert_instance(&instance).map_err(|error| {
            ObservedWarpMaterialError::Store(format!(
                "failed to persist observed Public WARP material: {error}"
            ))
        })?;

        Ok(ImportedObservedWarpMaterial {
            instance_id: instance.instance_id,
            group: instance.group,
        })
    }

    pub fn raw_material(&self) -> &str {
        &self.raw_material
    }

    pub fn adapter_config(&self) -> &PublicWarpAdapterConfig {
        &self.adapter_config
    }
}

impl ObservedWireGuardMaterial {
    fn validate(&self) -> Result<(), ObservedWarpMaterialError> {
        reject_empty("private_key", &self.private_key)?;
        reject_empty("peer_public_key", &self.peer_public_key)?;
        reject_empty("peer_endpoint", &self.peer_endpoint)?;
        reject_empty_list("interface_addresses", &self.interface_addresses)?;
        reject_empty_list("allowed_ips", &self.allowed_ips)?;
        reject_empty_list("dns_servers", &self.dns_servers)?;
        Ok(())
    }
}

impl fmt::Display for ObservedWarpMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedShape(reason) => {
                write!(formatter, "unsupported material shape: {reason}")
            }
            Self::ReadFailed(reason) => write!(formatter, "{reason}"),
            Self::Store(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl Error for ObservedWarpMaterialError {}

impl fmt::Debug for ObservedWarpMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedWarpMaterial")
            .field("raw_material", &"[redacted]")
            .field("adapter_config", &self.adapter_config)
            .finish()
    }
}

fn reject_empty(field: &str, value: &str) -> Result<(), ObservedWarpMaterialError> {
    if value.trim().is_empty() {
        return Err(ObservedWarpMaterialError::UnsupportedShape(format!(
            "wireguard.{field} must not be empty"
        )));
    }
    Ok(())
}

fn reject_empty_list(field: &str, value: &[String]) -> Result<(), ObservedWarpMaterialError> {
    if value.is_empty() || value.iter().any(|item| item.trim().is_empty()) {
        return Err(ObservedWarpMaterialError::UnsupportedShape(format!(
            "wireguard.{field} must contain at least one non-empty value"
        )));
    }
    Ok(())
}

pub fn read_explicit_observed_warp_material_path(
    path: impl AsRef<Path>,
) -> Result<ObservedWarpMaterial> {
    ObservedWarpMaterial::from_path(path).context("failed to import observed Public WARP material")
}
