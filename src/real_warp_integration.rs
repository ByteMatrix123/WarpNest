use crate::{
    config::Config,
    data_plane::{BoringTunDataPlane, DataPlaneInstanceConfig},
    direct_public_warp_registration::PublicWarpIntegrationGate,
    security::redact_sensitive,
    state_store::StateStore,
    warp_lifecycle::{
        PublicRegistrationRequest, RegistrationClient, RegistrationError, RegistrationService,
    },
};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealWarpFullPathHarnessPaths {
    pub config_path: PathBuf,
    pub state_store_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RealWarpFullPathStatus {
    Skipped,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RealWarpFullPathFailureClass {
    Registration,
    Store,
    RuntimeUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealWarpFullPathEvidence {
    pub persisted_instance_count: usize,
    pub prepared_runtime_count: usize,
    pub isolated_state_store: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealWarpFullPathFailure {
    pub class: RealWarpFullPathFailureClass,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealWarpFullPathReport {
    pub status: RealWarpFullPathStatus,
    pub config_path: String,
    pub state_store_path: String,
    pub registration_budget: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<RealWarpFullPathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<RealWarpFullPathFailure>,
}

#[derive(Debug)]
pub struct RealWarpFullPathHarness<C> {
    client: C,
    paths: RealWarpFullPathHarnessPaths,
    registration_budget: u16,
    target_serving_size: u16,
}

impl<C> RealWarpFullPathHarness<C> {
    pub fn new(client: C, paths: RealWarpFullPathHarnessPaths) -> Self {
        Self {
            client,
            paths,
            registration_budget: 2,
            target_serving_size: 2,
        }
    }

    pub fn with_budget(mut self, registration_budget: u16) -> Self {
        self.registration_budget = registration_budget;
        self
    }

    pub fn with_target_serving_size(mut self, target_serving_size: u16) -> Self {
        self.target_serving_size = target_serving_size;
        self
    }
}

impl<C> RealWarpFullPathHarness<C>
where
    C: RegistrationClient,
{
    pub fn run(mut self, gate: PublicWarpIntegrationGate) -> RealWarpFullPathReport {
        let config_path = self.paths.config_path.display().to_string();
        let state_store_path = self.paths.state_store_path.display().to_string();
        let registration_budget = self.registration_budget;

        if !gate.is_enabled() {
            return full_path_report(
                RealWarpFullPathStatus::Skipped,
                &config_path,
                &state_store_path,
                registration_budget,
                Some(
                    gate.skip_reason()
                        .unwrap_or("integration gate disabled")
                        .to_string(),
                ),
                None,
                None,
            );
        }

        match self.run_enabled() {
            Ok(evidence) => full_path_report(
                RealWarpFullPathStatus::Failed,
                &config_path,
                &state_store_path,
                registration_budget,
                None,
                Some(evidence),
                Some(RealWarpFullPathFailure {
                    class: RealWarpFullPathFailureClass::RuntimeUnsupported,
                    message: "full real WARP TCP/UDP/DNS proof is not yet implemented: the current runtime can prepare persisted Public WARP adapter configs, but the project still lacks a live smoltcp TCP/UDP socket runtime backed by BoringTun UDP transport"
                        .to_string(),
                }),
            ),
            Err(failure) => full_path_report(
                RealWarpFullPathStatus::Failed,
                &config_path,
                &state_store_path,
                registration_budget,
                None,
                None,
                Some(failure),
            ),
        }
    }

    fn run_enabled(
        &mut self,
    ) -> std::result::Result<RealWarpFullPathEvidence, RealWarpFullPathFailure> {
        self.prepare_isolated_config()
            .map_err(|error| failure(RealWarpFullPathFailureClass::Store, error))?;
        let store = StateStore::open(&self.paths.state_store_path)
            .map_err(|error| failure(RealWarpFullPathFailureClass::Store, error))?;

        self.ensure_registrations(&store)
            .map_err(registration_failure)?;
        let instances = store
            .list_instances()
            .map_err(|error| failure(RealWarpFullPathFailureClass::Store, error))?;
        let data_plane = BoringTunDataPlane::try_with_instances(instances.iter().map(|instance| {
            DataPlaneInstanceConfig {
                instance_id: instance.instance_id.clone(),
                adapter_config: instance.adapter_config.clone(),
            }
        }))
        .map_err(|error| failure(RealWarpFullPathFailureClass::RuntimeUnsupported, error))?;

        Ok(RealWarpFullPathEvidence {
            persisted_instance_count: instances.len(),
            prepared_runtime_count: data_plane.instance_count(),
            isolated_state_store: self.paths.state_store_path.exists()
                && !PathBuf::from("warpnest.sqlite").exists(),
        })
    }

    fn prepare_isolated_config(&self) -> anyhow::Result<()> {
        let config = Config {
            state_store_path: self.paths.state_store_path.display().to_string(),
            registration_budget: self.registration_budget,
            target_serving_size: self.target_serving_size,
            ..Config::default()
        };

        if let Some(parent) = self.paths.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.paths.config_path, toml::to_string_pretty(&config)?)?;
        Ok(())
    }

    fn ensure_registrations(&mut self, store: &StateStore) -> Result<(), RegistrationError> {
        let mut service =
            RegistrationService::new(store, &mut self.client, self.registration_budget);
        while store
            .list_instances()
            .map_err(|error| RegistrationError::Store(error.to_string()))?
            .len()
            < usize::from(self.target_serving_size)
        {
            service.create_public_registration(PublicRegistrationRequest {
                group: "integration".to_string(),
                label: Some("opt-in full real WARP path proof".to_string()),
            })?;
        }
        Ok(())
    }
}

fn full_path_report(
    status: RealWarpFullPathStatus,
    config_path: &str,
    state_store_path: &str,
    registration_budget: u16,
    skip_reason: Option<String>,
    evidence: Option<RealWarpFullPathEvidence>,
    failure: Option<RealWarpFullPathFailure>,
) -> RealWarpFullPathReport {
    RealWarpFullPathReport {
        status,
        config_path: config_path.to_string(),
        state_store_path: state_store_path.to_string(),
        registration_budget,
        skip_reason,
        evidence,
        failure,
    }
}

fn registration_failure(error: RegistrationError) -> RealWarpFullPathFailure {
    let message = match error {
        RegistrationError::BudgetExceeded => "registration budget exceeded".to_string(),
        RegistrationError::Blocked(reason)
        | RegistrationError::Unsupported(reason)
        | RegistrationError::Transient(reason)
        | RegistrationError::Store(reason) => reason,
    };
    RealWarpFullPathFailure {
        class: RealWarpFullPathFailureClass::Registration,
        message: redact_sensitive(&message),
    }
}

fn failure(
    class: RealWarpFullPathFailureClass,
    error: impl std::fmt::Display,
) -> RealWarpFullPathFailure {
    RealWarpFullPathFailure {
        class,
        message: redact_sensitive(&error.to_string()),
    }
}
