use crate::{
    config::Config,
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
pub struct PublicWarpRegistrationHarnessPaths {
    pub config_path: PathBuf,
    pub state_store_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicWarpRegistrationHarnessStatus {
    Skipped,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicWarpRegistrationFailureClass {
    Blocked,
    Unsupported,
    Transient,
    BudgetExceeded,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicWarpRegistrationHarnessEvidence {
    pub instance_id: String,
    pub group: String,
    pub adapter_kind: String,
    #[serde(rename = "adapter_version")]
    pub adapter_config_version: u16,
    pub persisted_instance_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicWarpRegistrationHarnessFailure {
    pub class: PublicWarpRegistrationFailureClass,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicWarpRegistrationHarnessReport {
    pub status: PublicWarpRegistrationHarnessStatus,
    pub config_path: String,
    pub state_store_path: String,
    pub registration_budget: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<PublicWarpRegistrationHarnessEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<PublicWarpRegistrationHarnessFailure>,
}

#[derive(Debug)]
pub struct PublicWarpRegistrationHarness<C> {
    client: C,
    paths: PublicWarpRegistrationHarnessPaths,
    registration_budget: u16,
}

impl<C> PublicWarpRegistrationHarness<C> {
    pub fn new(client: C, paths: PublicWarpRegistrationHarnessPaths) -> Self {
        Self {
            client,
            paths,
            registration_budget: 1,
        }
    }

    pub fn with_budget(mut self, registration_budget: u16) -> Self {
        self.registration_budget = registration_budget;
        self
    }
}

impl<C> PublicWarpRegistrationHarness<C>
where
    C: RegistrationClient,
{
    pub fn run(self, gate: PublicWarpIntegrationGate) -> PublicWarpRegistrationHarnessReport {
        let config_path = self.paths.config_path.display().to_string();
        let state_store_path = self.paths.state_store_path.display().to_string();
        let registration_budget = self.registration_budget;

        if !gate.is_enabled() {
            return harness_report(
                PublicWarpRegistrationHarnessStatus::Skipped,
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

        let store = match self.prepare_isolated_state_store() {
            Ok(store) => store,
            Err(error) => {
                return harness_report(
                    PublicWarpRegistrationHarnessStatus::Failed,
                    &config_path,
                    &state_store_path,
                    registration_budget,
                    None,
                    None,
                    Some(PublicWarpRegistrationHarnessFailure {
                        class: PublicWarpRegistrationFailureClass::Store,
                        message: redact_sensitive(&error.to_string()),
                    }),
                );
            }
        };
        let mut service = RegistrationService::new(&store, self.client, self.registration_budget);
        let request = PublicRegistrationRequest {
            group: "integration".to_string(),
            label: Some("opt-in direct public WARP registration".to_string()),
        };

        match service.create_public_registration(request) {
            Ok(created) => match store.list_instances() {
                Ok(instances) => {
                    let Some(instance) = instances
                        .iter()
                        .find(|instance| instance.instance_id == created.instance_id)
                    else {
                        return harness_report(
                            PublicWarpRegistrationHarnessStatus::Failed,
                            &config_path,
                            &state_store_path,
                            registration_budget,
                            None,
                            None,
                            Some(PublicWarpRegistrationHarnessFailure {
                                class: PublicWarpRegistrationFailureClass::Store,
                                message: "created registration was not persisted".to_string(),
                            }),
                        );
                    };

                    harness_report(
                        PublicWarpRegistrationHarnessStatus::Succeeded,
                        &config_path,
                        &state_store_path,
                        registration_budget,
                        None,
                        Some(PublicWarpRegistrationHarnessEvidence {
                            instance_id: created.instance_id,
                            group: created.group,
                            adapter_kind: instance.adapter_config.kind.clone(),
                            adapter_config_version: instance.adapter_config.version,
                            persisted_instance_count: instances.len(),
                        }),
                        None,
                    )
                }
                Err(error) => harness_report(
                    PublicWarpRegistrationHarnessStatus::Failed,
                    &config_path,
                    &state_store_path,
                    registration_budget,
                    None,
                    None,
                    Some(PublicWarpRegistrationHarnessFailure {
                        class: PublicWarpRegistrationFailureClass::Store,
                        message: redact_sensitive(&error.to_string()),
                    }),
                ),
            },
            Err(error) => harness_report(
                PublicWarpRegistrationHarnessStatus::Failed,
                &config_path,
                &state_store_path,
                registration_budget,
                None,
                None,
                Some(classified_failure(error)),
            ),
        }
    }

    fn prepare_isolated_state_store(&self) -> anyhow::Result<StateStore> {
        let config = Config {
            state_store_path: self.paths.state_store_path.display().to_string(),
            registration_budget: self.registration_budget,
            ..Config::default()
        };

        if let Some(parent) = self.paths.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let rendered = toml::to_string_pretty(&config)?;
        std::fs::write(&self.paths.config_path, rendered)?;
        StateStore::open(&self.paths.state_store_path)
    }
}

fn harness_report(
    status: PublicWarpRegistrationHarnessStatus,
    config_path: &str,
    state_store_path: &str,
    registration_budget: u16,
    skip_reason: Option<String>,
    evidence: Option<PublicWarpRegistrationHarnessEvidence>,
    failure: Option<PublicWarpRegistrationHarnessFailure>,
) -> PublicWarpRegistrationHarnessReport {
    PublicWarpRegistrationHarnessReport {
        status,
        config_path: config_path.to_string(),
        state_store_path: state_store_path.to_string(),
        registration_budget,
        skip_reason,
        evidence,
        failure,
    }
}

fn classified_failure(error: RegistrationError) -> PublicWarpRegistrationHarnessFailure {
    match error {
        RegistrationError::BudgetExceeded => PublicWarpRegistrationHarnessFailure {
            class: PublicWarpRegistrationFailureClass::BudgetExceeded,
            message: "registration budget exceeded".to_string(),
        },
        RegistrationError::Blocked(reason) => PublicWarpRegistrationHarnessFailure {
            class: PublicWarpRegistrationFailureClass::Blocked,
            message: redact_sensitive(&reason),
        },
        RegistrationError::Unsupported(reason) => PublicWarpRegistrationHarnessFailure {
            class: PublicWarpRegistrationFailureClass::Unsupported,
            message: redact_sensitive(&reason),
        },
        RegistrationError::Transient(reason) => PublicWarpRegistrationHarnessFailure {
            class: PublicWarpRegistrationFailureClass::Transient,
            message: redact_sensitive(&reason),
        },
        RegistrationError::Store(reason) => PublicWarpRegistrationHarnessFailure {
            class: PublicWarpRegistrationFailureClass::Store,
            message: redact_sensitive(&reason),
        },
    }
}
