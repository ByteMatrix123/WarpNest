use crate::{
    retry::{OperationKind, RetryDiscipline, RetryError},
    state_store::{
        InstanceLifecycleState, PoolMembershipPreference, StateStore, StoredWarpInstance,
    },
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRegistrationRequest {
    pub group: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRegistration {
    pub registration_material: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedRegistration {
    pub instance_id: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    BudgetExceeded,
    Blocked(String),
    Unsupported(String),
    Transient(String),
    Store(String),
}

pub trait RegistrationClient {
    fn create_public_registration(
        &mut self,
        request: &PublicRegistrationRequest,
    ) -> Result<PublicRegistration, RegistrationError>;
}

pub struct RegistrationService<'a, C> {
    store: &'a StateStore,
    client: C,
    registration_budget: u16,
    retry: RetryDiscipline,
}

#[derive(Debug, Clone)]
pub struct MockRegistrationClient {
    outcome: Result<PublicRegistration, RegistrationError>,
}

impl Default for PublicRegistrationRequest {
    fn default() -> Self {
        Self {
            group: "default".to_string(),
            label: None,
        }
    }
}

impl<'a, C> RegistrationService<'a, C>
where
    C: RegistrationClient,
{
    pub fn new(store: &'a StateStore, client: C, registration_budget: u16) -> Self {
        Self {
            store,
            client,
            registration_budget,
            retry: RetryDiscipline::default(),
        }
    }

    pub fn create_public_registration(
        &mut self,
        request: PublicRegistrationRequest,
    ) -> Result<CreatedRegistration, RegistrationError> {
        if self.store.list_instances().map_err(store_error)?.len()
            >= self.registration_budget as usize
        {
            return Err(RegistrationError::BudgetExceeded);
        }

        match self.client.create_public_registration(&request) {
            Ok(registration) => {
                self.retry.record_success(OperationKind::Registration);
                let mut instance = StoredWarpInstance::new_mock(
                    request.group,
                    None,
                    PoolMembershipPreference::Standby,
                    InstanceLifecycleState::Registered,
                    registration.registration_material,
                );
                instance.label = request.label;
                self.store.upsert_instance(&instance).map_err(store_error)?;
                Ok(CreatedRegistration {
                    instance_id: instance.instance_id,
                    group: instance.group,
                })
            }
            Err(RegistrationError::Blocked(reason)) => {
                self.retry.record_failure(
                    OperationKind::Registration,
                    RetryError::Blocked(reason.clone()),
                );
                Err(RegistrationError::Blocked(reason))
            }
            Err(RegistrationError::Unsupported(reason)) => {
                self.retry.record_failure(
                    OperationKind::Registration,
                    RetryError::Unsupported(reason.clone()),
                );
                Err(RegistrationError::Unsupported(reason))
            }
            Err(RegistrationError::Transient(reason)) => {
                self.retry.record_failure(
                    OperationKind::Registration,
                    RetryError::Transient(reason.clone()),
                );
                Err(RegistrationError::Transient(reason))
            }
            Err(error) => Err(error),
        }
    }

    pub fn retry_state(&self) -> &RetryDiscipline {
        &self.retry
    }
}

impl MockRegistrationClient {
    pub fn succeeds(registration_material: impl Into<String>) -> Self {
        Self {
            outcome: Ok(PublicRegistration {
                registration_material: registration_material.into(),
            }),
        }
    }

    pub fn blocked(reason: impl Into<String>) -> Self {
        Self {
            outcome: Err(RegistrationError::Blocked(reason.into())),
        }
    }

    pub fn transient(reason: impl Into<String>) -> Self {
        Self {
            outcome: Err(RegistrationError::Transient(reason.into())),
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            outcome: Err(RegistrationError::Unsupported(reason.into())),
        }
    }
}

impl RegistrationClient for MockRegistrationClient {
    fn create_public_registration(
        &mut self,
        _request: &PublicRegistrationRequest,
    ) -> Result<PublicRegistration, RegistrationError> {
        self.outcome.clone()
    }
}

impl fmt::Debug for dyn RegistrationClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistrationClient")
    }
}

fn store_error(error: anyhow::Error) -> RegistrationError {
    RegistrationError::Store(error.to_string())
}
