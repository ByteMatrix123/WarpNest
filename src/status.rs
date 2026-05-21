use crate::{
    config::Config,
    state_store::{PoolMembershipPreference, StoredWarpInstance},
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PoolStatus {
    pub readiness: Readiness,
    pub target_serving_size: u16,
    pub actual_serving_size: u16,
    pub registration_budget: u16,
    pub recent_error: Option<String>,
    pub instances: Vec<InstanceStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Readiness {
    Ready,
    Degraded,
    Unavailable,
    Blocked,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InstanceStatus {
    pub instance_id: String,
    pub group: String,
    pub lifecycle_state: String,
    pub pool_membership: String,
    pub current_exit_ip: Option<String>,
    pub last_observed_exit_ip: Option<String>,
    pub active_connections: u32,
    pub recent_error: Option<String>,
}

impl PoolStatus {
    pub fn mock(config: &Config) -> Self {
        Self {
            readiness: Readiness::Degraded,
            target_serving_size: config.target_serving_size,
            actual_serving_size: 0,
            registration_budget: config.registration_budget,
            recent_error: Some("mock WARP Instance is not connected".to_string()),
            instances: vec![InstanceStatus {
                instance_id: "mock-instance-1".to_string(),
                group: "default".to_string(),
                lifecycle_state: "mock".to_string(),
                pool_membership: "standby".to_string(),
                current_exit_ip: None,
                last_observed_exit_ip: None,
                active_connections: 0,
                recent_error: Some("mock WARP Instance is not connected".to_string()),
            }],
        }
    }

    pub fn from_restored_instances(
        target_serving_size: u16,
        registration_budget: u16,
        instances: Vec<StoredWarpInstance>,
    ) -> Self {
        let actual_serving_size = instances
            .iter()
            .filter(|instance| {
                instance.enabled
                    && instance.pool_membership_preference == PoolMembershipPreference::Serving
            })
            .count() as u16;

        let readiness = match actual_serving_size {
            0 => Readiness::Unavailable,
            count if count < target_serving_size => Readiness::Degraded,
            _ => Readiness::Ready,
        };

        Self {
            readiness,
            target_serving_size,
            actual_serving_size,
            registration_budget,
            recent_error: None,
            instances: instances
                .into_iter()
                .map(|instance| InstanceStatus {
                    instance_id: instance.instance_id,
                    group: instance.group,
                    lifecycle_state: instance.lifecycle_state.as_str().to_string(),
                    pool_membership: instance.pool_membership_preference.as_str().to_string(),
                    current_exit_ip: None,
                    last_observed_exit_ip: instance.last_observed_exit_ip,
                    active_connections: 0,
                    recent_error: instance.recent_error,
                })
                .collect(),
        }
    }

    pub fn blocked(
        target_serving_size: u16,
        registration_budget: u16,
        recent_error: impl Into<String>,
    ) -> Self {
        Self {
            readiness: Readiness::Blocked,
            target_serving_size,
            actual_serving_size: 0,
            registration_budget,
            recent_error: Some(recent_error.into()),
            instances: Vec::new(),
        }
    }
}
