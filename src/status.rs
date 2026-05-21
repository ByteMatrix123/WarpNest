use crate::config::Config;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PoolStatus {
    pub readiness: Readiness,
    pub target_serving_size: u16,
    pub actual_serving_size: u16,
    pub registration_budget: u16,
    pub instances: Vec<InstanceStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Readiness {
    Ready,
    Degraded,
    Unavailable,
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
}
