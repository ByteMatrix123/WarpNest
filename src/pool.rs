use crate::{
    state_store::{PoolMembershipPreference, StoredWarpInstance},
    status::{InstanceStatus, PoolStatus, Readiness},
};
use std::{cell::RefCell, collections::HashSet, rc::Rc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    pub target_serving_size: u16,
    pub registration_budget: u16,
    pub standby_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceSelector {
    Id(String),
    ExitIp(String),
    Group(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    NoServingInstance,
    NoServingInstanceInGroup,
    InstanceNotFound,
}

#[derive(Debug)]
pub struct ProxyPool {
    config: PoolConfig,
    instances: Vec<Rc<RefCell<PoolInstance>>>,
}

#[derive(Debug, Clone)]
struct PoolInstance {
    instance: StoredWarpInstance,
    pool_membership: PoolMembershipPreference,
    active_connections: u32,
    sequence: usize,
}

#[derive(Debug)]
pub struct ConnectionLease {
    instance: Rc<RefCell<PoolInstance>>,
}

impl PoolConfig {
    pub fn new(target_serving_size: u16, registration_budget: u16) -> Self {
        Self {
            target_serving_size,
            registration_budget,
            standby_fallback: false,
        }
    }

    pub fn with_standby_fallback(mut self, standby_fallback: bool) -> Self {
        self.standby_fallback = standby_fallback;
        self
    }
}

impl ProxyPool {
    pub fn from_instances(config: PoolConfig, instances: Vec<StoredWarpInstance>) -> Self {
        let mut seen_exit_ips = HashSet::new();
        let mut serving_count = 0_u16;

        let instances = instances
            .into_iter()
            .enumerate()
            .map(|(sequence, instance)| {
                let pool_membership = if !instance.enabled {
                    PoolMembershipPreference::Failed
                } else {
                    match instance.last_observed_exit_ip.as_ref() {
                        Some(exit_ip) => {
                            if serving_count < config.target_serving_size
                                && seen_exit_ips.insert(exit_ip.clone())
                            {
                                serving_count += 1;
                                PoolMembershipPreference::Serving
                            } else {
                                PoolMembershipPreference::Standby
                            }
                        }
                        None => PoolMembershipPreference::Failed,
                    }
                };

                Rc::new(RefCell::new(PoolInstance {
                    instance,
                    pool_membership,
                    active_connections: 0,
                    sequence,
                }))
            })
            .collect();

        Self { config, instances }
    }

    pub fn status(&self) -> PoolStatus {
        let actual_serving_size = self
            .instances
            .iter()
            .filter(|instance| {
                instance.borrow().pool_membership == PoolMembershipPreference::Serving
            })
            .count() as u16;

        let readiness = match actual_serving_size {
            0 => Readiness::Unavailable,
            count if count < self.config.target_serving_size => Readiness::Degraded,
            _ => Readiness::Ready,
        };

        PoolStatus {
            readiness,
            target_serving_size: self.config.target_serving_size,
            actual_serving_size,
            registration_budget: self.config.registration_budget,
            instances: self
                .instances
                .iter()
                .map(|instance| {
                    let instance = instance.borrow();
                    InstanceStatus {
                        instance_id: instance.instance.instance_id.clone(),
                        group: instance.instance.group.clone(),
                        lifecycle_state: instance.instance.lifecycle_state.as_str().to_string(),
                        pool_membership: instance.pool_membership.as_str().to_string(),
                        current_exit_ip: instance.instance.last_observed_exit_ip.clone(),
                        last_observed_exit_ip: instance.instance.last_observed_exit_ip.clone(),
                        active_connections: instance.active_connections,
                        recent_error: instance.instance.recent_error.clone(),
                    }
                })
                .collect(),
        }
    }

    pub fn schedule_auto(&mut self) -> Result<ConnectionLease, ScheduleError> {
        let candidate = self.best_candidate(|instance| {
            instance.pool_membership == PoolMembershipPreference::Serving
        });
        candidate
            .map(ConnectionLease::new)
            .ok_or(ScheduleError::NoServingInstance)
    }

    pub fn select_instance(
        &mut self,
        selector: InstanceSelector,
    ) -> Result<ConnectionLease, ScheduleError> {
        match selector {
            InstanceSelector::Id(id) => self
                .instances
                .iter()
                .find(|instance| {
                    let instance = instance.borrow();
                    instance.instance.instance_id == id
                        && matches!(
                            instance.pool_membership,
                            PoolMembershipPreference::Serving | PoolMembershipPreference::Standby
                        )
                })
                .cloned()
                .map(ConnectionLease::new)
                .ok_or(ScheduleError::InstanceNotFound),
            InstanceSelector::ExitIp(exit_ip) => self
                .best_candidate(|instance| {
                    matches!(
                        instance.pool_membership,
                        PoolMembershipPreference::Serving | PoolMembershipPreference::Standby
                    ) && instance.instance.last_observed_exit_ip.as_deref()
                        == Some(exit_ip.as_str())
                })
                .map(ConnectionLease::new)
                .ok_or(ScheduleError::InstanceNotFound),
            InstanceSelector::Group(group) => {
                let serving = self.best_candidate(|instance| {
                    instance.instance.group == group
                        && instance.pool_membership == PoolMembershipPreference::Serving
                });
                if let Some(serving) = serving {
                    return Ok(ConnectionLease::new(serving));
                }

                if self.config.standby_fallback {
                    return self
                        .best_candidate(|instance| {
                            instance.instance.group == group
                                && instance.pool_membership == PoolMembershipPreference::Standby
                        })
                        .map(ConnectionLease::new)
                        .ok_or(ScheduleError::NoServingInstanceInGroup);
                }

                Err(ScheduleError::NoServingInstanceInGroup)
            }
        }
    }

    fn best_candidate(
        &self,
        predicate: impl Fn(&PoolInstance) -> bool,
    ) -> Option<Rc<RefCell<PoolInstance>>> {
        self.instances
            .iter()
            .filter(|instance| predicate(&instance.borrow()))
            .min_by_key(|instance| {
                let instance = instance.borrow();
                (instance.active_connections, instance.sequence)
            })
            .cloned()
    }
}

impl ConnectionLease {
    fn new(instance: Rc<RefCell<PoolInstance>>) -> Self {
        instance.borrow_mut().active_connections += 1;
        Self { instance }
    }

    pub fn instance_id(&self) -> String {
        self.instance.borrow().instance.instance_id.clone()
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let mut instance = self.instance.borrow_mut();
        instance.active_connections = instance.active_connections.saturating_sub(1);
    }
}
