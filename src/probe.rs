use crate::state_store::StoredWarpInstance;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthObservation {
    Healthy,
    Unhealthy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeObservation {
    ObservedExitIp(String),
    EndpointFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Accepted(String),
    Uncertain,
    NoAcceptedObservation,
    HealthFailed(String),
}

pub fn apply_probe_cycle(
    instance: &mut StoredWarpInstance,
    health: HealthObservation,
    observations: Vec<ProbeObservation>,
) -> ProbeOutcome {
    match health {
        HealthObservation::Unhealthy(reason) => {
            instance.enabled = false;
            instance.recent_error = Some(reason.clone());
            return ProbeOutcome::HealthFailed(reason);
        }
        HealthObservation::Healthy => {
            instance.enabled = true;
        }
    }

    let observed_exit_ips = observations
        .iter()
        .filter_map(|observation| match observation {
            ProbeObservation::ObservedExitIp(exit_ip) => Some(exit_ip.clone()),
            ProbeObservation::EndpointFailed(_) => None,
        })
        .collect::<HashSet<_>>();

    match observed_exit_ips.len() {
        0 => {
            instance.recent_error = observations
                .iter()
                .find_map(|observation| match observation {
                    ProbeObservation::EndpointFailed(reason) => Some(reason.clone()),
                    ProbeObservation::ObservedExitIp(_) => None,
                });
            ProbeOutcome::NoAcceptedObservation
        }
        1 => {
            let exit_ip = observed_exit_ips.into_iter().next().expect("one exit ip");
            instance.last_observed_exit_ip = Some(exit_ip.clone());
            instance.recent_error = None;
            ProbeOutcome::Accepted(exit_ip)
        }
        _ => {
            instance.recent_error = Some("uncertain Exit Probe consensus".to_string());
            ProbeOutcome::Uncertain
        }
    }
}
