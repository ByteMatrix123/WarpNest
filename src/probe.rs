use crate::{
    data_plane::{DataPlaneTarget, UdpDatagram, UserSpaceDataPlane},
    security::redact_sensitive,
    state_store::StoredWarpInstance,
};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProbeRequest {
    pub instance_id: String,
    pub probe_host: String,
    pub probe_port: u16,
    pub health_host: String,
    pub health_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProbeCycle {
    pub health: HealthObservation,
    pub observations: Vec<ProbeObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRuntimeProbeTransport {
    health: HealthObservation,
    observations: Vec<ProbeObservation>,
}

impl RuntimeProbeRequest {
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            probe_host: "exit-probe.warpnest.local".to_string(),
            probe_port: 443,
            health_host: "health-check.warpnest.local".to_string(),
            health_port: 443,
        }
    }
}

impl FakeRuntimeProbeTransport {
    pub fn healthy_with_exit_ip(exit_ip: impl Into<String>) -> Self {
        Self {
            health: HealthObservation::Healthy,
            observations: vec![ProbeObservation::ObservedExitIp(exit_ip.into())],
        }
    }

    pub fn unhealthy(reason: impl Into<String>) -> Self {
        Self {
            health: HealthObservation::Unhealthy(redact_sensitive(&reason.into())),
            observations: Vec::new(),
        }
    }

    pub fn endpoint_failed(reason: impl Into<String>) -> Self {
        Self {
            health: HealthObservation::Healthy,
            observations: vec![ProbeObservation::EndpointFailed(redact_sensitive(
                &reason.into(),
            ))],
        }
    }

    pub async fn run(
        &self,
        data_plane: &(dyn UserSpaceDataPlane + Send + Sync),
        request: RuntimeProbeRequest,
    ) -> RuntimeProbeCycle {
        let health = match data_plane
            .connect_tcp(DataPlaneTarget {
                instance_id: request.instance_id.clone(),
                host: request.health_host,
                port: request.health_port,
            })
            .await
        {
            Ok(_) => self.health.clone(),
            Err(error) => HealthObservation::Unhealthy(redact_sensitive(&error.to_string())),
        };

        let observations = match health {
            HealthObservation::Healthy => {
                match data_plane.open_udp_session(request.instance_id).await {
                    Ok(session) => match session
                        .send_datagram(UdpDatagram {
                            target_host: request.probe_host,
                            target_port: request.probe_port,
                            payload: b"warpnest-exit-probe".to_vec(),
                        })
                        .await
                    {
                        Ok(_) => self.observations.clone(),
                        Err(error) => vec![ProbeObservation::EndpointFailed(redact_sensitive(
                            &error.to_string(),
                        ))],
                    },
                    Err(error) => vec![ProbeObservation::EndpointFailed(redact_sensitive(
                        &error.to_string(),
                    ))],
                }
            }
            HealthObservation::Unhealthy(_) => Vec::new(),
        };

        RuntimeProbeCycle {
            health,
            observations,
        }
    }
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
