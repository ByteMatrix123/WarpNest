use warpnest::{
    pool::{PoolConfig, ProxyPool},
    probe::{HealthObservation, ProbeObservation, ProbeOutcome, apply_probe_cycle},
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
    status::Readiness,
};

#[test]
fn accepted_probe_consensus_updates_last_observed_exit_ip() {
    let mut instance = instance("a", Some("198.51.100.1"));

    let outcome = apply_probe_cycle(
        &mut instance,
        HealthObservation::Healthy,
        vec![
            ProbeObservation::ObservedExitIp("203.0.113.10".to_string()),
            ProbeObservation::ObservedExitIp("203.0.113.10".to_string()),
        ],
    );

    assert_eq!(outcome, ProbeOutcome::Accepted("203.0.113.10".to_string()));
    assert_eq!(
        instance.last_observed_exit_ip.as_deref(),
        Some("203.0.113.10")
    );
    assert!(instance.enabled);
}

#[test]
fn conflicting_probe_consensus_does_not_replace_last_observed_exit_ip() {
    let mut instance = instance("a", Some("198.51.100.1"));

    let outcome = apply_probe_cycle(
        &mut instance,
        HealthObservation::Healthy,
        vec![
            ProbeObservation::ObservedExitIp("203.0.113.10".to_string()),
            ProbeObservation::ObservedExitIp("203.0.113.11".to_string()),
        ],
    );

    assert_eq!(outcome, ProbeOutcome::Uncertain);
    assert_eq!(
        instance.last_observed_exit_ip.as_deref(),
        Some("198.51.100.1")
    );
    assert!(instance.recent_error.unwrap().contains("uncertain"));
}

#[test]
fn probe_endpoint_failure_does_not_mark_instance_unhealthy() {
    let mut instance = instance("a", Some("198.51.100.1"));

    let outcome = apply_probe_cycle(
        &mut instance,
        HealthObservation::Healthy,
        vec![ProbeObservation::EndpointFailed(
            "probe endpoint timeout".to_string(),
        )],
    );

    assert_eq!(outcome, ProbeOutcome::NoAcceptedObservation);
    assert!(instance.enabled);
    assert_eq!(
        instance.last_observed_exit_ip.as_deref(),
        Some("198.51.100.1")
    );
}

#[test]
fn health_failure_prevents_serving_pool_membership() {
    let mut instance = instance("a", Some("198.51.100.1"));

    let outcome = apply_probe_cycle(
        &mut instance,
        HealthObservation::Unhealthy("mock transport failed".to_string()),
        vec![ProbeObservation::ObservedExitIp("198.51.100.9".to_string())],
    );

    assert_eq!(
        outcome,
        ProbeOutcome::HealthFailed("mock transport failed".to_string())
    );
    assert!(!instance.enabled);

    let pool = ProxyPool::from_instances(PoolConfig::new(1, 2), vec![instance]);
    assert_eq!(pool.status().readiness, Readiness::Unavailable);
}

#[test]
fn accepted_exit_ip_change_reclassifies_future_pool_status() {
    let mut first = instance("first", Some("198.51.100.1"));
    let second = instance("second", Some("198.51.100.2"));

    apply_probe_cycle(
        &mut first,
        HealthObservation::Healthy,
        vec![ProbeObservation::ObservedExitIp("198.51.100.2".to_string())],
    );

    let pool = ProxyPool::from_instances(PoolConfig::new(2, 3), vec![first, second]);
    let status = pool.status();

    assert_eq!(status.readiness, Readiness::Degraded);
    assert_eq!(status.actual_serving_size, 1);
}

fn instance(id: &str, exit_ip: Option<&str>) -> StoredWarpInstance {
    let mut instance = StoredWarpInstance::new_mock(
        "default",
        exit_ip,
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        format!("secret-{id}"),
    );
    instance.instance_id = id.to_string();
    instance
}
