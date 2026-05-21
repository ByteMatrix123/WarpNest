use warpnest::{
    data_plane::{BoringTunDataPlane, DataPlaneInstanceConfig},
    direct_public_warp_registration::WarpKeyPair,
    pool::{PoolConfig, ProxyPool},
    probe::{
        FakeRuntimeProbeTransport, HealthObservation, ProbeObservation, ProbeOutcome,
        RuntimeProbeRequest, apply_probe_cycle,
    },
    public_warp_adapter::PublicWarpAdapterConfig,
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
    status::{PoolStatus, Readiness},
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

#[tokio::test]
async fn runtime_probe_cycle_updates_exit_ip_through_selected_instance() {
    let data_plane = runtime_data_plane();
    let mut instance = instance("runtime-a", Some("198.51.100.1"));
    let cycle = FakeRuntimeProbeTransport::healthy_with_exit_ip("203.0.113.44")
        .run(&data_plane, RuntimeProbeRequest::new("runtime-a"))
        .await;

    let outcome = apply_probe_cycle(&mut instance, cycle.health, cycle.observations);

    assert_eq!(outcome, ProbeOutcome::Accepted("203.0.113.44".to_string()));
    assert_eq!(
        instance.last_observed_exit_ip.as_deref(),
        Some("203.0.113.44")
    );
    assert!(instance.enabled);
}

#[tokio::test]
async fn runtime_health_failure_stays_separate_from_exit_probe_observations() {
    let data_plane = runtime_data_plane();
    let mut instance = instance("runtime-a", Some("198.51.100.1"));
    let cycle = FakeRuntimeProbeTransport::unhealthy("private_key=secret transport down")
        .run(&data_plane, RuntimeProbeRequest::new("runtime-a"))
        .await;

    let outcome = apply_probe_cycle(&mut instance, cycle.health, cycle.observations);

    assert!(matches!(outcome, ProbeOutcome::HealthFailed(_)));
    assert!(!instance.enabled);
    assert_eq!(
        instance.last_observed_exit_ip.as_deref(),
        Some("198.51.100.1")
    );
    let status = PoolStatus::from_restored_instances(1, 2, vec![instance]);
    let rendered = serde_json::to_string(&status).unwrap();
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("secret"));
}

#[tokio::test]
async fn runtime_probe_failure_reports_sanitized_recent_error_without_disabling_health() {
    let data_plane = runtime_data_plane();
    let mut instance = instance("runtime-a", Some("198.51.100.1"));
    let cycle = FakeRuntimeProbeTransport::endpoint_failed("peer_public_key=secret timeout")
        .run(&data_plane, RuntimeProbeRequest::new("runtime-a"))
        .await;

    let outcome = apply_probe_cycle(&mut instance, cycle.health, cycle.observations);

    assert_eq!(outcome, ProbeOutcome::NoAcceptedObservation);
    assert!(instance.enabled);
    let rendered =
        serde_json::to_string(&PoolStatus::from_restored_instances(1, 2, vec![instance])).unwrap();
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("secret"));
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

fn runtime_data_plane() -> BoringTunDataPlane {
    BoringTunDataPlane::try_with_instances([DataPlaneInstanceConfig {
        instance_id: "runtime-a".to_string(),
        adapter_config: PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(
            serde_json::json!({
                "private_key": WarpKeyPair::from_private_key_bytes([51; 32]).private_key_base64(),
                "interface_addresses": ["172.16.0.2/32"],
                "peer_public_key": WarpKeyPair::from_private_key_bytes([52; 32]).public_key_base64(),
                "peer_endpoint": "engage.cloudflareclient.com:2408",
                "allowed_ips": ["0.0.0.0/0"],
                "dns_servers": ["1.1.1.1"],
                "device_id": "fixture-runtime-a",
            }),
        )
        .unwrap(),
    }])
    .unwrap()
}
