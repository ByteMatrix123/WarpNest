use warpnest::{
    public_warp_adapter::{PUBLIC_WARP_WIREGUARD_OBSERVED_V1, PublicWarpAdapterConfig},
    retry::{OperationKind, OperationOutcome},
    state_store::StateStore,
    status::PoolStatus,
    warp_lifecycle::{
        MockRegistrationClient, PublicRegistrationRequest, RegistrationError, RegistrationService,
    },
};

#[test]
fn creates_public_warp_registration_and_persists_sensitive_material() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    let store = StateStore::open(&db_path).unwrap();
    let client = MockRegistrationClient::succeeds("public-registration-secret");
    let mut service = RegistrationService::new(&store, client, 2);

    let created = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap();

    assert_eq!(created.group, "default");
    let restored = store.list_instances().unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, created.instance_id);
    assert_eq!(restored[0].redacted_registration_material(), "[redacted]");
    assert_eq!(restored[0].adapter_config.kind, "mock");
}

#[test]
fn creates_public_warp_registration_with_adapter_config() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    let store = StateStore::open(&db_path).unwrap();
    let adapter_config =
        PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(serde_json::json!({
            "interface_addresses": ["172.16.0.2/32"],
            "peer_endpoint": "engage.cloudflareclient.com:2408",
            "private_key": "fixture-private-key"
        }))
        .unwrap();
    let client = MockRegistrationClient::succeeds_with_adapter(
        "{\"registration_material\":\"fixture-secret\"}",
        adapter_config,
    );
    let mut service = RegistrationService::new(&store, client, 2);

    let created = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap();

    let restored = store.list_instances().unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, created.instance_id);
    assert_eq!(
        restored[0].raw_registration_material(),
        "{\"registration_material\":\"fixture-secret\"}"
    );
    assert_eq!(
        restored[0].adapter_config.kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
    assert_eq!(restored[0].adapter_config.version, 1);
    assert!(
        restored[0]
            .adapter_config
            .config_json()
            .contains("peer_endpoint")
    );

    let rendered_status =
        serde_json::to_string(&PoolStatus::from_restored_instances(1, 2, restored.clone()))
            .unwrap();
    let rendered_debug = format!("{:?}", restored[0]);
    assert!(!rendered_status.contains("fixture-secret"));
    assert!(!rendered_status.contains("fixture-private-key"));
    assert!(!rendered_status.contains("adapter_config"));
    assert!(!rendered_debug.contains("fixture-secret"));
    assert!(!rendered_debug.contains("fixture-private-key"));
}

#[test]
fn registration_budget_is_a_hard_limit() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let client = MockRegistrationClient::succeeds("public-registration-secret");
    let mut service = RegistrationService::new(&store, client, 1);

    service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap();
    let error = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap_err();

    assert_eq!(error, RegistrationError::BudgetExceeded);
}

#[test]
fn blocked_public_registration_failure_stops_automatic_retry() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let client = MockRegistrationClient::blocked("public WARP registration rejected");
    let mut service = RegistrationService::new(&store, client, 2);

    let error = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap_err();

    assert_eq!(
        error,
        RegistrationError::Blocked("public WARP registration rejected".to_string())
    );
    assert_eq!(
        service
            .retry_state()
            .next_retry(OperationKind::Registration),
        OperationOutcome::Blocked("public WARP registration rejected".to_string())
    );
}

#[test]
fn transient_public_registration_failure_records_retry_without_persisting() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let client = MockRegistrationClient::transient("temporary network error");
    let mut service = RegistrationService::new(&store, client, 2);

    let error = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap_err();

    assert_eq!(
        error,
        RegistrationError::Transient("temporary network error".to_string())
    );
    assert!(matches!(
        service
            .retry_state()
            .next_retry(OperationKind::Registration),
        OperationOutcome::RetryAfter(_)
    ));
    assert!(store.list_instances().unwrap().is_empty());
}

#[test]
fn unsupported_public_registration_failure_blocks_without_persisting() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let client = MockRegistrationClient::unsupported("unsupported public WARP material shape");
    let mut service = RegistrationService::new(&store, client, 2);

    let error = service
        .create_public_registration(PublicRegistrationRequest::default())
        .unwrap_err();

    assert_eq!(
        error,
        RegistrationError::Unsupported("unsupported public WARP material shape".to_string())
    );
    assert_eq!(
        service
            .retry_state()
            .next_retry(OperationKind::Registration),
        OperationOutcome::Blocked("unsupported public WARP material shape".to_string())
    );
    assert!(store.list_instances().unwrap().is_empty());
}

#[test]
fn public_scope_request_does_not_support_warp_plus_or_zero_trust_fields() {
    let request = PublicRegistrationRequest::default();

    assert_eq!(request.group, "default");
    assert_eq!(request.label, None);
}
