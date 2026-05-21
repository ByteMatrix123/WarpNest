use warpnest::{
    public_warp_adapter::{PUBLIC_WARP_WIREGUARD_OBSERVED_V1, PublicWarpAdapterConfig},
    state_store::{
        InstanceLifecycleState, PoolMembershipPreference, StateStore, StoredWarpInstance,
    },
    status::PoolStatus,
};

#[test]
fn state_store_persists_and_restores_warp_instances() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");

    let store = StateStore::open(&db_path).unwrap();
    let instance = StoredWarpInstance::new_mock(
        "default",
        Some("198.51.100.10"),
        PoolMembershipPreference::Serving,
        InstanceLifecycleState::Registered,
        "registration-secret-material",
    );
    let instance_id = instance.instance_id.clone();
    store.upsert_instance(&instance).unwrap();
    drop(store);

    let reopened = StateStore::open(&db_path).unwrap();
    let restored = reopened.list_instances().unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, instance_id);
    assert_eq!(restored[0].group, "default");
    assert_eq!(
        restored[0].last_observed_exit_ip.as_deref(),
        Some("198.51.100.10")
    );
    assert_eq!(
        restored[0].pool_membership_preference,
        PoolMembershipPreference::Serving
    );
    assert_eq!(
        restored[0].lifecycle_state,
        InstanceLifecycleState::Registered
    );
    assert_eq!(restored[0].adapter_config.kind, "mock");
    assert_eq!(restored[0].adapter_config.version, 1);
}

#[test]
fn pool_status_from_restored_instances_does_not_expose_registration_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    let store = StateStore::open(&db_path).unwrap();
    store
        .upsert_instance(&StoredWarpInstance::new_mock(
            "default",
            Some("203.0.113.8"),
            PoolMembershipPreference::Standby,
            InstanceLifecycleState::Registered,
            "super-secret-registration-token",
        ))
        .unwrap();

    let instances = store.list_instances().unwrap();
    let status = PoolStatus::from_restored_instances(2, 4, instances);
    let rendered = serde_json::to_string(&status).unwrap();

    assert!(rendered.contains("203.0.113.8"));
    assert!(!rendered.contains("super-secret-registration-token"));
    assert!(!rendered.contains("registration_material"));
    assert!(!rendered.contains("adapter_config"));
}

#[test]
fn state_store_persists_raw_and_normalized_public_warp_adapter_material() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    let store = StateStore::open(&db_path).unwrap();
    let adapter_config =
        PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(serde_json::json!({
            "interface_addresses": ["172.16.0.2/32"],
            "peer_endpoint": "engage.cloudflareclient.com:2408",
            "private_key": "sensitive-private-key"
        }))
        .unwrap();

    store
        .upsert_instance(&StoredWarpInstance::new_with_adapter(
            "default",
            Some("203.0.113.9"),
            PoolMembershipPreference::Standby,
            InstanceLifecycleState::Registered,
            "{\"registration_material\":\"sensitive-token\"}",
            adapter_config,
        ))
        .unwrap();

    let restored = store.list_instances().unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored[0].raw_registration_material(),
        "{\"registration_material\":\"sensitive-token\"}"
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
    assert!(restored[0].adapter_config.ensure_supported().is_ok());
}

#[test]
fn state_store_migrates_legacy_registration_material_to_mock_adapter_contract() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    {
        let connection = rusqlite::Connection::open(&db_path).unwrap();
        connection
            .execute_batch(
                r#"
                pragma user_version = 1;
                create table warp_instances (
                    instance_id text primary key not null,
                    instance_group text not null,
                    label text,
                    enabled integer not null,
                    last_observed_exit_ip text,
                    pool_membership_preference text not null,
                    lifecycle_state text not null,
                    registration_material text not null,
                    recent_error text,
                    created_at text not null default current_timestamp,
                    updated_at text not null default current_timestamp
                );
                insert into warp_instances (
                    instance_id,
                    instance_group,
                    label,
                    enabled,
                    last_observed_exit_ip,
                    pool_membership_preference,
                    lifecycle_state,
                    registration_material,
                    recent_error
                ) values (
                    'legacy-instance',
                    'default',
                    null,
                    1,
                    '198.51.100.11',
                    'serving',
                    'registered',
                    'legacy-registration-secret',
                    null
                );
                "#,
            )
            .unwrap();
    }

    let store = StateStore::open(&db_path).unwrap();
    let restored = store.list_instances().unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, "legacy-instance");
    assert_eq!(
        restored[0].raw_registration_material(),
        "legacy-registration-secret"
    );
    assert_eq!(restored[0].adapter_config.kind, "mock");
    assert_eq!(restored[0].adapter_config.version, 1);
    assert_eq!(restored[0].adapter_config.config_json(), "{}");
}

#[test]
fn stored_instance_debug_redacts_raw_and_normalized_adapter_secrets() {
    let adapter_config =
        PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(serde_json::json!({
            "private_key": "sensitive-private-key",
            "token": "sensitive-token"
        }))
        .unwrap();
    let instance = StoredWarpInstance::new_with_adapter(
        "default",
        None,
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        "raw-registration-secret",
        adapter_config,
    );

    let rendered = format!("{instance:?}");

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("raw-registration-secret"));
    assert!(!rendered.contains("sensitive-private-key"));
    assert!(!rendered.contains("sensitive-token"));
}

#[test]
fn unsupported_public_warp_adapter_contract_fails_explicitly() {
    let adapter_config =
        PublicWarpAdapterConfig::from_storage("future-public-warp-adapter", 99, "{}").unwrap();

    let error = adapter_config.ensure_supported().unwrap_err().to_string();

    assert!(error.contains("unsupported Public WARP Adapter future-public-warp-adapter v99"));
}

#[test]
fn corrupted_state_store_returns_clear_error() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    std::fs::write(&db_path, "not sqlite").unwrap();

    let error = StateStore::open(&db_path).unwrap_err().to_string();

    assert!(error.contains("failed to initialize State Store"));
}
