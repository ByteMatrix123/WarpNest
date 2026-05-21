use warpnest::{
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
}

#[test]
fn corrupted_state_store_returns_clear_error() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("warpnest.sqlite");
    std::fs::write(&db_path, "not sqlite").unwrap();

    let error = StateStore::open(&db_path).unwrap_err().to_string();

    assert!(error.contains("failed to initialize State Store"));
}
