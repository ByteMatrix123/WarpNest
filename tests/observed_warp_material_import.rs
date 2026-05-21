use warpnest::{
    observed_warp_material::{
        ObservedWarpMaterial, ObservedWarpMaterialError, read_explicit_observed_warp_material_path,
    },
    public_warp_adapter::PUBLIC_WARP_WIREGUARD_OBSERVED_V1,
    state_store::StateStore,
    status::PoolStatus,
};

const OBSERVED_FIXTURE: &str = r#"{
  "wireguard": {
    "private_key": "fixture-private-key",
    "interface_addresses": ["172.16.0.2/32", "2606:4700:110:8f24::2/128"],
    "peer_public_key": "fixture-peer-public-key",
    "peer_endpoint": "engage.cloudflareclient.com:2408",
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "dns_servers": ["1.1.1.1", "2606:4700:4700::1111"],
    "device_id": "fixture-device-id"
  }
}"#;

#[test]
fn imports_observed_public_warp_material_into_adapter_config() {
    let material = ObservedWarpMaterial::from_json(OBSERVED_FIXTURE).unwrap();

    assert_eq!(material.raw_material(), OBSERVED_FIXTURE);
    assert_eq!(
        material.adapter_config().kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
    assert_eq!(material.adapter_config().version, 1);
    assert!(
        material
            .adapter_config()
            .config_json()
            .contains("peer_endpoint")
    );
    assert!(
        material
            .adapter_config()
            .config_json()
            .contains("dns_servers")
    );
}

#[test]
fn imported_observed_material_persists_as_warp_registration() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let material = ObservedWarpMaterial::from_json(OBSERVED_FIXTURE).unwrap();

    let imported = material
        .import_into_store(&store, "bootstrap", Some("observed fixture".to_string()))
        .unwrap();
    let restored = store.list_instances().unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, imported.instance_id);
    assert_eq!(restored[0].group, "bootstrap");
    assert_eq!(restored[0].label.as_deref(), Some("observed fixture"));
    assert_eq!(restored[0].raw_registration_material(), OBSERVED_FIXTURE);
    assert_eq!(
        restored[0].adapter_config.kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
}

#[test]
fn observed_material_redacts_raw_and_normalized_secrets_from_debug_and_status() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let material = ObservedWarpMaterial::from_json(OBSERVED_FIXTURE).unwrap();
    let rendered_material = format!("{material:?}");

    material.import_into_store(&store, "default", None).unwrap();
    let rendered_status = serde_json::to_string(&PoolStatus::from_restored_instances(
        1,
        1,
        store.list_instances().unwrap(),
    ))
    .unwrap();

    assert!(rendered_material.contains("[redacted]"));
    assert!(!rendered_material.contains("fixture-private-key"));
    assert!(!rendered_material.contains("fixture-peer-public-key"));
    assert!(!rendered_status.contains("fixture-private-key"));
    assert!(!rendered_status.contains("fixture-peer-public-key"));
    assert!(!rendered_status.contains("adapter_config"));
}

#[test]
fn unsupported_observed_material_shape_is_not_a_transient_read_failure() {
    let error = ObservedWarpMaterial::from_json(r#"{"wireguard":{"private_key":""}}"#).unwrap_err();

    assert!(matches!(
        error,
        ObservedWarpMaterialError::UnsupportedShape(_)
    ));
    assert!(error.to_string().contains("unsupported material shape"));
}

#[test]
fn missing_explicit_observed_material_path_reports_read_failure() {
    let temp = tempfile::tempdir().unwrap();
    let missing_path = temp.path().join("missing-observed-warp.json");
    let error = read_explicit_observed_warp_material_path(&missing_path).unwrap_err();
    let chain = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        error
            .to_string()
            .contains("failed to import observed Public WARP material")
    );
    assert!(chain.contains("failed to read observed Public WARP material"));
}

#[test]
fn import_from_explicit_path_uses_only_the_supplied_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("observed-warp.json");
    std::fs::write(&path, OBSERVED_FIXTURE).unwrap();

    let material = read_explicit_observed_warp_material_path(&path).unwrap();

    assert_eq!(
        material.adapter_config().kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
}
