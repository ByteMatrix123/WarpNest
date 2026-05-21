use assert_cmd::Command;
use predicates::prelude::*;
use warpnest::{public_warp_adapter::PUBLIC_WARP_WIREGUARD_OBSERVED_V1, state_store::StateStore};

const OBSERVED_FIXTURE: &str = r#"{
  "wireguard": {
    "private_key": "fixture-private-key",
    "interface_addresses": ["172.16.0.2/32"],
    "peer_public_key": "fixture-peer-public-key",
    "peer_endpoint": "engage.cloudflareclient.com:2408",
    "allowed_ips": ["0.0.0.0/0"],
    "dns_servers": ["1.1.1.1"],
    "device_id": "fixture-device-id"
  }
}"#;

#[test]
fn cli_imports_observed_material_into_configured_state_store_without_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    let db_path = temp.path().join("warpnest.sqlite");
    let material_path = temp.path().join("observed-warp.json");
    write_config(&config_path, &db_path);
    std::fs::write(&material_path, OBSERVED_FIXTURE).unwrap();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args([
            "import-observed",
            "--config",
            config_path.to_str().unwrap(),
            "--material",
            material_path.to_str().unwrap(),
            "--group",
            "bootstrap",
            "--label",
            "laptop-a",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"instance_id\""))
        .stdout(predicate::str::contains("\"group\": \"bootstrap\""))
        .stdout(predicate::str::contains("\"label\": \"laptop-a\""))
        .stdout(predicate::str::contains("fixture-private-key").not())
        .stdout(predicate::str::contains("fixture-peer-public-key").not())
        .stdout(predicate::str::contains("adapter_config").not());

    let store = StateStore::open(&db_path).unwrap();
    let restored = store.list_instances().unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].group, "bootstrap");
    assert_eq!(restored[0].label.as_deref(), Some("laptop-a"));
    assert_eq!(restored[0].raw_registration_material(), OBSERVED_FIXTURE);
    assert_eq!(
        restored[0].adapter_config.kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
}

#[test]
fn cli_import_reports_missing_explicit_material_file() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    let db_path = temp.path().join("warpnest.sqlite");
    let missing_path = temp.path().join("missing-observed-warp.json");
    write_config(&config_path, &db_path);

    Command::cargo_bin("warpnest")
        .unwrap()
        .args([
            "import-observed",
            "--config",
            config_path.to_str().unwrap(),
            "--material",
            missing_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "failed to import observed Public WARP material",
        ));
}

#[test]
fn cli_import_reports_unsupported_material_shape() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    let db_path = temp.path().join("warpnest.sqlite");
    let material_path = temp.path().join("observed-warp.json");
    write_config(&config_path, &db_path);
    std::fs::write(&material_path, r#"{"wireguard":{"private_key":""}}"#).unwrap();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args([
            "import-observed",
            "--config",
            config_path.to_str().unwrap(),
            "--material",
            material_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported material shape"));
}

fn write_config(config_path: &std::path::Path, db_path: &std::path::Path) {
    std::fs::write(
        config_path,
        format!(
            r#"
target_serving_size = 1
registration_budget = 3
state_store_path = "{}"

[listeners]
management_bind = "127.0.0.1:0"
socks5_bind = "127.0.0.1:1080"
http_bind = "127.0.0.1:8080"

[auth]
shared_secret = ""
"#,
            db_path.display()
        ),
    )
    .unwrap();
}
