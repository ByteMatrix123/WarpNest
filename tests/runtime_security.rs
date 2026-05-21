use predicates::prelude::*;
use warpnest::{
    config::Config,
    security::{SecurityWarning, file_permission_warnings, redact_sensitive},
    state_store::{
        InstanceLifecycleState, PoolMembershipPreference, StateStore, StoredWarpInstance,
    },
    status::PoolStatus,
};

#[test]
fn public_proxy_endpoint_exposure_requires_shared_secret() {
    let config = toml::from_str::<Config>(
        r#"
target_serving_size = 1
registration_budget = 3
state_store_path = "warpnest.sqlite"

[listeners]
management_bind = "127.0.0.1:0"
socks5_bind = "0.0.0.0:1080"
http_bind = "127.0.0.1:8080"

[auth]
shared_secret = ""
"#,
    )
    .unwrap();

    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("public Proxy Endpoint exposure requires a shared secret")
    );
}

#[test]
fn public_listener_exposure_is_allowed_with_shared_secret() {
    let config = toml::from_str::<Config>(
        r#"
target_serving_size = 1
registration_budget = 3
state_store_path = "warpnest.sqlite"

[listeners]
management_bind = "0.0.0.0:9090"
socks5_bind = "0.0.0.0:1080"
http_bind = "0.0.0.0:8080"

[auth]
shared_secret = "secret"
"#,
    )
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn status_redacts_recent_errors_that_look_sensitive() {
    let status = PoolStatus::blocked(1, 3, "registration token abc123 rejected");
    let rendered = serde_json::to_string(&status).unwrap();

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("abc123"));
}

#[test]
fn restored_status_redacts_instance_recent_errors() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let mut instance = StoredWarpInstance::new_mock(
        "default",
        Some("198.51.100.1"),
        PoolMembershipPreference::Serving,
        InstanceLifecycleState::Registered,
        "raw-registration-secret",
    );
    instance.recent_error = Some("private_key leaked in upstream error".to_string());
    store.upsert_instance(&instance).unwrap();

    let status = PoolStatus::from_restored_instances(1, 3, store.list_instances().unwrap());
    let rendered = serde_json::to_string(&status).unwrap();

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("private_key"));
    assert!(!rendered.contains("raw-registration-secret"));
}

#[test]
fn redaction_leaves_non_sensitive_errors_readable() {
    assert_eq!(
        redact_sensitive("probe endpoint timeout"),
        "probe endpoint timeout"
    );
}

#[cfg(unix)]
#[test]
fn broad_file_permissions_are_reported_as_warnings() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("warpnest.sqlite");
    std::fs::write(&path, "state").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        file_permission_warnings(&path),
        vec![SecurityWarning::FilePermissionsTooBroad {
            path: path.display().to_string()
        }]
    );
}

#[test]
fn cli_validation_reports_public_proxy_exposure() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    std::fs::write(
        &config_path,
        r#"
target_serving_size = 1
registration_budget = 3
state_store_path = "warpnest.sqlite"

[listeners]
management_bind = "127.0.0.1:0"
socks5_bind = "0.0.0.0:1080"
http_bind = "127.0.0.1:8080"

[auth]
shared_secret = ""
"#,
    )
    .unwrap();

    assert_cmd::Command::cargo_bin("warpnest")
        .unwrap()
        .args(["status", "--config", config_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "public Proxy Endpoint exposure requires a shared secret",
        ));
}
