use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn init_writes_default_configuration_file() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");

    Command::cargo_bin("warpnest")
        .unwrap()
        .args(["init", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote configuration"));

    let config = std::fs::read_to_string(config_path).unwrap();
    assert!(config.contains("target_serving_size = 1"));
    assert!(config.contains("registration_budget = 3"));
    assert!(config.contains("state_store_path = \"warpnest.sqlite\""));
    assert!(config.contains("management_bind = \"127.0.0.1:0\""));
}

#[test]
fn mock_status_reports_pool_shape_without_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");

    Command::cargo_bin("warpnest")
        .unwrap()
        .args(["init", "--config", config_path.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args([
            "status",
            "--config",
            config_path.to_str().unwrap(),
            "--mock",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"readiness\": \"degraded\""))
        .stdout(predicate::str::contains("\"target_serving_size\": 1"))
        .stdout(predicate::str::contains("\"registration_budget\": 3"))
        .stdout(predicate::str::contains("\"instances\""))
        .stdout(predicate::str::contains("secret").not());
}

#[test]
fn config_validation_rejects_public_management_api_without_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    std::fs::write(
        &config_path,
        r#"
target_serving_size = 1
registration_budget = 3
state_store_path = "warpnest.sqlite"

[listeners]
management_bind = "0.0.0.0:8080"
socks5_bind = "127.0.0.1:1080"
http_bind = "127.0.0.1:8081"

[auth]
shared_secret = ""
"#,
    )
    .unwrap();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args([
            "status",
            "--config",
            config_path.to_str().unwrap(),
            "--mock",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "public Management API exposure requires a shared secret",
        ));
}
