use assert_cmd::Command;
use predicates::prelude::*;
use warpnest::state_store::{
    InstanceLifecycleState, PoolMembershipPreference, StateStore, StoredWarpInstance,
};

#[test]
fn status_restores_instances_from_state_store() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    let db_path = temp.path().join("warpnest.sqlite");

    std::fs::write(
        &config_path,
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

    let store = StateStore::open(&db_path).unwrap();
    let instance = StoredWarpInstance::new_mock(
        "default",
        Some("198.51.100.12"),
        PoolMembershipPreference::Serving,
        InstanceLifecycleState::Registered,
        "raw-secret-registration-material",
    );
    store.upsert_instance(&instance).unwrap();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args(["status", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"readiness\": \"ready\""))
        .stdout(predicate::str::contains("198.51.100.12"))
        .stdout(predicate::str::contains("raw-secret-registration-material").not());
}

#[test]
fn status_reclassifies_duplicate_exit_ips_from_state_store() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("warpnest.toml");
    let db_path = temp.path().join("warpnest.sqlite");

    std::fs::write(
        &config_path,
        format!(
            r#"
target_serving_size = 2
registration_budget = 4
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

    let store = StateStore::open(&db_path).unwrap();
    store
        .upsert_instance(&stored_instance("one", "198.51.100.1"))
        .unwrap();
    store
        .upsert_instance(&stored_instance("two", "198.51.100.1"))
        .unwrap();

    Command::cargo_bin("warpnest")
        .unwrap()
        .args(["status", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"readiness\": \"degraded\""))
        .stdout(predicate::str::contains("\"actual_serving_size\": 1"))
        .stdout(predicate::str::contains("\"pool_membership\": \"serving\""))
        .stdout(predicate::str::contains("\"pool_membership\": \"standby\""));
}

fn stored_instance(id: &str, exit_ip: &str) -> StoredWarpInstance {
    let mut instance = StoredWarpInstance::new_mock(
        "default",
        Some(exit_ip),
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        format!("secret-{id}"),
    );
    instance.instance_id = id.to_string();
    instance
}
