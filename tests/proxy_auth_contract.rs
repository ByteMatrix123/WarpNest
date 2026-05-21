use warpnest::{
    config,
    pool::{PoolConfig, ProxyPool, ScheduleError},
    proxy_auth::{AuthConfig, ProxyCredentials, ProxyRequestError, resolve_proxy_request},
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
};

#[test]
fn empty_username_with_valid_password_uses_automatic_scheduling() {
    let mut pool = pool();
    let lease = resolve_proxy_request(
        &mut pool,
        &AuthConfig::shared_secret("secret"),
        ProxyCredentials::new("", "secret"),
    )
    .unwrap();

    assert_eq!(lease.instance_id(), "serving-a");
}

#[test]
fn username_selectors_resolve_to_matching_instances() {
    let mut pool = pool();
    let auth = AuthConfig::shared_secret("secret");

    assert_eq!(
        resolve_proxy_request(
            &mut pool,
            &auth,
            ProxyCredentials::new("id:standby-a", "secret")
        )
        .unwrap()
        .instance_id(),
        "standby-a"
    );
    assert_eq!(
        resolve_proxy_request(
            &mut pool,
            &auth,
            ProxyCredentials::new("exit:198.51.100.2", "secret")
        )
        .unwrap()
        .instance_id(),
        "serving-b"
    );
    assert_eq!(
        resolve_proxy_request(
            &mut pool,
            &auth,
            ProxyCredentials::new("group:api", "secret")
        )
        .unwrap()
        .instance_id(),
        "serving-b"
    );
}

#[test]
fn shared_secret_authentication_uses_password_not_username() {
    let mut pool = pool();

    assert_eq!(
        resolve_proxy_request(
            &mut pool,
            &AuthConfig::shared_secret("secret"),
            ProxyCredentials::new("id:serving-a", "wrong")
        )
        .unwrap_err(),
        ProxyRequestError::AuthenticationFailed
    );
}

#[test]
fn invalid_or_unavailable_selectors_fail_without_fallback() {
    let mut pool = pool();
    let auth = AuthConfig::shared_secret("secret");

    assert_eq!(
        resolve_proxy_request(&mut pool, &auth, ProxyCredentials::new("bad", "secret"))
            .unwrap_err(),
        ProxyRequestError::InvalidSelector
    );
    assert_eq!(
        resolve_proxy_request(
            &mut pool,
            &auth,
            ProxyCredentials::new("id:missing", "secret")
        )
        .unwrap_err(),
        ProxyRequestError::SelectionFailed(ScheduleError::InstanceNotFound)
    );
}

#[test]
fn unauthenticated_mode_still_treats_username_as_selector() {
    let mut pool = pool();

    let lease = resolve_proxy_request(
        &mut pool,
        &AuthConfig::disabled(),
        ProxyCredentials::new("id:standby-a", ""),
    )
    .unwrap();

    assert_eq!(lease.instance_id(), "standby-a");
}

#[test]
fn auth_config_is_derived_from_runtime_configuration() {
    assert_eq!(
        AuthConfig::from_config(&config::AuthConfig {
            shared_secret: String::new(),
        }),
        AuthConfig::disabled()
    );
    assert_eq!(
        AuthConfig::from_config(&config::AuthConfig {
            shared_secret: "secret".to_string(),
        }),
        AuthConfig::shared_secret("secret")
    );
}

fn pool() -> ProxyPool {
    ProxyPool::from_instances(
        PoolConfig::new(2, 4),
        vec![
            instance("serving-a", "default", "198.51.100.1"),
            instance("serving-b", "api", "198.51.100.2"),
            instance("standby-a", "api", "198.51.100.1"),
        ],
    )
}

fn instance(id: &str, group: &str, exit_ip: &str) -> StoredWarpInstance {
    let mut instance = StoredWarpInstance::new_mock(
        group,
        Some(exit_ip),
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        format!("secret-{id}"),
    );
    instance.instance_id = id.to_string();
    instance
}
