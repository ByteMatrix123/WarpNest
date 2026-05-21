use warpnest::{
    pool::{InstanceSelector, PoolConfig, ProxyPool, ScheduleError},
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
    status::Readiness,
};

#[test]
fn classifies_distinct_exit_ips_into_serving_and_duplicates_into_standby() {
    let pool = ProxyPool::from_instances(
        PoolConfig::new(2, 4),
        vec![
            instance("a", "default", Some("198.51.100.1")),
            instance("b", "default", Some("198.51.100.2")),
            instance("c", "default", Some("198.51.100.1")),
        ],
    );

    let status = pool.status();

    assert_eq!(status.readiness, Readiness::Ready);
    assert_eq!(status.actual_serving_size, 2);
    assert_eq!(
        membership(&status, "a"),
        Some(PoolMembershipPreference::Serving.as_str())
    );
    assert_eq!(
        membership(&status, "b"),
        Some(PoolMembershipPreference::Serving.as_str())
    );
    assert_eq!(
        membership(&status, "c"),
        Some(PoolMembershipPreference::Standby.as_str())
    );
}

#[test]
fn reports_degraded_and_unavailable_pool_states() {
    let degraded = ProxyPool::from_instances(
        PoolConfig::new(2, 4),
        vec![instance("a", "default", Some("198.51.100.1"))],
    );
    assert_eq!(degraded.status().readiness, Readiness::Degraded);
    assert_eq!(degraded.status().actual_serving_size, 1);

    let mut unavailable =
        ProxyPool::from_instances(PoolConfig::new(2, 4), vec![instance("a", "default", None)]);
    assert_eq!(unavailable.status().readiness, Readiness::Unavailable);
    assert_eq!(
        unavailable.schedule_auto().unwrap_err(),
        ScheduleError::NoServingInstance
    );
}

#[test]
fn schedules_automatic_connections_by_least_active_connections() {
    let mut pool = ProxyPool::from_instances(
        PoolConfig::new(2, 4),
        vec![
            instance("a", "default", Some("198.51.100.1")),
            instance("b", "default", Some("198.51.100.2")),
        ],
    );

    let first = pool.schedule_auto().unwrap();
    assert_eq!(first.instance_id(), "a");
    let second = pool.schedule_auto().unwrap();
    assert_eq!(second.instance_id(), "b");
    drop(first);

    let third = pool.schedule_auto().unwrap();
    assert_eq!(third.instance_id(), "a");
}

#[test]
fn explicit_selection_can_use_standby_instances() {
    let mut pool = ProxyPool::from_instances(
        PoolConfig::new(1, 3),
        vec![
            instance("serving", "default", Some("198.51.100.1")),
            instance("standby", "default", Some("198.51.100.1")),
        ],
    );

    let selected = pool
        .select_instance(InstanceSelector::Id("standby".to_string()))
        .unwrap();

    assert_eq!(selected.instance_id(), "standby");
}

#[test]
fn group_selector_uses_serving_instances_unless_standby_fallback_is_enabled() {
    let instances = vec![
        instance("a", "default", Some("198.51.100.1")),
        instance("b", "api", Some("198.51.100.1")),
    ];

    let mut strict = ProxyPool::from_instances(PoolConfig::new(1, 3), instances.clone());
    assert_eq!(
        strict
            .select_instance(InstanceSelector::Group("api".to_string()))
            .unwrap_err(),
        ScheduleError::NoServingInstanceInGroup
    );

    let mut fallback =
        ProxyPool::from_instances(PoolConfig::new(1, 3).with_standby_fallback(true), instances);
    let selected = fallback
        .select_instance(InstanceSelector::Group("api".to_string()))
        .unwrap();
    assert_eq!(selected.instance_id(), "b");
}

fn instance(id: &str, group: &str, exit_ip: Option<&str>) -> StoredWarpInstance {
    let mut instance = StoredWarpInstance::new_mock(
        group,
        exit_ip,
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        format!("secret-{id}"),
    );
    instance.instance_id = id.to_string();
    instance
}

fn membership<'a>(status: &'a warpnest::status::PoolStatus, id: &str) -> Option<&'a str> {
    status
        .instances
        .iter()
        .find(|instance| instance.instance_id == id)
        .map(|instance| instance.pool_membership.as_str())
}
