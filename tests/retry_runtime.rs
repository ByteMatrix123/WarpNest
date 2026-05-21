use std::time::Duration;
use warpnest::{
    retry::{OperationKind, OperationOutcome, RetryDiscipline, RetryError, RetryPolicy},
    status::{PoolStatus, Readiness},
};

#[test]
fn transient_failures_retry_with_independent_backoff() {
    let mut retry = RetryDiscipline::new(RetryPolicy {
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        jitter: Duration::from_millis(25),
        max_registration_concurrency: 1,
        max_connection_concurrency: 2,
        max_probe_concurrency: 3,
    });

    let first = retry.record_failure(
        OperationKind::ExitProbe,
        RetryError::Transient("timeout".to_string()),
    );
    let second = retry.record_failure(
        OperationKind::ExitProbe,
        RetryError::Transient("timeout".to_string()),
    );
    let connection = retry.record_failure(
        OperationKind::Connection,
        RetryError::Transient("connection reset".to_string()),
    );

    assert!(matches!(first, OperationOutcome::RetryAfter(_)));
    assert!(matches!(second, OperationOutcome::RetryAfter(_)));
    assert!(second.retry_after().unwrap() > first.retry_after().unwrap());
    assert_eq!(
        connection.retry_after().unwrap(),
        Duration::from_millis(125)
    );
}

#[test]
fn permanent_policy_failure_blocks_without_retry() {
    let mut retry = RetryDiscipline::default();

    let outcome = retry.record_failure(
        OperationKind::Registration,
        RetryError::Blocked("public WARP registration rejected".to_string()),
    );

    assert_eq!(
        outcome,
        OperationOutcome::Blocked("public WARP registration rejected".to_string())
    );
    assert!(retry.is_blocked(OperationKind::Registration));
    assert_eq!(
        retry.next_retry(OperationKind::Registration),
        OperationOutcome::Blocked("public WARP registration rejected".to_string())
    );
}

#[test]
fn concurrency_limits_are_tracked_per_operation_family() {
    let retry = RetryDiscipline::default();

    let first = retry.try_acquire(OperationKind::Registration).unwrap();
    assert!(retry.try_acquire(OperationKind::Registration).is_err());
    drop(first);
    assert!(retry.try_acquire(OperationKind::Registration).is_ok());
}

#[test]
fn successful_operation_clears_retry_state() {
    let mut retry = RetryDiscipline::default();
    retry.record_failure(
        OperationKind::HealthCheck,
        RetryError::Transient("temporary".to_string()),
    );

    retry.record_success(OperationKind::HealthCheck);

    assert_eq!(
        retry.next_retry(OperationKind::HealthCheck),
        OperationOutcome::Ready
    );
}

#[test]
fn blocked_readiness_is_reported_with_non_sensitive_error_summary() {
    let status = PoolStatus::blocked(2, 4, "authorization rejected: token redacted");

    assert_eq!(status.readiness, Readiness::Blocked);
    assert_eq!(status.recent_error.as_deref(), Some("[redacted]"));
    assert!(serde_json::to_string(&status).unwrap().contains("blocked"));
}
