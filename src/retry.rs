use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationKind {
    Registration,
    Connection,
    ExitProbe,
    HealthCheck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryError {
    Transient(String),
    Blocked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationOutcome {
    Ready,
    RetryAfter(Duration),
    Blocked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: Duration,
    pub max_registration_concurrency: usize,
    pub max_connection_concurrency: usize,
    pub max_probe_concurrency: usize,
}

#[derive(Debug)]
pub struct RetryDiscipline {
    policy: RetryPolicy,
    attempts: HashMap<OperationKind, u32>,
    blocked: HashMap<OperationKind, String>,
    limits: HashMap<OperationKind, Arc<ConcurrencyLimit>>,
}

#[derive(Debug)]
pub struct ConcurrencyPermit {
    limit: Arc<ConcurrencyLimit>,
}

#[derive(Debug)]
pub enum ConcurrencyError {
    LimitReached,
}

#[derive(Debug)]
struct ConcurrencyLimit {
    max: usize,
    current: AtomicUsize,
}

impl Default for RetryDiscipline {
    fn default() -> Self {
        Self::new(RetryPolicy::default())
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            jitter: Duration::from_millis(25),
            max_registration_concurrency: 1,
            max_connection_concurrency: 8,
            max_probe_concurrency: 4,
        }
    }
}

impl RetryDiscipline {
    pub fn new(policy: RetryPolicy) -> Self {
        let limits = HashMap::from([
            (
                OperationKind::Registration,
                Arc::new(ConcurrencyLimit::new(policy.max_registration_concurrency)),
            ),
            (
                OperationKind::Connection,
                Arc::new(ConcurrencyLimit::new(policy.max_connection_concurrency)),
            ),
            (
                OperationKind::ExitProbe,
                Arc::new(ConcurrencyLimit::new(policy.max_probe_concurrency)),
            ),
            (
                OperationKind::HealthCheck,
                Arc::new(ConcurrencyLimit::new(policy.max_probe_concurrency)),
            ),
        ]);
        Self {
            policy,
            attempts: HashMap::new(),
            blocked: HashMap::new(),
            limits,
        }
    }

    pub fn record_failure(
        &mut self,
        operation: OperationKind,
        error: RetryError,
    ) -> OperationOutcome {
        match error {
            RetryError::Blocked(reason) => {
                self.blocked.insert(operation, reason.clone());
                OperationOutcome::Blocked(reason)
            }
            RetryError::Transient(_) => {
                if let Some(reason) = self.blocked.get(&operation) {
                    return OperationOutcome::Blocked(reason.clone());
                }

                let attempts = self.attempts.entry(operation).or_insert(0);
                let delay = retry_delay(&self.policy, *attempts);
                *attempts += 1;
                OperationOutcome::RetryAfter(delay)
            }
        }
    }

    pub fn record_success(&mut self, operation: OperationKind) {
        self.attempts.remove(&operation);
        self.blocked.remove(&operation);
    }

    pub fn next_retry(&self, operation: OperationKind) -> OperationOutcome {
        if let Some(reason) = self.blocked.get(&operation) {
            return OperationOutcome::Blocked(reason.clone());
        }

        self.attempts
            .get(&operation)
            .map(|attempts| OperationOutcome::RetryAfter(retry_delay(&self.policy, *attempts)))
            .unwrap_or(OperationOutcome::Ready)
    }

    pub fn is_blocked(&self, operation: OperationKind) -> bool {
        self.blocked.contains_key(&operation)
    }

    pub fn try_acquire(
        &self,
        operation: OperationKind,
    ) -> Result<ConcurrencyPermit, ConcurrencyError> {
        let limit = self
            .limits
            .get(&operation)
            .expect("all operation kinds have limits")
            .clone();
        limit.acquire()
    }
}

impl OperationOutcome {
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RetryAfter(delay) => Some(*delay),
            Self::Ready | Self::Blocked(_) => None,
        }
    }
}

impl ConcurrencyLimit {
    fn new(max: usize) -> Self {
        Self {
            max,
            current: AtomicUsize::new(0),
        }
    }

    fn acquire(self: Arc<Self>) -> Result<ConcurrencyPermit, ConcurrencyError> {
        let mut current = self.current.load(Ordering::Relaxed);
        loop {
            if current >= self.max {
                return Err(ConcurrencyError::LimitReached);
            }

            match self.current.compare_exchange(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(ConcurrencyPermit { limit: self }),
                Err(next) => current = next,
            }
        }
    }
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.limit.current.fetch_sub(1, Ordering::Release);
    }
}

fn retry_delay(policy: &RetryPolicy, attempts: u32) -> Duration {
    let multiplier = 2_u32.saturating_pow(attempts);
    let delay = policy.base_delay.saturating_mul(multiplier);
    delay.min(policy.max_delay).saturating_add(policy.jitter)
}

#[allow(dead_code)]
fn operation_set() -> HashSet<OperationKind> {
    HashSet::from([
        OperationKind::Registration,
        OperationKind::Connection,
        OperationKind::ExitProbe,
        OperationKind::HealthCheck,
    ])
}
