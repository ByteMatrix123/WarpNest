use crate::{
    config,
    pool::{ConnectionLease, InstanceSelector, ProxyPool, ScheduleError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    shared_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyRequestError {
    AuthenticationFailed,
    InvalidSelector,
    SelectionFailed(ScheduleError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyRoute {
    Automatic,
    Select(InstanceSelector),
}

impl AuthConfig {
    pub fn shared_secret(secret: impl Into<String>) -> Self {
        Self {
            shared_secret: Some(secret.into()),
        }
    }

    pub fn disabled() -> Self {
        Self {
            shared_secret: None,
        }
    }

    pub fn from_config(config: &config::AuthConfig) -> Self {
        if config.shared_secret.is_empty() {
            Self::disabled()
        } else {
            Self::shared_secret(config.shared_secret.clone())
        }
    }

    pub fn requires_password(&self) -> bool {
        self.shared_secret.is_some()
    }

    fn authenticate(&self, credentials: &ProxyCredentials) -> bool {
        match &self.shared_secret {
            Some(secret) => credentials.password == *secret,
            None => true,
        }
    }
}

impl ProxyCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

pub fn resolve_proxy_request(
    pool: &mut ProxyPool,
    auth: &AuthConfig,
    credentials: ProxyCredentials,
) -> Result<ConnectionLease, ProxyRequestError> {
    if !auth.authenticate(&credentials) {
        return Err(ProxyRequestError::AuthenticationFailed);
    }

    match parse_route(&credentials.username)? {
        ProxyRoute::Automatic => pool
            .schedule_auto()
            .map_err(ProxyRequestError::SelectionFailed),
        ProxyRoute::Select(selector) => pool
            .select_instance(selector)
            .map_err(ProxyRequestError::SelectionFailed),
    }
}

fn parse_route(username: &str) -> Result<ProxyRoute, ProxyRequestError> {
    if username.is_empty() {
        return Ok(ProxyRoute::Automatic);
    }

    let Some((kind, value)) = username.split_once(':') else {
        return Err(ProxyRequestError::InvalidSelector);
    };

    if value.is_empty() {
        return Err(ProxyRequestError::InvalidSelector);
    }

    match kind {
        "id" => Ok(ProxyRoute::Select(InstanceSelector::Id(value.to_string()))),
        "exit" => Ok(ProxyRoute::Select(InstanceSelector::ExitIp(
            value.to_string(),
        ))),
        "group" => Ok(ProxyRoute::Select(InstanceSelector::Group(
            value.to_string(),
        ))),
        _ => Err(ProxyRequestError::InvalidSelector),
    }
}
