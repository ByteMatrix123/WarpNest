use crate::{
    public_warp_adapter::PublicWarpAdapterConfig,
    warp_lifecycle::{
        PublicRegistration, PublicRegistrationRequest, RegistrationClient, RegistrationError,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};
use std::{collections::HashMap, env, fmt, time::SystemTime};
use x25519_dalek::{PublicKey, StaticSecret};

const API_BASE_URL: &str = "https://api.cloudflareclient.com";
const API_VERSION: &str = "v0a1922";
const USER_AGENT: &str = "okhttp/3.12.1";
const CF_CLIENT_VERSION: &str = "a-6.3-1922";
const DEFAULT_LOCALE: &str = "en_US";
const DEFAULT_MODEL: &str = "PC";

#[derive(Clone, PartialEq, Eq)]
pub struct WarpKeyPair {
    private_key_base64: String,
    public_key_base64: String,
}

#[derive(Debug, Clone)]
pub struct OsWarpKeySource;

#[derive(Debug, Clone)]
pub struct FixedWarpKeySource {
    key_pair: WarpKeyPair,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DirectRegistrationHttpRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DirectRegistrationHttpResponse {
    pub status: u16,
    pub body: Value,
}

pub trait DirectRegistrationHttpTransport {
    fn send(
        &self,
        request: DirectRegistrationHttpRequest,
    ) -> Result<DirectRegistrationHttpResponse, String>;
}

pub trait WarpKeySource {
    fn next_key_pair(&mut self) -> Result<WarpKeyPair, RegistrationError>;
}

pub struct DirectPublicWarpRegistrationClient<T, K = OsWarpKeySource> {
    transport: T,
    key_source: K,
}

#[derive(Debug, Clone)]
pub struct ReqwestDirectRegistrationHttpTransport {
    client: reqwest::blocking::Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicWarpIntegrationGate {
    pub run_warp_integration: bool,
    pub accept_public_warp_compat_risk: bool,
}

impl WarpKeyPair {
    pub fn generate() -> Result<Self, RegistrationError> {
        let mut private_key = [0u8; 32];
        getrandom::fill(&mut private_key).map_err(|error| {
            RegistrationError::Transient(format!(
                "failed to generate WireGuard private key material: {error}"
            ))
        })?;
        Ok(Self::from_private_key_bytes(private_key))
    }

    pub fn from_private_key_bytes(private_key_bytes: [u8; 32]) -> Self {
        let private_key_bytes = clamp_wireguard_private_key(private_key_bytes);
        let private_secret = StaticSecret::from(private_key_bytes);
        let public_key = PublicKey::from(&private_secret);

        Self {
            private_key_base64: BASE64.encode(private_key_bytes),
            public_key_base64: BASE64.encode(public_key.to_bytes()),
        }
    }

    pub fn private_key_base64(&self) -> &str {
        &self.private_key_base64
    }

    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }
}

impl FixedWarpKeySource {
    pub fn new(key_pair: WarpKeyPair) -> Self {
        Self { key_pair }
    }
}

impl WarpKeySource for OsWarpKeySource {
    fn next_key_pair(&mut self) -> Result<WarpKeyPair, RegistrationError> {
        WarpKeyPair::generate()
    }
}

impl WarpKeySource for FixedWarpKeySource {
    fn next_key_pair(&mut self) -> Result<WarpKeyPair, RegistrationError> {
        Ok(self.key_pair.clone())
    }
}

impl<T> DirectPublicWarpRegistrationClient<T, FixedWarpKeySource> {
    pub fn new(transport: T, key_pair: WarpKeyPair) -> Self {
        Self {
            transport,
            key_source: FixedWarpKeySource::new(key_pair),
        }
    }
}

impl<T, K> DirectPublicWarpRegistrationClient<T, K> {
    pub fn with_key_source(transport: T, key_source: K) -> Self {
        Self {
            transport,
            key_source,
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl DirectPublicWarpRegistrationClient<ReqwestDirectRegistrationHttpTransport, OsWarpKeySource> {
    pub fn real() -> Result<Self, RegistrationError> {
        Ok(Self::with_key_source(
            ReqwestDirectRegistrationHttpTransport::new()?,
            OsWarpKeySource,
        ))
    }
}

impl ReqwestDirectRegistrationHttpTransport {
    pub fn new() -> Result<Self, RegistrationError> {
        let client = reqwest::blocking::Client::builder()
            .http1_only()
            .tls_version_min(reqwest::tls::Version::TLS_1_2)
            .tls_version_max(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|error| {
                RegistrationError::Unsupported(format!(
                    "failed to configure Public WARP registration HTTP client: {error}"
                ))
            })?;

        Ok(Self { client })
    }
}

impl DirectRegistrationHttpTransport for ReqwestDirectRegistrationHttpTransport {
    fn send(
        &self,
        request: DirectRegistrationHttpRequest,
    ) -> Result<DirectRegistrationHttpResponse, String> {
        let mut builder = self.client.post(&request.url);
        for (header, value) in request.headers {
            builder = builder.header(header, value);
        }

        let response = builder
            .json(&request.body)
            .send()
            .map_err(|error| format!("Public WARP registration request failed: {error}"))?;
        let status = response.status().as_u16();
        let body = response
            .json::<Value>()
            .map_err(|error| format!("Public WARP registration response was not JSON: {error}"))?;

        Ok(DirectRegistrationHttpResponse { status, body })
    }
}

impl PublicWarpIntegrationGate {
    pub fn from_env() -> Self {
        Self {
            run_warp_integration: env_flag("WARPNEST_RUN_WARP_INTEGRATION"),
            accept_public_warp_compat_risk: env_flag("WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK"),
        }
    }

    pub fn is_enabled(self) -> bool {
        self.run_warp_integration && self.accept_public_warp_compat_risk
    }

    pub fn skip_reason(self) -> Option<&'static str> {
        if self.is_enabled() {
            None
        } else {
            Some(
                "set WARPNEST_RUN_WARP_INTEGRATION=1 and WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1",
            )
        }
    }
}

impl<T, K> RegistrationClient for DirectPublicWarpRegistrationClient<T, K>
where
    T: DirectRegistrationHttpTransport,
    K: WarpKeySource,
{
    fn create_public_registration(
        &mut self,
        _request: &PublicRegistrationRequest,
    ) -> Result<PublicRegistration, RegistrationError> {
        let key_pair = self.key_source.next_key_pair()?;
        let request = DirectRegistrationHttpRequest {
            url: format!("{API_BASE_URL}/{API_VERSION}/reg"),
            headers: compatibility_headers(),
            body: registration_request_body(&key_pair),
        };
        let response = self
            .transport
            .send(request)
            .map_err(RegistrationError::Transient)?;
        classify_status(response.status, &response.body)?;

        let adapter_config = normalize_registration_response(&response.body, &key_pair)?;
        let registration_material = serde_json::to_string(&json!({
            "adapter": "wgcf-derived-public-warp-registration",
            "api_version": API_VERSION,
            "response": response.body,
        }))
        .map_err(|error| {
            RegistrationError::Unsupported(format!(
                "failed to preserve Public WARP registration material: {error}"
            ))
        })?;

        Ok(PublicRegistration {
            registration_material,
            adapter_config,
        })
    }
}

impl<T, K> fmt::Debug for DirectPublicWarpRegistrationClient<T, K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectPublicWarpRegistrationClient")
            .field("transport", &"DirectRegistrationHttpTransport")
            .field("key_source", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for WarpKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WarpKeyPair")
            .field("private_key", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for DirectRegistrationHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectRegistrationHttpRequest")
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for DirectRegistrationHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectRegistrationHttpResponse")
            .field("status", &self.status)
            .field("body", &"[redacted]")
            .finish()
    }
}

fn compatibility_headers() -> HashMap<String, String> {
    HashMap::from([
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        (
            "CF-Client-Version".to_string(),
            CF_CLIENT_VERSION.to_string(),
        ),
    ])
}

fn registration_request_body(key_pair: &WarpKeyPair) -> Value {
    json!({
        "fcm_token": "",
        "install_id": "",
        "key": key_pair.public_key_base64(),
        "locale": DEFAULT_LOCALE,
        "model": DEFAULT_MODEL,
        "tos": unix_timestamp_string(),
        "type": "Android",
    })
}

fn unix_timestamp_string() -> String {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn classify_status(status: u16, body: &Value) -> Result<(), RegistrationError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 | 409 | 451 => Err(RegistrationError::Blocked(format!(
            "Public WARP registration rejected with HTTP {status}: {}",
            sanitized_remote_error(body)
        ))),
        400 | 404 | 422 => Err(RegistrationError::Unsupported(format!(
            "Public WARP registration returned unsupported HTTP {status}: {}",
            sanitized_remote_error(body)
        ))),
        408 | 425 | 429 | 500..=599 => Err(RegistrationError::Transient(format!(
            "Public WARP registration returned retryable HTTP {status}: {}",
            sanitized_remote_error(body)
        ))),
        _ => Err(RegistrationError::Transient(format!(
            "Public WARP registration returned HTTP {status}: {}",
            sanitized_remote_error(body)
        ))),
    }
}

fn normalize_registration_response(
    response: &Value,
    key_pair: &WarpKeyPair,
) -> Result<PublicWarpAdapterConfig, RegistrationError> {
    let device_id = required_string(response, &["id"])?;
    let addresses = response
        .pointer("/config/interface/addresses")
        .ok_or_else(|| unsupported_shape("missing config.interface.addresses"))?;
    let v4_address = required_string(addresses, &["v4"])?;
    let v6_address = required_string(addresses, &["v6"])?;
    let first_peer = response
        .pointer("/config/peers/0")
        .ok_or_else(|| unsupported_shape("missing config.peers[0]"))?;
    let peer_public_key = required_string(first_peer, &["public_key"])?;
    let peer_endpoint = required_string(first_peer, &["endpoint", "host"])?;

    PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(json!({
        "private_key": key_pair.private_key_base64(),
        "interface_addresses": [
            format!("{v4_address}/32"),
            format!("{v6_address}/128")
        ],
        "peer_public_key": peer_public_key,
        "peer_endpoint": peer_endpoint,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "dns_servers": [
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001"
        ],
        "device_id": device_id,
    }))
    .map_err(|error| {
        RegistrationError::Unsupported(format!(
            "failed to normalize Public WARP registration response: {error}"
        ))
    })
}

fn required_string(value: &Value, path: &[&str]) -> Result<String, RegistrationError> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor
            .get(*segment)
            .ok_or_else(|| unsupported_shape(format!("missing {}", path.join("."))))?;
    }

    let value = cursor
        .as_str()
        .ok_or_else(|| unsupported_shape(format!("{} must be a string", path.join("."))))?;
    if value.trim().is_empty() {
        return Err(unsupported_shape(format!(
            "{} must not be empty",
            path.join(".")
        )));
    }
    Ok(value.to_string())
}

fn unsupported_shape(reason: impl Into<String>) -> RegistrationError {
    RegistrationError::Unsupported(format!(
        "unsupported Public WARP registration response shape: {}",
        reason.into()
    ))
}

fn sanitized_remote_error(body: &Value) -> String {
    body.get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| body.get("error").and_then(Value::as_str))
        .unwrap_or("remote response omitted a public error message")
        .to_string()
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE"))
}

fn clamp_wireguard_private_key(mut private_key_bytes: [u8; 32]) -> [u8; 32] {
    private_key_bytes[0] &= 248;
    private_key_bytes[31] = (private_key_bytes[31] & 127) | 64;
    private_key_bytes
}
