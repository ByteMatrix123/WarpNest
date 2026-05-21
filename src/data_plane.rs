use crate::public_warp_adapter::{
    PUBLIC_WARP_WIREGUARD_OBSERVED_V1, PublicWarpAdapterConfig, PublicWarpAdapterError,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt, net::IpAddr, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneRequest {
    pub protocol: DataPlaneProtocol,
    pub instance_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneResponse {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneTarget {
    pub instance_id: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub target_host: String,
    pub target_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneInstanceConfig {
    pub instance_id: String,
    pub adapter_config: PublicWarpAdapterConfig,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardKey([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerEndpoint {
    host: String,
    port: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BoringTunRuntimeConfig {
    private_key: WireGuardKey,
    interface_addresses: Vec<IpNetwork>,
    peer_public_key: WireGuardKey,
    peer_endpoint: WireGuardPeerEndpoint,
    allowed_ips: Vec<IpNetwork>,
    dns_servers: Vec<IpAddr>,
    device_id: Option<String>,
}

#[async_trait]
pub trait DataPlaneTcpStream: Send {
    fn instance_id(&self) -> &str;
    fn target(&self) -> &DataPlaneTarget;
    async fn write_all(&mut self, payload: &[u8]) -> Result<()>;
    async fn read_once(&mut self) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait DataPlaneUdpSession: Send + Sync {
    fn instance_id(&self) -> &str;
    async fn send_datagram(&self, datagram: UdpDatagram) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait UserSpaceDataPlane: Send + Sync {
    async fn connect_tcp(&self, target: DataPlaneTarget) -> Result<Box<dyn DataPlaneTcpStream>>;

    async fn open_udp_session(&self, instance_id: String) -> Result<Box<dyn DataPlaneUdpSession>>;

    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse>;
}

#[derive(Debug, Default)]
pub struct MockDataPlane;

#[derive(Debug, Default)]
pub struct BoringTunDataPlane {
    instances: BTreeMap<String, DataPlaneInstance>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DataPlaneInstance {
    Lazy(PublicWarpAdapterConfig),
    Prepared(BoringTunRuntimeConfig),
}

#[derive(Debug)]
struct MockTcpStream {
    target: DataPlaneTarget,
    written_bytes: usize,
}

#[derive(Debug)]
struct MockUdpSession {
    instance_id: String,
}

#[async_trait]
impl UserSpaceDataPlane for MockDataPlane {
    async fn connect_tcp(&self, target: DataPlaneTarget) -> Result<Box<dyn DataPlaneTcpStream>> {
        Ok(Box::new(MockTcpStream {
            target,
            written_bytes: 0,
        }))
    }

    async fn open_udp_session(&self, instance_id: String) -> Result<Box<dyn DataPlaneUdpSession>> {
        Ok(Box::new(MockUdpSession { instance_id }))
    }

    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse> {
        default_send(self, request).await
    }
}

#[async_trait]
impl DataPlaneTcpStream for MockTcpStream {
    fn instance_id(&self) -> &str {
        &self.target.instance_id
    }

    fn target(&self) -> &DataPlaneTarget {
        &self.target
    }

    async fn write_all(&mut self, payload: &[u8]) -> Result<()> {
        self.written_bytes += payload.len();
        Ok(())
    }

    async fn read_once(&mut self) -> Result<Vec<u8>> {
        Ok(format!(
            "warpnest mock tcp instance={} target={}:{} bytes={}\n",
            self.target.instance_id, self.target.host, self.target.port, self.written_bytes
        )
        .into_bytes())
    }
}

#[async_trait]
impl DataPlaneUdpSession for MockUdpSession {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    async fn send_datagram(&self, datagram: UdpDatagram) -> Result<Vec<u8>> {
        Ok(format!(
            "warpnest mock udp instance={} target={}:{} bytes={}\n",
            self.instance_id,
            datagram.target_host,
            datagram.target_port,
            datagram.payload.len()
        )
        .into_bytes())
    }
}

impl BoringTunDataPlane {
    pub fn with_instances(instances: impl IntoIterator<Item = DataPlaneInstanceConfig>) -> Self {
        Self {
            instances: instances
                .into_iter()
                .map(|instance| {
                    (
                        instance.instance_id,
                        DataPlaneInstance::Lazy(instance.adapter_config),
                    )
                })
                .collect(),
        }
    }

    pub fn try_with_instances(
        instances: impl IntoIterator<Item = DataPlaneInstanceConfig>,
    ) -> Result<Self, PublicWarpAdapterError> {
        Ok(Self {
            instances: instances
                .into_iter()
                .map(|instance| {
                    let runtime_config =
                        BoringTunRuntimeConfig::from_adapter_config(&instance.adapter_config)?;
                    Ok((
                        instance.instance_id,
                        DataPlaneInstance::Prepared(runtime_config),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, PublicWarpAdapterError>>()?,
        })
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    pub fn has_instance(&self, instance_id: &str) -> bool {
        self.instances.contains_key(instance_id)
    }

    pub fn runtime_config(&self, instance_id: &str) -> Result<&BoringTunRuntimeConfig> {
        match self.instance(instance_id)? {
            DataPlaneInstance::Prepared(runtime_config) => Ok(runtime_config),
            DataPlaneInstance::Lazy(adapter_config) => Err(anyhow!(
                "BoringTun runtime config is not prepared for Public WARP Adapter {} v{}",
                adapter_config.kind,
                adapter_config.version
            )),
        }
    }

    fn instance(&self, instance_id: &str) -> Result<&DataPlaneInstance> {
        self.instances
            .get(instance_id)
            .ok_or_else(|| anyhow!("unknown WARP Instance {instance_id}"))
    }

    fn ensure_instance_is_serviceable(&self, instance_id: &str) -> Result<()> {
        match self.instance(instance_id)? {
            DataPlaneInstance::Lazy(adapter_config) => adapter_config
                .ensure_supported()
                .map_err(|error| anyhow!(error)),
            DataPlaneInstance::Prepared(_) => Ok(()),
        }
    }
}

impl BoringTunRuntimeConfig {
    fn from_adapter_config(
        adapter_config: &PublicWarpAdapterConfig,
    ) -> Result<Self, PublicWarpAdapterError> {
        adapter_config.ensure_supported()?;

        if (adapter_config.kind.as_str(), adapter_config.version)
            != (PUBLIC_WARP_WIREGUARD_OBSERVED_V1, 1)
        {
            return Err(PublicWarpAdapterError::UnsupportedAdapter {
                kind: adapter_config.kind.clone(),
                version: adapter_config.version,
            });
        }

        let normalized: NormalizedWireGuardRuntimeConfig =
            serde_json::from_str(adapter_config.config_json()).map_err(|error| {
                unsupported_adapter_config(
                    adapter_config,
                    format!("normalized config JSON is malformed: {error}"),
                )
            })?;

        Ok(Self {
            private_key: parse_wireguard_key(
                adapter_config,
                "private_key",
                normalized.private_key,
            )?,
            interface_addresses: parse_ip_networks(
                adapter_config,
                "interface_addresses",
                normalized.interface_addresses,
            )?,
            peer_public_key: parse_wireguard_key(
                adapter_config,
                "peer_public_key",
                normalized.peer_public_key,
            )?,
            peer_endpoint: parse_peer_endpoint(adapter_config, normalized.peer_endpoint)?,
            allowed_ips: parse_ip_networks(adapter_config, "allowed_ips", normalized.allowed_ips)?,
            dns_servers: parse_ip_addresses(adapter_config, "dns_servers", normalized.dns_servers)?,
            device_id: normalized.device_id.and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }),
        })
    }

    pub fn private_key(&self) -> &WireGuardKey {
        &self.private_key
    }

    pub fn interface_addresses(&self) -> &[IpNetwork] {
        &self.interface_addresses
    }

    pub fn peer_public_key(&self) -> &WireGuardKey {
        &self.peer_public_key
    }

    pub fn peer_endpoint(&self) -> &WireGuardPeerEndpoint {
        &self.peer_endpoint
    }

    pub fn allowed_ips(&self) -> &[IpNetwork] {
        &self.allowed_ips
    }

    pub fn dns_servers(&self) -> &[IpAddr] {
        &self.dns_servers
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }
}

impl WireGuardKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl IpNetwork {
    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl WireGuardPeerEndpoint {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl FromStr for IpNetwork {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| "missing CIDR prefix length".to_string())?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid IP address: {error}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|error| format!("invalid CIDR prefix length: {error}"))?;
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "CIDR prefix length {prefix_len} exceeds maximum {max_prefix}"
            ));
        }

        Ok(Self {
            address,
            prefix_len,
        })
    }
}

impl fmt::Debug for WireGuardKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl fmt::Debug for BoringTunRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoringTunRuntimeConfig")
            .field("private_key", &self.private_key)
            .field("interface_addresses", &self.interface_addresses)
            .field("peer_public_key", &self.peer_public_key)
            .field("peer_endpoint", &self.peer_endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("dns_servers", &self.dns_servers)
            .field("device_id", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct NormalizedWireGuardRuntimeConfig {
    private_key: String,
    interface_addresses: Vec<String>,
    peer_public_key: String,
    peer_endpoint: String,
    allowed_ips: Vec<String>,
    dns_servers: Vec<String>,
    #[serde(default)]
    device_id: Option<String>,
}

#[async_trait]
impl UserSpaceDataPlane for BoringTunDataPlane {
    async fn connect_tcp(&self, target: DataPlaneTarget) -> Result<Box<dyn DataPlaneTcpStream>> {
        self.ensure_instance_is_serviceable(&target.instance_id)?;
        Err(anyhow!(
            "real WireGuard-compatible User-Space Data Plane is not implemented for instance {}",
            target.instance_id
        ))
    }

    async fn open_udp_session(&self, instance_id: String) -> Result<Box<dyn DataPlaneUdpSession>> {
        self.ensure_instance_is_serviceable(&instance_id)?;
        Err(anyhow!(
            "real WireGuard-compatible User-Space Data Plane is not implemented for instance {instance_id}"
        ))
    }

    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse> {
        default_send(self, request).await
    }
}

fn parse_wireguard_key(
    adapter_config: &PublicWarpAdapterConfig,
    field: &str,
    value: String,
) -> Result<WireGuardKey, PublicWarpAdapterError> {
    let trimmed = reject_empty_string(adapter_config, field, value)?;
    let decoded = BASE64.decode(trimmed.as_bytes()).map_err(|error| {
        unsupported_adapter_config(
            adapter_config,
            format!("{field} is not valid base64: {error}"),
        )
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        unsupported_adapter_config(
            adapter_config,
            format!("{field} must decode to 32 bytes, got {}", decoded.len()),
        )
    })?;

    Ok(WireGuardKey(bytes))
}

fn parse_ip_networks(
    adapter_config: &PublicWarpAdapterConfig,
    field: &str,
    values: Vec<String>,
) -> Result<Vec<IpNetwork>, PublicWarpAdapterError> {
    reject_empty_list(adapter_config, field, &values)?;
    values
        .into_iter()
        .map(|value| {
            let trimmed = reject_empty_string(adapter_config, field, value)?;
            trimmed.parse::<IpNetwork>().map_err(|error| {
                unsupported_adapter_config(adapter_config, format!("{field} contains {error}"))
            })
        })
        .collect()
}

fn parse_ip_addresses(
    adapter_config: &PublicWarpAdapterConfig,
    field: &str,
    values: Vec<String>,
) -> Result<Vec<IpAddr>, PublicWarpAdapterError> {
    reject_empty_list(adapter_config, field, &values)?;
    values
        .into_iter()
        .map(|value| {
            let trimmed = reject_empty_string(adapter_config, field, value)?;
            trimmed.parse::<IpAddr>().map_err(|error| {
                unsupported_adapter_config(adapter_config, format!("{field} contains {error}"))
            })
        })
        .collect()
}

fn parse_peer_endpoint(
    adapter_config: &PublicWarpAdapterConfig,
    value: String,
) -> Result<WireGuardPeerEndpoint, PublicWarpAdapterError> {
    let trimmed = reject_empty_string(adapter_config, "peer_endpoint", value)?;
    let (host, port) = if let Some(without_brackets) = trimmed.strip_prefix('[') {
        let (host, rest) = without_brackets.split_once(']').ok_or_else(|| {
            unsupported_adapter_config(
                adapter_config,
                "peer_endpoint has an unterminated IPv6 host literal",
            )
        })?;
        let port = rest.strip_prefix(':').ok_or_else(|| {
            unsupported_adapter_config(adapter_config, "peer_endpoint is missing a UDP port")
        })?;
        (host, port)
    } else {
        trimmed.rsplit_once(':').ok_or_else(|| {
            unsupported_adapter_config(adapter_config, "peer_endpoint is missing a UDP port")
        })?
    };
    let host = host.trim();
    if host.is_empty() {
        return Err(unsupported_adapter_config(
            adapter_config,
            "peer_endpoint host must not be empty",
        ));
    }
    let port = port.trim().parse::<u16>().map_err(|error| {
        unsupported_adapter_config(
            adapter_config,
            format!("peer_endpoint has an invalid UDP port: {error}"),
        )
    })?;
    if port == 0 {
        return Err(unsupported_adapter_config(
            adapter_config,
            "peer_endpoint UDP port must not be 0",
        ));
    }

    Ok(WireGuardPeerEndpoint {
        host: host.to_string(),
        port,
    })
}

fn reject_empty_string(
    adapter_config: &PublicWarpAdapterConfig,
    field: &str,
    value: String,
) -> Result<String, PublicWarpAdapterError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(unsupported_adapter_config(
            adapter_config,
            format!("{field} must not be empty"),
        ));
    }
    Ok(trimmed.to_string())
}

fn reject_empty_list(
    adapter_config: &PublicWarpAdapterConfig,
    field: &str,
    values: &[String],
) -> Result<(), PublicWarpAdapterError> {
    if values.is_empty() {
        return Err(unsupported_adapter_config(
            adapter_config,
            format!("{field} must contain at least one value"),
        ));
    }
    Ok(())
}

fn unsupported_adapter_config(
    adapter_config: &PublicWarpAdapterConfig,
    reason: impl Into<String>,
) -> PublicWarpAdapterError {
    PublicWarpAdapterError::UnsupportedAdapterConfig {
        kind: adapter_config.kind.clone(),
        version: adapter_config.version,
        reason: reason.into(),
    }
}

async fn default_send(
    data_plane: &(dyn UserSpaceDataPlane + Send + Sync),
    request: DataPlaneRequest,
) -> Result<DataPlaneResponse> {
    match request.protocol {
        DataPlaneProtocol::Tcp => {
            let mut stream = data_plane
                .connect_tcp(DataPlaneTarget {
                    instance_id: request.instance_id,
                    host: request.target_host,
                    port: request.target_port,
                })
                .await?;
            stream.write_all(&request.payload).await?;
            Ok(DataPlaneResponse {
                payload: stream.read_once().await?,
            })
        }
        DataPlaneProtocol::Udp => {
            let session = data_plane.open_udp_session(request.instance_id).await?;
            Ok(DataPlaneResponse {
                payload: session
                    .send_datagram(UdpDatagram {
                        target_host: request.target_host,
                        target_port: request.target_port,
                        payload: request.payload,
                    })
                    .await?,
            })
        }
    }
}
