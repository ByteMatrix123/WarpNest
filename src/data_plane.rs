use crate::public_warp_adapter::{
    PUBLIC_WARP_WIREGUARD_OBSERVED_V1, PublicWarpAdapterConfig, PublicWarpAdapterError,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519,
};
use serde::Deserialize;
use smoltcp::{
    iface::{Config as SmoltcpConfig, Interface, SocketSet},
    phy::{Device, Loopback, Medium, RxToken, TxToken},
    time::Instant as SmoltcpInstant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fmt,
    net::IpAddr,
    str::FromStr,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLifecycleState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTransportEvent {
    SentToPeer(Vec<u8>),
    DeliveredToStack(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePumpReport {
    pub outbound_packets: usize,
    pub inbound_packets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimePacketPumpError {
    AlreadyRunning,
    NotRunning,
    TransportFailed(String),
    PacketEngineFailed(String),
}

pub struct RuntimePacketPump {
    runtime_config: BoringTunRuntimeConfig,
    lifecycle_state: RuntimeLifecycleState,
    packet_engine: RuntimePacketEngine,
    stack: RuntimeStack,
    transport: TestRuntimeTransport,
    inbound_wireguard_packets: VecDeque<Vec<u8>>,
    last_error: Option<String>,
}

enum RuntimePacketEngine {
    Fake(FakeWireGuardPacketEngine),
    BoringTun(Box<Tunn>),
}

#[derive(Debug, Default)]
struct FakeWireGuardPacketEngine;

struct RuntimeStack {
    interface: Interface,
    device: Loopback,
    delivered_packets: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct TestRuntimeTransport {
    events: Vec<RuntimeTransportEvent>,
    fail_next_send: Option<String>,
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

    pub fn runtime_packet_pump(&self, instance_id: &str) -> Result<RuntimePacketPump> {
        Ok(RuntimePacketPump::boringtun(
            self.runtime_config(instance_id)?.clone(),
        ))
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

impl RuntimePacketPump {
    pub fn test(runtime_config: BoringTunRuntimeConfig) -> Self {
        Self::with_packet_engine(
            runtime_config,
            RuntimePacketEngine::Fake(Default::default()),
        )
    }

    pub fn boringtun(runtime_config: BoringTunRuntimeConfig) -> Self {
        Self::with_packet_engine(
            runtime_config.clone(),
            RuntimePacketEngine::BoringTun(Box::new(create_boringtun_engine(&runtime_config))),
        )
    }

    fn with_packet_engine(
        runtime_config: BoringTunRuntimeConfig,
        packet_engine: RuntimePacketEngine,
    ) -> Self {
        Self {
            stack: RuntimeStack::new(&runtime_config),
            runtime_config,
            lifecycle_state: RuntimeLifecycleState::Stopped,
            packet_engine,
            transport: TestRuntimeTransport::default(),
            inbound_wireguard_packets: VecDeque::new(),
            last_error: None,
        }
    }

    pub fn start(&mut self) -> Result<(), RuntimePacketPumpError> {
        if self.lifecycle_state == RuntimeLifecycleState::Running {
            self.fail(RuntimePacketPumpError::AlreadyRunning)?;
        }

        self.lifecycle_state = RuntimeLifecycleState::Running;
        self.last_error = None;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), RuntimePacketPumpError> {
        if self.lifecycle_state != RuntimeLifecycleState::Running {
            self.lifecycle_state = RuntimeLifecycleState::Stopped;
            return Ok(());
        }

        self.lifecycle_state = RuntimeLifecycleState::Stopped;
        Ok(())
    }

    pub fn lifecycle(&self) -> RuntimeLifecycleState {
        self.lifecycle_state
    }

    pub fn lifecycle_state(&self) -> &'static str {
        match self.lifecycle_state {
            RuntimeLifecycleState::Stopped => "stopped",
            RuntimeLifecycleState::Running => "running",
            RuntimeLifecycleState::Failed => "failed",
        }
    }

    pub fn runtime_config(&self) -> &BoringTunRuntimeConfig {
        &self.runtime_config
    }

    pub fn queue_outbound_ip_packet(&mut self, packet: Vec<u8>) {
        self.stack.queue_outbound_packet(packet);
    }

    pub fn queue_inbound_wireguard_packet(&mut self, packet: Vec<u8>) {
        self.inbound_wireguard_packets.push_back(packet);
    }

    pub fn pump_once(&mut self) -> Result<RuntimePumpReport, RuntimePacketPumpError> {
        if self.lifecycle_state != RuntimeLifecycleState::Running {
            self.fail(RuntimePacketPumpError::NotRunning)?;
        }

        let mut outbound_packets = 0;
        let mut inbound_packets = 0;

        while let Some(packet) = self.stack.next_outbound_packet() {
            let datagram = match self.packet_engine.encapsulate(&packet) {
                Ok(datagram) => datagram,
                Err(error) => return self.fail(error),
            };
            if let Err(error) = self.transport.send_to_peer(datagram) {
                return self.fail(error);
            }
            outbound_packets += 1;
        }

        while let Some(packet) = self.inbound_wireguard_packets.pop_front() {
            let ip_packet = match self.packet_engine.decapsulate(&packet) {
                Ok(ip_packet) => ip_packet,
                Err(error) => return self.fail(error),
            };
            self.stack.deliver_from_wireguard(ip_packet.clone());
            self.transport.deliver_to_stack(ip_packet);
            inbound_packets += 1;
        }

        Ok(RuntimePumpReport {
            outbound_packets,
            inbound_packets,
        })
    }

    pub fn transport_events(&self) -> &[RuntimeTransportEvent] {
        &self.transport.events
    }

    pub fn delivered_stack_packets(&self) -> &[Vec<u8>] {
        &self.stack.delivered_packets
    }

    pub fn fail_next_transport_send(&mut self, reason: impl Into<String>) {
        self.transport.fail_next_send = Some(reason.into());
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn fail<T>(&mut self, error: RuntimePacketPumpError) -> Result<T, RuntimePacketPumpError> {
        self.lifecycle_state = RuntimeLifecycleState::Failed;
        self.last_error = Some(error.to_string());
        Err(error)
    }
}

impl RuntimePacketEngine {
    fn encapsulate(&mut self, packet: &[u8]) -> Result<Vec<u8>, RuntimePacketPumpError> {
        match self {
            Self::Fake(engine) => engine.encapsulate(packet),
            Self::BoringTun(tunn) => {
                let mut dst = vec![0_u8; packet.len().saturating_add(256).max(2048)];
                match tunn.encapsulate(packet, &mut dst) {
                    TunnResult::WriteToNetwork(datagram) => Ok(datagram.to_vec()),
                    TunnResult::Done => Ok(Vec::new()),
                    TunnResult::Err(error) => Err(RuntimePacketPumpError::PacketEngineFailed(
                        format!("{error:?}"),
                    )),
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        Err(RuntimePacketPumpError::PacketEngineFailed(
                            "unexpected tunnel packet while encapsulating outbound IP packet"
                                .to_string(),
                        ))
                    }
                }
            }
        }
    }

    fn decapsulate(&mut self, packet: &[u8]) -> Result<Vec<u8>, RuntimePacketPumpError> {
        match self {
            Self::Fake(engine) => engine.decapsulate(packet),
            Self::BoringTun(tunn) => {
                let mut dst = vec![0_u8; packet.len().saturating_add(256).max(2048)];
                match tunn.decapsulate(None, packet, &mut dst) {
                    TunnResult::WriteToTunnelV4(ip_packet, _)
                    | TunnResult::WriteToTunnelV6(ip_packet, _) => Ok(ip_packet.to_vec()),
                    TunnResult::Done => Ok(Vec::new()),
                    TunnResult::Err(error) => Err(RuntimePacketPumpError::PacketEngineFailed(
                        format!("{error:?}"),
                    )),
                    TunnResult::WriteToNetwork(datagram) => Ok(datagram.to_vec()),
                }
            }
        }
    }
}

impl FakeWireGuardPacketEngine {
    fn encapsulate(&mut self, packet: &[u8]) -> Result<Vec<u8>, RuntimePacketPumpError> {
        Ok(packet.to_vec())
    }

    fn decapsulate(&mut self, packet: &[u8]) -> Result<Vec<u8>, RuntimePacketPumpError> {
        Ok(packet.to_vec())
    }
}

impl RuntimeStack {
    fn new(runtime_config: &BoringTunRuntimeConfig) -> Self {
        let mut device = Loopback::new(Medium::Ip);
        let mut interface = Interface::new(
            SmoltcpConfig::new(HardwareAddress::Ip),
            &mut device,
            SmoltcpInstant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            for address in runtime_config.interface_addresses() {
                let cidr = IpCidr::new(IpAddress::from(address.address()), address.prefix_len());
                let _ = addresses.push(cidr);
            }
        });

        Self {
            interface,
            device,
            delivered_packets: Vec::new(),
        }
    }

    fn deliver_from_wireguard(&mut self, packet: Vec<u8>) {
        if let Some(token) = self.device.transmit(SmoltcpInstant::ZERO) {
            token.consume(packet.len(), |buffer| buffer.copy_from_slice(&packet));
        }
        if let Some((rx, _tx)) = self.device.receive(SmoltcpInstant::ZERO) {
            self.delivered_packets
                .push(rx.consume(|buffer| buffer.to_vec()));
        }
        let mut sockets = SocketSet::new(Vec::new());
        let _ = self
            .interface
            .poll(SmoltcpInstant::ZERO, &mut self.device, &mut sockets);
    }

    fn queue_outbound_packet(&mut self, packet: Vec<u8>) {
        if let Some(token) = self.device.transmit(SmoltcpInstant::ZERO) {
            token.consume(packet.len(), |buffer| buffer.copy_from_slice(&packet));
        }
    }

    fn next_outbound_packet(&mut self) -> Option<Vec<u8>> {
        self.device
            .receive(SmoltcpInstant::ZERO)
            .map(|(rx, _tx)| rx.consume(|buffer| buffer.to_vec()))
    }
}

impl TestRuntimeTransport {
    fn send_to_peer(&mut self, packet: Vec<u8>) -> Result<(), RuntimePacketPumpError> {
        if let Some(reason) = self.fail_next_send.take() {
            return Err(RuntimePacketPumpError::TransportFailed(
                redact_sensitive_text(&reason),
            ));
        }
        self.events.push(RuntimeTransportEvent::SentToPeer(packet));
        Ok(())
    }

    fn deliver_to_stack(&mut self, packet: Vec<u8>) {
        self.events
            .push(RuntimeTransportEvent::DeliveredToStack(packet));
    }
}

impl fmt::Display for RuntimePacketPumpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => write!(formatter, "WARP Connection runtime is already running"),
            Self::NotRunning => write!(formatter, "WARP Connection runtime is not running"),
            Self::TransportFailed(reason) => {
                write!(
                    formatter,
                    "WARP Connection runtime transport failed: {reason}"
                )
            }
            Self::PacketEngineFailed(reason) => {
                write!(
                    formatter,
                    "WARP Connection runtime packet engine failed: {reason}"
                )
            }
        }
    }
}

impl Error for RuntimePacketPumpError {}

impl fmt::Debug for RuntimePacketPump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePacketPump")
            .field("runtime_config", &self.runtime_config)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("last_error", &self.last_error)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RuntimePacketEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fake(_) => formatter.write_str("FakeWireGuardPacketEngine"),
            Self::BoringTun(_) => formatter.write_str("BoringTunPacketEngine"),
        }
    }
}

impl fmt::Debug for RuntimeStack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeStack")
            .field("delivered_packets", &self.delivered_packets.len())
            .finish_non_exhaustive()
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

fn create_boringtun_engine(runtime_config: &BoringTunRuntimeConfig) -> Tunn {
    Tunn::new(
        x25519::StaticSecret::from(*runtime_config.private_key().as_bytes()),
        x25519::PublicKey::from(*runtime_config.peer_public_key().as_bytes()),
        None,
        None,
        0,
        None,
    )
}

fn redact_sensitive_text(value: &str) -> String {
    if value.trim().is_empty() {
        "operation failed".to_string()
    } else {
        value
            .split_whitespace()
            .map(|token| {
                if token.starts_with("private_key=") || token.starts_with("peer_public_key=") {
                    "[redacted]".to_string()
                } else {
                    token.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
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
