use crate::public_warp_adapter::PublicWarpAdapterConfig;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::collections::BTreeMap;

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
    instances: BTreeMap<String, PublicWarpAdapterConfig>,
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
                .map(|instance| (instance.instance_id, instance.adapter_config))
                .collect(),
        }
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    pub fn has_instance(&self, instance_id: &str) -> bool {
        self.instances.contains_key(instance_id)
    }

    fn adapter_config(&self, instance_id: &str) -> Result<&PublicWarpAdapterConfig> {
        self.instances
            .get(instance_id)
            .ok_or_else(|| anyhow!("unknown WARP Instance {instance_id}"))
    }
}

#[async_trait]
impl UserSpaceDataPlane for BoringTunDataPlane {
    async fn connect_tcp(&self, target: DataPlaneTarget) -> Result<Box<dyn DataPlaneTcpStream>> {
        self.adapter_config(&target.instance_id)?
            .ensure_supported()
            .map_err(|error| anyhow!(error))?;
        Err(anyhow!(
            "real WireGuard-compatible User-Space Data Plane is not implemented for instance {}",
            target.instance_id
        ))
    }

    async fn open_udp_session(&self, instance_id: String) -> Result<Box<dyn DataPlaneUdpSession>> {
        self.adapter_config(&instance_id)?
            .ensure_supported()
            .map_err(|error| anyhow!(error))?;
        Err(anyhow!(
            "real WireGuard-compatible User-Space Data Plane is not implemented for instance {instance_id}"
        ))
    }

    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse> {
        default_send(self, request).await
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
