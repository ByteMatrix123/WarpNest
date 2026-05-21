use anyhow::Result;
use async_trait::async_trait;

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

#[async_trait]
pub trait UserSpaceDataPlane: Send + Sync {
    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse>;
}

#[derive(Debug, Default)]
pub struct MockDataPlane;

#[derive(Debug, Default)]
pub struct BoringTunDataPlane;

#[async_trait]
impl UserSpaceDataPlane for MockDataPlane {
    async fn send(&self, request: DataPlaneRequest) -> Result<DataPlaneResponse> {
        let protocol = match request.protocol {
            DataPlaneProtocol::Tcp => "tcp",
            DataPlaneProtocol::Udp => "udp",
        };
        Ok(DataPlaneResponse {
            payload: format!(
                "warpnest mock {protocol} instance={} target={}:{} bytes={}\n",
                request.instance_id,
                request.target_host,
                request.target_port,
                request.payload.len()
            )
            .into_bytes(),
        })
    }
}

#[async_trait]
impl UserSpaceDataPlane for BoringTunDataPlane {
    async fn send(&self, _request: DataPlaneRequest) -> Result<DataPlaneResponse> {
        anyhow::bail!(
            "real WARP User-Space Data Plane is not configured; BoringTun adapter boundary is present"
        )
    }
}
