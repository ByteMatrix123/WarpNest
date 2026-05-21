use crate::status::PoolStatus;
use anyhow::Result;
use axum::{Json, Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug)]
pub struct ManagementServer {
    listener: TcpListener,
    status: PoolStatus,
}

impl ManagementServer {
    pub async fn bind(addr: SocketAddr, status: PoolStatus) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, status })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve(self) -> Result<()> {
        let status = self.status;
        let app = Router::new().route("/status", get(move || async move { Json(status) }));
        axum::serve(self.listener, app).await?;
        Ok(())
    }
}
