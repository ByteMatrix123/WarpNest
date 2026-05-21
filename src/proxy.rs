use crate::{
    config::Config,
    pool::ProxyPool,
    proxy_auth::{AuthConfig, ProxyCredentials, ProxyRequestError, resolve_proxy_request},
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
};

#[derive(Debug)]
pub struct ProxyRuntime {
    socks5: TcpListener,
    http: TcpListener,
    pool: Arc<Mutex<ProxyPool>>,
    auth: AuthConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRuntimeAddrs {
    pub socks5: SocketAddr,
    pub http: SocketAddr,
}

impl ProxyRuntime {
    pub async fn bind(config: &Config, pool: ProxyPool) -> Result<Self> {
        let socks5 = TcpListener::bind(config.listeners.socks5_bind)
            .await
            .context("failed to bind SOCKS5 Proxy Endpoint")?;
        let http = TcpListener::bind(config.listeners.http_bind)
            .await
            .context("failed to bind HTTP Proxy Endpoint")?;
        Ok(Self {
            socks5,
            http,
            pool: Arc::new(Mutex::new(pool)),
            auth: AuthConfig::from_config(&config.auth),
        })
    }

    pub fn local_addrs(&self) -> Result<ProxyRuntimeAddrs> {
        Ok(ProxyRuntimeAddrs {
            socks5: self.socks5.local_addr()?,
            http: self.http.local_addr()?,
        })
    }

    pub async fn serve(self) -> Result<()> {
        let socks5_pool = Arc::clone(&self.pool);
        let socks5_auth = self.auth.clone();
        let socks5 = serve_listener(self.socks5, move |stream| {
            let pool = Arc::clone(&socks5_pool);
            let auth = socks5_auth.clone();
            async move { handle_socks5(stream, pool, auth).await }
        });

        let http_pool = Arc::clone(&self.pool);
        let http_auth = self.auth;
        let http = serve_listener(self.http, move |stream| {
            let pool = Arc::clone(&http_pool);
            let auth = http_auth.clone();
            async move { handle_http(stream, pool, auth).await }
        });

        tokio::try_join!(socks5, http)?;
        Ok(())
    }
}

async fn serve_listener<F, Fut>(listener: TcpListener, handler: F) -> Result<()>
where
    F: Fn(TcpStream) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = handler(stream).await;
        });
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    pool: Arc<Mutex<ProxyPool>>,
    auth: AuthConfig,
) -> Result<()> {
    let version = read_u8(&mut stream).await?;
    if version != 0x05 {
        return Err(anyhow!("invalid SOCKS version"));
    }

    let method_count = read_u8(&mut stream).await?;
    let mut methods = vec![0_u8; method_count as usize];
    stream.read_exact(&mut methods).await?;
    let method = if auth.requires_password() { 0x02 } else { 0x00 };
    if !methods.contains(&method) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    stream.write_all(&[0x05, method]).await?;

    let credentials = if method == 0x02 {
        read_socks5_credentials(&mut stream).await?
    } else {
        ProxyCredentials::new("", "")
    };

    let version = read_u8(&mut stream).await?;
    let command = read_u8(&mut stream).await?;
    let _reserved = read_u8(&mut stream).await?;
    let address_type = read_u8(&mut stream).await?;
    if version != 0x05 || !matches!(command, 0x01 | 0x03) {
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let target_host = read_socks5_host(&mut stream, address_type).await?;
    let target_port = read_u16(&mut stream).await?;

    let resolved = {
        let mut pool = pool.lock().await;
        resolve_proxy_request(&mut pool, &auth, credentials)
    };

    match resolved {
        Ok(lease) if command == 0x01 => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await?;
            let response =
                mock_tcp_response("socks5", &lease.instance_id(), &target_host, target_port);
            stream.write_all(response.as_bytes()).await?;
            drop(lease);
        }
        Ok(lease) => {
            let relay = UdpSocket::bind("127.0.0.1:0").await?;
            let relay_addr = relay.local_addr()?;
            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&reply).await?;

            let instance_id = lease.instance_id();
            let relay_task = tokio::spawn(async move {
                let _ = serve_udp_association(relay, instance_id).await;
            });

            let mut drain = [0_u8; 1];
            loop {
                match stream.read(&mut drain).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            relay_task.abort();
            drop(lease);
        }
        Err(error) => {
            let code = socks5_error_code(error);
            stream
                .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }

    Ok(())
}

async fn serve_udp_association(relay: UdpSocket, instance_id: String) -> Result<()> {
    let mut buffer = vec![0_u8; 2048];
    loop {
        let (len, peer) = relay.recv_from(&mut buffer).await?;
        let Some(packet) = parse_socks5_udp_packet(&buffer[..len]) else {
            continue;
        };
        let response = mock_udp_response(&instance_id, &packet.host, packet.port, packet.payload);
        relay.send_to(response.as_bytes(), peer).await?;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Socks5UdpPacket<'a> {
    host: String,
    port: u16,
    payload: &'a [u8],
}

fn parse_socks5_udp_packet(packet: &[u8]) -> Option<Socks5UdpPacket<'_>> {
    if packet.len() < 7 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }

    match packet[3] {
        0x01 => {
            if packet.len() < 10 {
                return None;
            }
            let host =
                std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]).to_string();
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some(Socks5UdpPacket {
                host,
                port,
                payload: &packet[10..],
            })
        }
        0x03 => {
            let len = *packet.get(4)? as usize;
            let host_start = 5;
            let host_end = host_start + len;
            let port_end = host_end + 2;
            if packet.len() < port_end {
                return None;
            }
            let host = String::from_utf8(packet[host_start..host_end].to_vec()).ok()?;
            let port = u16::from_be_bytes([packet[host_end], packet[host_end + 1]]);
            Some(Socks5UdpPacket {
                host,
                port,
                payload: &packet[port_end..],
            })
        }
        _ => None,
    }
}

async fn read_socks5_credentials(stream: &mut TcpStream) -> Result<ProxyCredentials> {
    let version = read_u8(stream).await?;
    if version != 0x01 {
        return Err(anyhow!("invalid SOCKS5 auth version"));
    }
    let username_len = read_u8(stream).await? as usize;
    let mut username = vec![0_u8; username_len];
    stream.read_exact(&mut username).await?;
    let password_len = read_u8(stream).await? as usize;
    let mut password = vec![0_u8; password_len];
    stream.read_exact(&mut password).await?;
    stream.write_all(&[0x01, 0x00]).await?;
    Ok(ProxyCredentials::new(
        String::from_utf8(username)?,
        String::from_utf8(password)?,
    ))
}

async fn read_socks5_host(stream: &mut TcpStream, address_type: u8) -> Result<String> {
    match address_type {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            Ok(std::net::Ipv4Addr::from(bytes).to_string())
        }
        0x03 => {
            let len = read_u8(stream).await? as usize;
            let mut bytes = vec![0_u8; len];
            stream.read_exact(&mut bytes).await?;
            Ok(String::from_utf8(bytes)?)
        }
        _ => Err(anyhow!("unsupported SOCKS5 address type")),
    }
}

async fn handle_http(
    mut stream: TcpStream,
    pool: Arc<Mutex<ProxyPool>>,
    auth: AuthConfig,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let credentials =
        parse_http_credentials(&request).unwrap_or_else(|| ProxyCredentials::new("", ""));
    let target = parse_http_target(&request).ok_or_else(|| anyhow!("missing HTTP target"))?;

    let resolved = {
        let mut pool = pool.lock().await;
        resolve_proxy_request(&mut pool, &auth, credentials)
    };

    match resolved {
        Ok(lease) => {
            if request.starts_with("CONNECT ") {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let response = mock_tcp_response(
                    "http-connect",
                    &lease.instance_id(),
                    &target.host,
                    target.port,
                );
                stream.write_all(response.as_bytes()).await?;
            } else {
                let body =
                    mock_tcp_response("http", &lease.instance_id(), &target.host, target.port);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await?;
            }
            drop(lease);
        }
        Err(ProxyRequestError::AuthenticationFailed) => {
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\n\r\n",
                )
                .await?;
        }
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                .await?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpTarget {
    host: String,
    port: u16,
}

fn parse_http_target(request: &str) -> Option<HttpTarget> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let uri = parts.next()?;

    if method.eq_ignore_ascii_case("CONNECT") {
        parse_host_port(uri, 443)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        parse_host_port(authority, 80)
    } else {
        request
            .lines()
            .find_map(|line| line.strip_prefix("Host: "))
            .and_then(|host| parse_host_port(host.trim(), 80))
    }
}

fn parse_host_port(value: &str, default_port: u16) -> Option<HttpTarget> {
    if let Some((host, port)) = value.rsplit_once(':') {
        Some(HttpTarget {
            host: host.to_string(),
            port: port.parse().ok()?,
        })
    } else {
        Some(HttpTarget {
            host: value.to_string(),
            port: default_port,
        })
    }
}

fn parse_http_credentials(request: &str) -> Option<ProxyCredentials> {
    let header = request.lines().find_map(|line| {
        line.strip_prefix("Proxy-Authorization: Basic ")
            .or_else(|| line.strip_prefix("proxy-authorization: Basic "))
    })?;
    let decoded = BASE64.decode(header.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.rsplit_once(':')?;
    Some(ProxyCredentials::new(username, password))
}

async fn read_http_request(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn mock_tcp_response(protocol: &str, instance_id: &str, host: &str, port: u16) -> String {
    format!("warpnest mock {protocol} instance={instance_id} target={host}:{port}\n")
}

fn mock_udp_response(instance_id: &str, host: &str, port: u16, payload: &[u8]) -> String {
    format!(
        "warpnest mock udp instance={instance_id} target={host}:{port} bytes={}\n",
        payload.len()
    )
}

fn socks5_error_code(error: ProxyRequestError) -> u8 {
    match error {
        ProxyRequestError::AuthenticationFailed => 0x02,
        ProxyRequestError::InvalidSelector | ProxyRequestError::SelectionFailed(_) => 0x04,
    }
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8> {
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

async fn read_u16(stream: &mut TcpStream) -> Result<u16> {
    let mut bytes = [0_u8; 2];
    stream.read_exact(&mut bytes).await?;
    Ok(u16::from_be_bytes(bytes))
}
