use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use warpnest::{
    config::{AuthConfig as RuntimeAuthConfig, Config, ListenerConfig},
    data_plane::{BoringTunDataPlane, DataPlaneInstanceConfig},
    direct_public_warp_registration::WarpKeyPair,
    pool::{PoolConfig, ProxyPool},
    proxy::ProxyRuntime,
    public_warp_adapter::PublicWarpAdapterConfig,
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
};

#[tokio::test]
async fn socks5_udp_association_routes_dns_shaped_payload_through_selected_instance() {
    let runtime = bind_runtime("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut control = TcpStream::connect(addrs.socks5).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_exact(&mut control, 2).await, vec![0x05, 0x02]);
    write_socks5_auth(&mut control, "id:serving-b", "secret").await;
    assert_eq!(read_exact(&mut control, 2).await, vec![0x01, 0x00]);
    write_udp_associate(&mut control).await;

    let reply = read_exact(&mut control, 10).await;
    assert_eq!(reply[1], 0x00);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet("dns.example.test", 53, b"\x12\x34\x01\x00mock-dns");
    socket
        .send_to(&packet, ("127.0.0.1", relay_port))
        .await
        .unwrap();

    let mut response = vec![0_u8; 512];
    let (len, _) = socket.recv_from(&mut response).await.unwrap();
    let text = String::from_utf8(response[..len].to_vec()).unwrap();

    assert!(text.contains("warpnest mock udp"));
    assert!(text.contains("instance=serving-b"));
    assert!(text.contains("target=dns.example.test:53"));

    drop(control);
    handle.abort();
}

#[tokio::test]
async fn socks5_udp_association_rejects_bad_authentication() {
    let runtime = bind_runtime("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut control = TcpStream::connect(addrs.socks5).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_exact(&mut control, 2).await, vec![0x05, 0x02]);
    write_socks5_auth(&mut control, "id:serving-b", "wrong").await;
    assert_eq!(read_exact(&mut control, 2).await, vec![0x01, 0x00]);
    write_udp_associate(&mut control).await;

    let reply = read_exact(&mut control, 10).await;
    assert_ne!(reply[1], 0x00);

    handle.abort();
}

#[tokio::test]
async fn socks5_udp_association_can_use_prepared_real_runtime_boundary() {
    let runtime = bind_runtime_with_real_data_plane("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut control = TcpStream::connect(addrs.socks5).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_exact(&mut control, 2).await, vec![0x05, 0x02]);
    write_socks5_auth(&mut control, "id:serving-b", "secret").await;
    assert_eq!(read_exact(&mut control, 2).await, vec![0x01, 0x00]);
    write_udp_associate(&mut control).await;

    let reply = read_exact(&mut control, 10).await;
    assert_eq!(reply[1], 0x00);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet("runtime-dns.example.test", 53, b"\x12\x34\x01\x00mock-dns");
    socket
        .send_to(&packet, ("127.0.0.1", relay_port))
        .await
        .unwrap();

    let mut response = vec![0_u8; 512];
    let (len, _) = socket.recv_from(&mut response).await.unwrap();
    let text = String::from_utf8(response[..len].to_vec()).unwrap();

    assert!(text.contains("warpnest runtime udp"));
    assert!(text.contains("instance=serving-b"));
    assert!(text.contains("target=runtime-dns.example.test:53"));

    drop(control);
    handle.abort();
}

async fn bind_runtime(shared_secret: &str) -> ProxyRuntime {
    let config = Config {
        target_serving_size: 2,
        registration_budget: 4,
        state_store_path: "unused.sqlite".to_string(),
        listeners: ListenerConfig {
            management_bind: "127.0.0.1:0".parse().unwrap(),
            socks5_bind: "127.0.0.1:0".parse().unwrap(),
            http_bind: "127.0.0.1:0".parse().unwrap(),
        },
        auth: RuntimeAuthConfig {
            shared_secret: shared_secret.to_string(),
        },
    };
    let pool = ProxyPool::from_instances(
        PoolConfig::new(2, 4),
        vec![
            instance("serving-a", "default", "198.51.100.1"),
            instance("serving-b", "api", "198.51.100.2"),
        ],
    );
    ProxyRuntime::bind(&config, pool).await.unwrap()
}

async fn bind_runtime_with_real_data_plane(shared_secret: &str) -> ProxyRuntime {
    let runtime = bind_runtime(shared_secret).await;
    runtime.with_data_plane(Arc::new(
        BoringTunDataPlane::try_with_instances([
            runtime_instance_config("serving-a", 41),
            runtime_instance_config("serving-b", 42),
        ])
        .unwrap(),
    ))
}

fn instance(id: &str, group: &str, exit_ip: &str) -> StoredWarpInstance {
    let mut instance = StoredWarpInstance::new_mock(
        group,
        Some(exit_ip),
        PoolMembershipPreference::Standby,
        InstanceLifecycleState::Registered,
        format!("secret-{id}"),
    );
    instance.instance_id = id.to_string();
    instance
}

fn runtime_instance_config(instance_id: &str, key_seed: u8) -> DataPlaneInstanceConfig {
    DataPlaneInstanceConfig {
        instance_id: instance_id.to_string(),
        adapter_config: PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(
            serde_json::json!({
                "private_key": WarpKeyPair::from_private_key_bytes([key_seed; 32]).private_key_base64(),
                "interface_addresses": ["172.16.0.2/32"],
                "peer_public_key": WarpKeyPair::from_private_key_bytes([key_seed + 1; 32]).public_key_base64(),
                "peer_endpoint": "engage.cloudflareclient.com:2408",
                "allowed_ips": ["0.0.0.0/0"],
                "dns_servers": ["1.1.1.1"],
                "device_id": format!("fixture-{instance_id}"),
            }),
        )
        .unwrap(),
    }
}

async fn write_socks5_auth(stream: &mut TcpStream, username: &str, password: &str) {
    let mut bytes = vec![0x01, username.len() as u8];
    bytes.extend_from_slice(username.as_bytes());
    bytes.push(password.len() as u8);
    bytes.extend_from_slice(password.as_bytes());
    stream.write_all(&bytes).await.unwrap();
}

async fn write_udp_associate(stream: &mut TcpStream) {
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
}

fn udp_packet(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00, 0x03, host.len() as u8];
    packet.extend_from_slice(host.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn read_exact(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}
