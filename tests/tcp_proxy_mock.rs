use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use warpnest::{
    config::{AuthConfig as RuntimeAuthConfig, Config, ListenerConfig},
    pool::{PoolConfig, ProxyPool},
    proxy::ProxyRuntime,
    state_store::{InstanceLifecycleState, PoolMembershipPreference, StoredWarpInstance},
};

#[tokio::test]
async fn socks5_tcp_connect_routes_through_selected_mock_instance() {
    let runtime = bind_runtime("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut stream = TcpStream::connect(addrs.socks5).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, vec![0x05, 0x02]);

    write_socks5_auth(&mut stream, "id:standby-a", "secret").await;
    assert_eq!(read_exact(&mut stream, 2).await, vec![0x01, 0x00]);

    write_socks5_connect(&mut stream, "example.test", 443).await;
    let reply = read_exact(&mut stream, 10).await;
    assert_eq!(reply[1], 0x00);

    let response = read_text(&mut stream).await;
    assert!(response.contains("instance=standby-a"));
    assert!(response.contains("target=example.test:443"));

    handle.abort();
}

#[tokio::test]
async fn socks5_authentication_failure_returns_proxy_failure() {
    let runtime = bind_runtime("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut stream = TcpStream::connect(addrs.socks5).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, vec![0x05, 0x02]);
    write_socks5_auth(&mut stream, "id:serving-a", "wrong").await;
    assert_eq!(read_exact(&mut stream, 2).await, vec![0x01, 0x00]);
    write_socks5_connect(&mut stream, "example.test", 443).await;

    let reply = read_exact(&mut stream, 10).await;
    assert_ne!(reply[1], 0x00);

    handle.abort();
}

#[tokio::test]
async fn http_connect_uses_same_selector_and_auth_contract() {
    let runtime = bind_runtime("secret").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut stream = TcpStream::connect(addrs.http).await.unwrap();
    let auth = BASE64.encode("group:api:secret");
    let request = format!(
        "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let response = read_text(&mut stream).await;
    assert!(response.contains("200 Connection Established"));
    assert!(response.contains("instance=serving-b"));
    assert!(response.contains("target=api.example.test:443"));

    handle.abort();
}

#[tokio::test]
async fn ordinary_http_proxy_preserves_hostname_for_mock_data_plane() {
    let runtime = bind_runtime("").await;
    let addrs = runtime.local_addrs().unwrap();
    let handle = tokio::spawn(runtime.serve());

    let mut stream = TcpStream::connect(addrs.http).await.unwrap();
    stream
        .write_all(
            b"GET http://plain.example.test/path HTTP/1.1\r\nHost: plain.example.test\r\n\r\n",
        )
        .await
        .unwrap();

    let response = read_text(&mut stream).await;
    assert!(response.contains("200 OK"));
    assert!(response.contains("instance=serving-a"));
    assert!(response.contains("target=plain.example.test:80"));

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
            instance("standby-a", "api", "198.51.100.1"),
        ],
    );
    ProxyRuntime::bind(&config, pool).await.unwrap()
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

async fn write_socks5_auth(stream: &mut TcpStream, username: &str, password: &str) {
    let mut bytes = vec![0x01, username.len() as u8];
    bytes.extend_from_slice(username.as_bytes());
    bytes.push(password.len() as u8);
    bytes.extend_from_slice(password.as_bytes());
    stream.write_all(&bytes).await.unwrap();
}

async fn write_socks5_connect(stream: &mut TcpStream, host: &str, port: u16) {
    let mut bytes = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    bytes.extend_from_slice(host.as_bytes());
    bytes.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&bytes).await.unwrap();
}

async fn read_exact(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}

async fn read_text(stream: &mut TcpStream) -> String {
    let mut bytes = vec![0_u8; 4096];
    let len = stream.read(&mut bytes).await.unwrap();
    String::from_utf8(bytes[..len].to_vec()).unwrap()
}
