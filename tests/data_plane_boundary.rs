use std::net::IpAddr;

use warpnest::data_plane::{
    BoringTunDataPlane, DataPlaneInstanceConfig, DataPlaneProtocol, DataPlaneRequest,
    DataPlaneTarget, IpNetwork, MockDataPlane, RuntimeLifecycleState, RuntimePacketPump,
    RuntimePacketPumpError, RuntimeTransportEvent, UdpDatagram, UserSpaceDataPlane,
};
use warpnest::direct_public_warp_registration::WarpKeyPair;
use warpnest::public_warp_adapter::{PUBLIC_WARP_WIREGUARD_OBSERVED_V1, PublicWarpAdapterConfig};

#[tokio::test]
async fn mock_data_plane_preserves_instance_and_target_without_host_resolution() {
    let response = MockDataPlane
        .send(DataPlaneRequest {
            protocol: DataPlaneProtocol::Tcp,
            instance_id: "instance-a".to_string(),
            target_host: "example.test".to_string(),
            target_port: 443,
            payload: Vec::new(),
        })
        .await
        .unwrap();

    let body = String::from_utf8(response.payload).unwrap();
    assert!(body.contains("instance=instance-a"));
    assert!(body.contains("target=example.test:443"));
}

#[tokio::test]
async fn mock_tcp_stream_preserves_instance_and_hostname_target() {
    let mut stream = MockDataPlane
        .connect_tcp(DataPlaneTarget {
            instance_id: "instance-a".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
        })
        .await
        .unwrap();

    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let body = String::from_utf8(stream.read_once().await.unwrap()).unwrap();

    assert_eq!(stream.instance_id(), "instance-a");
    assert_eq!(stream.target().host, "api.example.test");
    assert!(body.contains("warpnest mock tcp"));
    assert!(body.contains("instance=instance-a"));
    assert!(body.contains("target=api.example.test:443"));
    assert!(body.contains("bytes=18"));
}

#[tokio::test]
async fn mock_udp_session_binds_datagrams_to_one_instance() {
    let session = MockDataPlane
        .open_udp_session("instance-b".to_string())
        .await
        .unwrap();

    let body = String::from_utf8(
        session
            .send_datagram(UdpDatagram {
                target_host: "dns.example.test".to_string(),
                target_port: 53,
                payload: b"dns".to_vec(),
            })
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(session.instance_id(), "instance-b");
    assert!(body.contains("warpnest mock udp"));
    assert!(body.contains("instance=instance-b"));
    assert!(body.contains("target=dns.example.test:53"));
}

fn runtime_adapter_config() -> PublicWarpAdapterConfig {
    let private_key = WarpKeyPair::from_private_key_bytes([7; 32]);
    let peer_key = WarpKeyPair::from_private_key_bytes([8; 32]);

    runtime_adapter_config_with(serde_json::json!({
        "private_key": private_key.private_key_base64(),
        "interface_addresses": [
            "172.16.0.2/32",
            "2606:4700:110:8f24::2/128"
        ],
        "peer_public_key": peer_key.public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "dns_servers": [
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001"
        ],
        "device_id": "fixture-device-id",
    }))
}

fn runtime_adapter_config_with(config: serde_json::Value) -> PublicWarpAdapterConfig {
    PublicWarpAdapterConfig::public_warp_wireguard_observed_v1(config).unwrap()
}

fn runtime_data_plane(
    adapter_config: PublicWarpAdapterConfig,
) -> Result<BoringTunDataPlane, String> {
    BoringTunDataPlane::try_with_instances([DataPlaneInstanceConfig {
        instance_id: "instance-a".to_string(),
        adapter_config,
    }])
    .map_err(|error| error.to_string())
}

#[test]
fn boringtun_skeleton_tracks_configured_warp_instances() {
    let data_plane = BoringTunDataPlane::with_instances([DataPlaneInstanceConfig {
        instance_id: "instance-a".to_string(),
        adapter_config: PublicWarpAdapterConfig::mock(),
    }]);

    assert_eq!(data_plane.instance_count(), 1);
    assert!(data_plane.has_instance("instance-a"));
    assert!(!data_plane.has_instance("instance-b"));
}

#[test]
fn boringtun_prepares_direct_registration_runtime_config() {
    let data_plane = runtime_data_plane(runtime_adapter_config()).unwrap();

    let runtime_config = data_plane.runtime_config("instance-a").unwrap();

    assert_eq!(runtime_config.private_key().as_bytes().len(), 32);
    assert_eq!(runtime_config.peer_public_key().as_bytes().len(), 32);
    assert_eq!(
        runtime_config.interface_addresses(),
        &[
            "172.16.0.2/32".parse::<IpNetwork>().unwrap(),
            "2606:4700:110:8f24::2/128".parse::<IpNetwork>().unwrap()
        ]
    );
    assert_eq!(
        runtime_config.peer_endpoint().host(),
        "engage.cloudflareclient.com"
    );
    assert_eq!(runtime_config.peer_endpoint().port(), 2408);
    assert_eq!(
        runtime_config.allowed_ips(),
        &[
            "0.0.0.0/0".parse::<IpNetwork>().unwrap(),
            "::/0".parse::<IpNetwork>().unwrap()
        ]
    );
    assert_eq!(
        runtime_config.dns_servers(),
        &[
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "1.0.0.1".parse::<IpAddr>().unwrap(),
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "2606:4700:4700::1001".parse::<IpAddr>().unwrap()
        ]
    );
    assert_eq!(runtime_config.device_id(), Some("fixture-device-id"));
}

#[test]
fn boringtun_prepares_observed_import_runtime_config_without_device_id() {
    let data_plane = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([17; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([18; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap();

    let runtime_config = data_plane.runtime_config("instance-a").unwrap();

    assert_eq!(runtime_config.interface_addresses().len(), 1);
    assert_eq!(runtime_config.allowed_ips().len(), 1);
    assert_eq!(runtime_config.dns_servers().len(), 1);
    assert_eq!(runtime_config.device_id(), None);
}

#[test]
fn boringtun_runtime_config_rejects_malformed_keys() {
    let error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": "not-base64",
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();

    assert!(error.contains("unsupported Public WARP Adapter"));
    assert!(error.contains("private_key"));
    assert!(error.contains("base64"));
    assert!(!error.contains("not-base64"));
}

#[test]
fn boringtun_runtime_config_rejects_short_peer_public_keys() {
    let short_peer_key =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1_u8; 31]);
    let error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([7; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": short_peer_key,
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();

    assert!(error.contains("peer_public_key"));
    assert!(error.contains("32 bytes"));
    assert!(!error.contains(&short_peer_key));
}

#[test]
fn boringtun_runtime_config_rejects_missing_peer_endpoint_port() {
    let error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([7; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();

    assert!(error.contains("peer_endpoint"));
    assert!(error.contains("missing a UDP port"));
    assert!(!error.contains("engage.cloudflareclient.com"));
}

#[test]
fn boringtun_runtime_config_rejects_malformed_interface_addresses() {
    let error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([7; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/33"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();

    assert!(error.contains("interface_addresses"));
    assert!(error.contains("CIDR prefix length"));
    assert!(!error.contains("172.16.0.2"));
}

#[test]
fn boringtun_runtime_config_rejects_malformed_dns_servers() {
    let error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([7; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["dns.cloudflare.test"],
    })))
    .unwrap_err();

    assert!(error.contains("dns_servers"));
    assert!(!error.contains("dns.cloudflare.test"));
}

#[test]
fn boringtun_runtime_config_rejects_missing_and_empty_fields() {
    let missing_field_error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": WarpKeyPair::from_private_key_bytes([7; 32]).private_key_base64(),
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();
    let empty_field_error = runtime_data_plane(runtime_adapter_config_with(serde_json::json!({
        "private_key": "",
        "interface_addresses": ["172.16.0.2/32"],
        "peer_public_key": WarpKeyPair::from_private_key_bytes([8; 32]).public_key_base64(),
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "allowed_ips": ["0.0.0.0/0"],
        "dns_servers": ["1.1.1.1"],
    })))
    .unwrap_err();

    assert!(missing_field_error.contains("unsupported Public WARP Adapter"));
    assert!(missing_field_error.contains("allowed_ips"));
    assert!(empty_field_error.contains("private_key must not be empty"));
}

#[test]
fn boringtun_runtime_config_rejects_unsupported_adapter_kind_and_version() {
    let unsupported_kind = runtime_data_plane(
        PublicWarpAdapterConfig::from_storage("future-adapter", 1, "{}").unwrap(),
    )
    .unwrap_err();
    let unsupported_version = runtime_data_plane(
        PublicWarpAdapterConfig::from_storage(PUBLIC_WARP_WIREGUARD_OBSERVED_V1, 2, "{}").unwrap(),
    )
    .unwrap_err();

    assert!(unsupported_kind.contains("unsupported Public WARP Adapter future-adapter v1"));
    assert!(
        unsupported_version
            .contains("unsupported Public WARP Adapter public_warp_wireguard_observed_v1 v2")
    );
}

#[test]
fn boringtun_runtime_config_debug_output_redacts_sensitive_material() {
    let adapter_config = runtime_adapter_config();
    let private_key = serde_json::from_str::<serde_json::Value>(adapter_config.config_json())
        .unwrap()["private_key"]
        .as_str()
        .unwrap()
        .to_string();
    let peer_public_key = serde_json::from_str::<serde_json::Value>(adapter_config.config_json())
        .unwrap()["peer_public_key"]
        .as_str()
        .unwrap()
        .to_string();
    let data_plane = runtime_data_plane(adapter_config).unwrap();

    let rendered = format!("{:?}", data_plane.runtime_config("instance-a").unwrap());

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains(&private_key));
    assert!(!rendered.contains(&peer_public_key));
    assert!(!rendered.contains("fixture-device-id"));
}

#[test]
fn runtime_packet_pump_moves_packets_through_injected_transport() {
    let data_plane = runtime_data_plane(runtime_adapter_config()).unwrap();
    let runtime_config = data_plane.runtime_config("instance-a").unwrap().clone();
    let mut pump = RuntimePacketPump::test(runtime_config);

    assert_eq!(pump.lifecycle_state(), "stopped");
    pump.start().unwrap();
    assert_eq!(pump.lifecycle_state(), "running");
    pump.queue_outbound_ip_packet(vec![0x45, 0, 0, 20]);
    pump.queue_inbound_wireguard_packet(vec![0x88, 0x99, 0xaa]);

    let report = pump.pump_once().unwrap();

    assert_eq!(report.outbound_packets, 1);
    assert_eq!(report.inbound_packets, 1);
    assert_eq!(
        pump.transport_events(),
        &[
            RuntimeTransportEvent::SentToPeer(vec![0x45, 0, 0, 20]),
            RuntimeTransportEvent::DeliveredToStack(vec![0x88, 0x99, 0xaa]),
        ]
    );
    pump.stop().unwrap();
    assert_eq!(pump.lifecycle_state(), "stopped");
}

#[test]
fn runtime_packet_pump_keeps_multiple_instances_independent() {
    let data_plane = BoringTunDataPlane::try_with_instances([
        DataPlaneInstanceConfig {
            instance_id: "instance-a".to_string(),
            adapter_config: runtime_adapter_config(),
        },
        DataPlaneInstanceConfig {
            instance_id: "instance-b".to_string(),
            adapter_config: runtime_adapter_config_with(serde_json::json!({
                "private_key": WarpKeyPair::from_private_key_bytes([27; 32]).private_key_base64(),
                "interface_addresses": ["172.16.0.3/32"],
                "peer_public_key": WarpKeyPair::from_private_key_bytes([28; 32]).public_key_base64(),
                "peer_endpoint": "engage.cloudflareclient.com:2408",
                "allowed_ips": ["0.0.0.0/0"],
                "dns_servers": ["1.1.1.1"],
                "device_id": "fixture-device-id-b",
            })),
        },
    ])
    .unwrap();
    let mut pump_a =
        RuntimePacketPump::test(data_plane.runtime_config("instance-a").unwrap().clone());
    let mut pump_b =
        RuntimePacketPump::test(data_plane.runtime_config("instance-b").unwrap().clone());

    pump_a.start().unwrap();
    pump_b.start().unwrap();
    pump_a.queue_outbound_ip_packet(vec![0x45, 0, 0, 20, 0xa]);
    pump_b.queue_outbound_ip_packet(vec![0x45, 0, 0, 20, 0xb]);

    pump_a.pump_once().unwrap();
    pump_b.pump_once().unwrap();

    assert_ne!(
        pump_a.runtime_config().device_id(),
        pump_b.runtime_config().device_id()
    );
    assert_eq!(
        pump_a.transport_events(),
        &[RuntimeTransportEvent::SentToPeer(vec![0x45, 0, 0, 20, 0xa])]
    );
    assert_eq!(
        pump_b.transport_events(),
        &[RuntimeTransportEvent::SentToPeer(vec![0x45, 0, 0, 20, 0xb])]
    );
}

#[test]
fn runtime_packet_pump_reports_failures_without_sensitive_material() {
    let mut pump = RuntimePacketPump::test(
        runtime_data_plane(runtime_adapter_config())
            .unwrap()
            .runtime_config("instance-a")
            .unwrap()
            .clone(),
    );

    let not_running = pump.pump_once().unwrap_err();
    assert_eq!(not_running, RuntimePacketPumpError::NotRunning);
    assert_eq!(pump.lifecycle(), RuntimeLifecycleState::Failed);

    pump.start().unwrap();
    pump.queue_outbound_ip_packet(vec![0x45, 0, 0, 20]);
    pump.fail_next_transport_send("private_key=super-secret peer_public_key=also-secret");
    let transport_error = pump.pump_once().unwrap_err();
    let rendered = transport_error.to_string();

    assert!(matches!(
        transport_error,
        RuntimePacketPumpError::TransportFailed(_)
    ));
    assert_eq!(pump.lifecycle(), RuntimeLifecycleState::Failed);
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("super-secret"));
    assert!(!rendered.contains("also-secret"));
}

#[tokio::test]
async fn boringtun_data_plane_with_prepared_runtime_still_defers_tcp_and_udp_support() {
    let data_plane = runtime_data_plane(runtime_adapter_config()).unwrap();
    let tcp_error = match data_plane
        .connect_tcp(DataPlaneTarget {
            instance_id: "instance-a".to_string(),
            host: "example.test".to_string(),
            port: 443,
        })
        .await
    {
        Ok(_) => panic!("expected TCP support to remain deferred"),
        Err(error) => error.to_string(),
    };
    let udp_error = match data_plane.open_udp_session("instance-a".to_string()).await {
        Ok(_) => panic!("expected UDP support to remain deferred"),
        Err(error) => error.to_string(),
    };

    assert!(
        tcp_error.contains("real WireGuard-compatible User-Space Data Plane is not implemented")
    );
    assert!(
        udp_error.contains("real WireGuard-compatible User-Space Data Plane is not implemented")
    );
}

#[tokio::test]
async fn boringtun_data_plane_boundary_fails_explicitly_until_real_adapter_is_configured() {
    let data_plane = BoringTunDataPlane::with_instances([DataPlaneInstanceConfig {
        instance_id: "instance-a".to_string(),
        adapter_config: PublicWarpAdapterConfig::mock(),
    }]);
    let error = match data_plane
        .connect_tcp(DataPlaneTarget {
            instance_id: "instance-a".to_string(),
            host: "example.test".to_string(),
            port: 443,
        })
        .await
    {
        Ok(_) => panic!("expected unsupported real data plane"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("real WireGuard-compatible User-Space Data Plane is not implemented"));
}

#[tokio::test]
async fn boringtun_skeleton_fails_unknown_instances_explicitly() {
    let error = match BoringTunDataPlane::default()
        .open_udp_session("missing-instance".to_string())
        .await
    {
        Ok(_) => panic!("expected missing instance failure"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("unknown WARP Instance missing-instance"));
}

#[tokio::test]
async fn boringtun_skeleton_rejects_unsupported_adapter_versions() {
    let data_plane = BoringTunDataPlane::with_instances([DataPlaneInstanceConfig {
        instance_id: "instance-a".to_string(),
        adapter_config: PublicWarpAdapterConfig::from_storage("future-adapter", 42, "{}").unwrap(),
    }]);

    let error = match data_plane.open_udp_session("instance-a".to_string()).await {
        Ok(_) => panic!("expected unsupported adapter failure"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("unsupported Public WARP Adapter future-adapter v42"));
}

#[tokio::test]
async fn compatibility_send_uses_tcp_and_udp_session_paths() {
    let tcp = MockDataPlane
        .send(DataPlaneRequest {
            protocol: DataPlaneProtocol::Tcp,
            instance_id: "instance-a".to_string(),
            target_host: "api.example.test".to_string(),
            target_port: 443,
            payload: b"hello".to_vec(),
        })
        .await
        .unwrap();
    let udp = MockDataPlane
        .send(DataPlaneRequest {
            protocol: DataPlaneProtocol::Udp,
            instance_id: "instance-a".to_string(),
            target_host: "dns.example.test".to_string(),
            target_port: 53,
            payload: b"dns".to_vec(),
        })
        .await
        .unwrap();

    assert!(
        String::from_utf8(tcp.payload)
            .unwrap()
            .contains("warpnest mock tcp")
    );
    assert!(
        String::from_utf8(udp.payload)
            .unwrap()
            .contains("warpnest mock udp")
    );
}
