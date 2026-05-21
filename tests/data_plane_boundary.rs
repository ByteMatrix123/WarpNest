use warpnest::data_plane::{
    BoringTunDataPlane, DataPlaneInstanceConfig, DataPlaneProtocol, DataPlaneRequest,
    DataPlaneTarget, MockDataPlane, UdpDatagram, UserSpaceDataPlane,
};
use warpnest::public_warp_adapter::PublicWarpAdapterConfig;

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
