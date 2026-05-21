use warpnest::data_plane::{
    BoringTunDataPlane, DataPlaneProtocol, DataPlaneRequest, MockDataPlane, UserSpaceDataPlane,
};

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
async fn boringtun_data_plane_boundary_fails_explicitly_until_real_adapter_is_configured() {
    let error = BoringTunDataPlane
        .send(DataPlaneRequest {
            protocol: DataPlaneProtocol::Udp,
            instance_id: "instance-a".to_string(),
            target_host: "dns.example.test".to_string(),
            target_port: 53,
            payload: b"dns".to_vec(),
        })
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("BoringTun adapter boundary is present"));
}
