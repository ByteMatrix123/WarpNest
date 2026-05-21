use warpnest::{config::Config, management::ManagementServer, status::PoolStatus};

#[tokio::test]
async fn management_api_returns_mock_pool_status() {
    let config = Config::default();
    let status = PoolStatus::mock(&config);
    let server = ManagementServer::bind(config.listeners.management_bind, status)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();

    let handle = tokio::spawn(server.serve());
    let response: serde_json::Value = reqwest::get(format!("http://{addr}/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response["readiness"], "degraded");
    assert_eq!(response["target_serving_size"], 1);
    assert_eq!(response["actual_serving_size"], 0);
    assert_eq!(response["registration_budget"], 3);
    assert_eq!(response["instances"][0]["instance_id"], "mock-instance-1");
    assert!(!response.to_string().contains("secret"));

    handle.abort();
}
