use std::cell::RefCell;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;
use warpnest::{
    direct_public_warp_registration::{
        DirectPublicWarpRegistrationClient, DirectRegistrationHttpRequest,
        DirectRegistrationHttpResponse, DirectRegistrationHttpTransport, WarpKeyPair,
    },
    public_warp_adapter::PUBLIC_WARP_WIREGUARD_OBSERVED_V1,
    state_store::StateStore,
    warp_lifecycle::{PublicRegistrationRequest, RegistrationClient, RegistrationService},
};

#[derive(Debug)]
struct FakeRegistrationTransport {
    requests: RefCell<Vec<DirectRegistrationHttpRequest>>,
    response: DirectRegistrationHttpResponse,
}

impl FakeRegistrationTransport {
    fn succeeds_with_wgcf_shape() -> Self {
        Self {
            requests: RefCell::new(Vec::new()),
            response: DirectRegistrationHttpResponse {
                status: 200,
                body: serde_json::json!({
                    "id": "fixture-device-id",
                    "token": "fixture-access-token",
                    "account": {
                        "id": "fixture-account-id",
                        "license": "fixture-license"
                    },
                    "config": {
                        "interface": {
                            "addresses": {
                                "v4": "172.16.0.2",
                                "v6": "2606:4700:110:8f24::2"
                            }
                        },
                        "peers": [
                            {
                                "public_key": "fixture-peer-public-key",
                                "endpoint": {
                                    "host": "engage.cloudflareclient.com:2408"
                                }
                            }
                        ]
                    }
                }),
            },
        }
    }

    fn responds(status: u16, body: Value) -> Self {
        Self {
            requests: RefCell::new(Vec::new()),
            response: DirectRegistrationHttpResponse { status, body },
        }
    }
}

impl DirectRegistrationHttpTransport for FakeRegistrationTransport {
    fn send(
        &self,
        request: DirectRegistrationHttpRequest,
    ) -> Result<DirectRegistrationHttpResponse, String> {
        self.requests.borrow_mut().push(request);
        Ok(self.response.clone())
    }
}

#[test]
fn direct_registration_maps_wgcf_response_to_observed_adapter_config() {
    let transport = FakeRegistrationTransport::succeeds_with_wgcf_shape();
    let key_pair = WarpKeyPair::from_private_key_bytes([7; 32]);
    let mut client = DirectPublicWarpRegistrationClient::new(transport, key_pair.clone());

    let registration = client
        .create_public_registration(&PublicRegistrationRequest::default())
        .unwrap();

    let raw: Value = serde_json::from_str(&registration.registration_material).unwrap();
    assert_eq!(raw["response"]["id"], "fixture-device-id");
    assert_eq!(raw["response"]["token"], "fixture-access-token");
    assert_eq!(
        registration.adapter_config.kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
    assert_eq!(registration.adapter_config.version, 1);

    let normalized: Value =
        serde_json::from_str(registration.adapter_config.config_json()).unwrap();
    assert_eq!(normalized["private_key"], key_pair.private_key_base64());
    assert_eq!(
        normalized["interface_addresses"],
        serde_json::json!(["172.16.0.2/32", "2606:4700:110:8f24::2/128"])
    );
    assert_eq!(normalized["peer_public_key"], "fixture-peer-public-key");
    assert_eq!(
        normalized["peer_endpoint"],
        "engage.cloudflareclient.com:2408"
    );
    assert_eq!(
        normalized["allowed_ips"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
    assert_eq!(
        normalized["dns_servers"],
        serde_json::json!([
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001"
        ])
    );
    assert_eq!(normalized["device_id"], "fixture-device-id");

    let requests = client.transport().requests.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url,
        "https://api.cloudflareclient.com/v0a1922/reg"
    );
    assert_eq!(
        requests[0].headers.get("User-Agent"),
        Some(&"okhttp/3.12.1".to_string())
    );
    assert_eq!(
        requests[0].headers.get("CF-Client-Version"),
        Some(&"a-6.3-1922".to_string())
    );
    assert_eq!(requests[0].body["fcm_token"], "");
    assert_eq!(requests[0].body["install_id"], "");
    assert_eq!(requests[0].body["key"], key_pair.public_key_base64());
    assert_eq!(requests[0].body["locale"], "en_US");
    assert_eq!(requests[0].body["model"], "PC");
    assert_eq!(requests[0].body["type"], "Android");
    assert!(requests[0].body["tos"].as_str().is_some());
}

#[test]
fn generated_wireguard_private_key_material_is_clamped() {
    let key_pair = WarpKeyPair::from_private_key_bytes([255; 32]);
    let decoded = BASE64.decode(key_pair.private_key_base64()).unwrap();

    assert_eq!(decoded[0] & 7, 0);
    assert_eq!(decoded[31] & 128, 0);
    assert_eq!(decoded[31] & 64, 64);
}

#[test]
fn direct_registration_service_persists_raw_and_normalized_material() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("warpnest.sqlite")).unwrap();
    let transport = FakeRegistrationTransport::succeeds_with_wgcf_shape();
    let key_pair = WarpKeyPair::from_private_key_bytes([8; 32]);
    let client = DirectPublicWarpRegistrationClient::new(transport, key_pair);
    let mut service = RegistrationService::new(&store, client, 1);

    let created = service
        .create_public_registration(PublicRegistrationRequest {
            group: "direct".to_string(),
            label: Some("direct public WARP".to_string()),
        })
        .unwrap();
    let restored = store.list_instances().unwrap();

    assert_eq!(created.group, "direct");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].instance_id, created.instance_id);
    assert_eq!(restored[0].group, "direct");
    assert_eq!(restored[0].label.as_deref(), Some("direct public WARP"));
    assert!(
        restored[0]
            .raw_registration_material()
            .contains("\"adapter\":\"wgcf-derived-public-warp-registration\"")
    );
    assert_eq!(
        restored[0].adapter_config.kind,
        PUBLIC_WARP_WIREGUARD_OBSERVED_V1
    );
    assert_eq!(restored[0].adapter_config.version, 1);
}

#[test]
fn direct_registration_classifies_public_service_rejection_as_blocked() {
    let transport = FakeRegistrationTransport::responds(
        403,
        serde_json::json!({
            "errors": [
                {
                    "message": "public WARP registration rejected by compatibility gate"
                }
            ]
        }),
    );
    let key_pair = WarpKeyPair::from_private_key_bytes([9; 32]);
    let mut client = DirectPublicWarpRegistrationClient::new(transport, key_pair);

    let error = client
        .create_public_registration(&PublicRegistrationRequest::default())
        .unwrap_err();

    assert_eq!(
        error,
        warpnest::warp_lifecycle::RegistrationError::Blocked(
            "Public WARP registration rejected with HTTP 403: public WARP registration rejected by compatibility gate".to_string()
        )
    );
}

#[test]
fn direct_registration_classifies_unknown_success_shape_as_unsupported() {
    let transport = FakeRegistrationTransport::responds(
        200,
        serde_json::json!({
            "id": "fixture-device-id",
            "token": "fixture-access-token",
            "config": {
                "interface": {
                    "addresses": {
                        "v4": "172.16.0.2"
                    }
                },
                "peers": []
            }
        }),
    );
    let key_pair = WarpKeyPair::from_private_key_bytes([11; 32]);
    let mut client = DirectPublicWarpRegistrationClient::new(transport, key_pair);

    let error = client
        .create_public_registration(&PublicRegistrationRequest::default())
        .unwrap_err();

    assert!(matches!(
        &error,
        warpnest::warp_lifecycle::RegistrationError::Unsupported(_)
    ));
    match error {
        warpnest::warp_lifecycle::RegistrationError::Unsupported(reason) => {
            assert!(reason.contains("unsupported"));
        }
        unexpected => panic!("expected unsupported registration error, got {unexpected:?}"),
    }
}

#[test]
fn direct_registration_debug_output_redacts_key_material() {
    let transport = FakeRegistrationTransport::succeeds_with_wgcf_shape();
    let key_pair = WarpKeyPair::from_private_key_bytes([13; 32]);
    let private_key = key_pair.private_key_base64().to_string();
    let public_key = key_pair.public_key_base64().to_string();
    let rendered_key_pair = format!("{key_pair:?}");
    let client = DirectPublicWarpRegistrationClient::new(transport, key_pair);

    let rendered = format!("{client:?}");

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains(&private_key));
    assert!(!rendered.contains(&public_key));
    assert!(rendered_key_pair.contains("[redacted]"));
    assert!(!rendered_key_pair.contains(&private_key));
    assert!(!rendered_key_pair.contains(&public_key));
}

#[test]
fn direct_registration_transport_debug_output_redacts_bodies() {
    let transport = FakeRegistrationTransport::succeeds_with_wgcf_shape();
    let key_pair = WarpKeyPair::from_private_key_bytes([14; 32]);
    let mut client = DirectPublicWarpRegistrationClient::new(transport, key_pair);

    client
        .create_public_registration(&PublicRegistrationRequest::default())
        .unwrap();

    let request_debug = format!("{:?}", client.transport().requests.borrow()[0]);
    let response_debug = format!(
        "{:?}",
        FakeRegistrationTransport::succeeds_with_wgcf_shape().response
    );

    assert!(request_debug.contains("[redacted]"));
    assert!(!request_debug.contains("fcm_token"));
    assert!(!request_debug.contains("install_id"));
    assert!(response_debug.contains("[redacted]"));
    assert!(!response_debug.contains("fixture-access-token"));
    assert!(!response_debug.contains("fixture-license"));
}

#[test]
fn direct_registration_result_debug_output_redacts_registration_material() {
    let transport = FakeRegistrationTransport::succeeds_with_wgcf_shape();
    let key_pair = WarpKeyPair::from_private_key_bytes([15; 32]);
    let private_key = key_pair.private_key_base64().to_string();
    let mut client = DirectPublicWarpRegistrationClient::new(transport, key_pair);

    let registration = client
        .create_public_registration(&PublicRegistrationRequest::default())
        .unwrap();
    let rendered = format!("{registration:?}");

    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("fixture-access-token"));
    assert!(!rendered.contains(&private_key));
}
