use std::{cell::RefCell, path::PathBuf};

use warpnest::{
    direct_public_warp_registration::{
        DirectPublicWarpRegistrationClient, DirectRegistrationHttpRequest,
        DirectRegistrationHttpResponse, DirectRegistrationHttpTransport, PublicWarpIntegrationGate,
        WarpKeyPair,
    },
    real_warp_integration::{
        RealWarpFullPathFailureClass, RealWarpFullPathHarness, RealWarpFullPathHarnessPaths,
        RealWarpFullPathStatus,
    },
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
fn full_path_harness_skips_without_both_public_warp_integration_gates() {
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::new(
        FakeRegistrationTransport::succeeds_with_wgcf_shape(),
        WarpKeyPair::from_private_key_bytes([61; 32]),
    );
    let harness = RealWarpFullPathHarness::new(client, paths.clone());

    let report = harness.run(PublicWarpIntegrationGate {
        run_warp_integration: true,
        accept_public_warp_compat_risk: false,
    });

    assert_eq!(report.status, RealWarpFullPathStatus::Skipped);
    assert!(
        report
            .skip_reason
            .unwrap()
            .contains("WARPNEST_RUN_WARP_INTEGRATION")
    );
    assert!(!paths.config_path.exists());
    assert!(!paths.state_store_path.exists());
}

#[test]
#[ignore = "requires Cloudflare Public WARP registration and explicit risk gates"]
fn opt_in_full_real_warp_path_reports_sanitized_runtime_blocker() {
    let gate = PublicWarpIntegrationGate::from_env();
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::real().unwrap();
    let harness = RealWarpFullPathHarness::new(client, paths);

    let report = harness.run(gate);
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    if !gate.is_enabled() {
        assert_eq!(report.status, RealWarpFullPathStatus::Skipped);
        return;
    }

    assert_eq!(report.status, RealWarpFullPathStatus::Failed);
    assert_eq!(
        report.failure.as_ref().unwrap().class,
        RealWarpFullPathFailureClass::RuntimeUnsupported
    );
    let evidence = report.evidence.as_ref().unwrap();
    assert!(evidence.persisted_instance_count >= 2);
    assert!(evidence.prepared_runtime_count >= 2);
    assert!(evidence.isolated_state_store);

    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("fixture-access-token"));
    assert!(!rendered.contains("private_key"));
    assert!(!rendered.contains("adapter_config"));
}

fn harness_paths(temp: PathBuf) -> RealWarpFullPathHarnessPaths {
    RealWarpFullPathHarnessPaths {
        config_path: temp.join("isolated").join("warpnest.toml"),
        state_store_path: temp.join("isolated").join("warpnest.sqlite"),
    }
}
