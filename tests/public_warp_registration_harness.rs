use std::{cell::RefCell, path::PathBuf};

use warpnest::{
    direct_public_warp_registration::{
        DirectPublicWarpRegistrationClient, DirectRegistrationHttpRequest,
        DirectRegistrationHttpResponse, DirectRegistrationHttpTransport, PublicWarpIntegrationGate,
        WarpKeyPair,
    },
    public_warp_adapter::PUBLIC_WARP_WIREGUARD_OBSERVED_V1,
    public_warp_registration_harness::{
        PublicWarpRegistrationFailureClass, PublicWarpRegistrationHarness,
        PublicWarpRegistrationHarnessPaths, PublicWarpRegistrationHarnessStatus,
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

    fn rejects_with_sensitive_error() -> Self {
        Self {
            requests: RefCell::new(Vec::new()),
            response: DirectRegistrationHttpResponse {
                status: 403,
                body: serde_json::json!({
                    "errors": [
                        {
                            "message": "registration token fixture-secret-token rejected"
                        }
                    ]
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
fn harness_reports_success_without_sensitive_registration_material() {
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::new(
        FakeRegistrationTransport::succeeds_with_wgcf_shape(),
        WarpKeyPair::from_private_key_bytes([21; 32]),
    );
    let harness = PublicWarpRegistrationHarness::new(client, paths.clone()).with_budget(1);

    let report = harness.run(PublicWarpIntegrationGate {
        run_warp_integration: true,
        accept_public_warp_compat_risk: true,
    });

    assert_eq!(
        report.status,
        PublicWarpRegistrationHarnessStatus::Succeeded
    );
    assert_eq!(report.registration_budget, 1);
    assert_eq!(report.config_path, paths.config_path.display().to_string());
    assert_eq!(
        report.state_store_path,
        paths.state_store_path.display().to_string()
    );
    assert!(paths.config_path.exists());
    assert!(paths.state_store_path.exists());
    assert!(!temp.path().join("warpnest.sqlite").exists());

    let evidence = report.evidence.as_ref().unwrap();
    assert_eq!(evidence.group, "integration");
    assert_eq!(evidence.adapter_kind, PUBLIC_WARP_WIREGUARD_OBSERVED_V1);
    assert_eq!(evidence.adapter_config_version, 1);
    assert_eq!(evidence.persisted_instance_count, 1);

    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("fixture-access-token"));
    assert!(!rendered.contains("fixture-secret-token"));
    assert!(!rendered.contains("fixture-license"));
    assert!(!rendered.contains("adapter_config"));
    assert!(!rendered.contains("private_key"));
}

#[test]
fn integration_gate_requires_both_public_warp_risk_flags() {
    assert!(
        !PublicWarpIntegrationGate {
            run_warp_integration: false,
            accept_public_warp_compat_risk: false,
        }
        .is_enabled()
    );
    assert!(
        !PublicWarpIntegrationGate {
            run_warp_integration: true,
            accept_public_warp_compat_risk: false,
        }
        .is_enabled()
    );
    assert!(
        !PublicWarpIntegrationGate {
            run_warp_integration: false,
            accept_public_warp_compat_risk: true,
        }
        .is_enabled()
    );
    assert!(
        PublicWarpIntegrationGate {
            run_warp_integration: true,
            accept_public_warp_compat_risk: true,
        }
        .is_enabled()
    );
}

#[test]
fn harness_reports_sanitized_classified_registration_failures() {
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::new(
        FakeRegistrationTransport::rejects_with_sensitive_error(),
        WarpKeyPair::from_private_key_bytes([22; 32]),
    );
    let harness = PublicWarpRegistrationHarness::new(client, paths.clone()).with_budget(1);

    let report = harness.run(PublicWarpIntegrationGate {
        run_warp_integration: true,
        accept_public_warp_compat_risk: true,
    });

    assert_eq!(report.status, PublicWarpRegistrationHarnessStatus::Failed);
    let failure = report.failure.as_ref().unwrap();
    assert_eq!(failure.class, PublicWarpRegistrationFailureClass::Blocked);
    assert_eq!(failure.message, "[redacted]");
    assert!(report.evidence.is_none());
    assert!(paths.config_path.exists());
    assert!(paths.state_store_path.exists());

    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("fixture-secret-token"));
    assert!(!rendered.contains("registration token"));
}

#[test]
fn harness_skips_without_both_public_warp_integration_gates() {
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::new(
        FakeRegistrationTransport::succeeds_with_wgcf_shape(),
        WarpKeyPair::from_private_key_bytes([23; 32]),
    );
    let harness = PublicWarpRegistrationHarness::new(client, paths.clone()).with_budget(1);

    let report = harness.run(PublicWarpIntegrationGate {
        run_warp_integration: true,
        accept_public_warp_compat_risk: false,
    });

    assert_eq!(report.status, PublicWarpRegistrationHarnessStatus::Skipped);
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
fn opt_in_public_warp_registration_harness_reports_sanitized_evidence() {
    let gate = PublicWarpIntegrationGate::from_env();
    let temp = tempfile::tempdir().unwrap();
    let paths = harness_paths(temp.path().into());
    let client = DirectPublicWarpRegistrationClient::real().unwrap();
    let harness = PublicWarpRegistrationHarness::new(client, paths).with_budget(1);

    let report = harness.run(gate);
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    if !gate.is_enabled() {
        assert_eq!(report.status, PublicWarpRegistrationHarnessStatus::Skipped);
        return;
    }

    assert_eq!(
        report.status,
        PublicWarpRegistrationHarnessStatus::Succeeded
    );
    let evidence = report.evidence.as_ref().unwrap();
    assert_eq!(evidence.adapter_kind, PUBLIC_WARP_WIREGUARD_OBSERVED_V1);
    assert_eq!(evidence.adapter_config_version, 1);
    assert_eq!(evidence.persisted_instance_count, 1);
}

fn harness_paths(temp: PathBuf) -> PublicWarpRegistrationHarnessPaths {
    PublicWarpRegistrationHarnessPaths {
        config_path: temp.join("isolated").join("warpnest.toml"),
        state_store_path: temp.join("isolated").join("warpnest.sqlite"),
    }
}
