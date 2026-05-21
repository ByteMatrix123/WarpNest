# Public WARP Registration Boundary

WarpNest models Public WARP Registration behind a `RegistrationClient` boundary. Ordinary automated tests use a mock client so they do not call Cloudflare's public WARP service.

The real client adapter should remain isolated from the Proxy Pool. It is responsible only for creating an ordinary public WARP registration equivalent in product behavior to `warp-cli registration new`, returning registration material to be persisted by the lifecycle service.

## Direct Public WARP Registration Contract

A direct Public WARP Registration client is the future implementation of `RegistrationClient` that talks to Cloudflare's ordinary public WARP service without using a locally running WARP client. It is a best-effort compatibility adapter, not a stable Cloudflare API contract.

The client input is intentionally narrow:

- Instance Group and optional label from `PublicRegistrationRequest`.
- A bounded Registration Budget enforced by the lifecycle service before the client is called.
- Public WARP Scope only: ordinary public WARP, no WARP+, no Zero Trust enrollment, no organization-managed device enrollment, and no identity-provider flow.

The client output must be a complete WARP Registration result that can be stored without additional host-client state:

- Raw Public WARP Registration material for recovery and future migrations.
- A normalized `public_warp_wireguard_observed_v1` Public WARP Adapter config, unless a new ADR and adapter version intentionally replace that shape.
- Enough peer, interface, route, DNS, and device identity material for a real User-Space Data Plane to establish a WARP Connection later.

Successful registration must map to the State Store exactly like imported observed material: raw material remains available for migration, normalized adapter config is versioned, and all sensitive fields remain redacted from status, logs, and `Debug` output. The registration client must not persist partial successful material outside the State Store.

## wgcf-Derived Compatibility Mapping

WarpNest accepts the `wgcf` public WARP registration behavior as the initial direct-registration compatibility baseline. This mapping is used only for ordinary Public WARP Scope and must remain isolated behind the `RegistrationClient` and Public WARP Adapter boundaries.

The registration client should create a fresh WireGuard key pair locally and submit the public key to Cloudflare's public WARP registration endpoint:

- Base URL: `https://api.cloudflareclient.com`
- API version: `v0a1922`
- Endpoint: `POST /v0a1922/reg`
- Required compatibility headers:
  - `User-Agent: okhttp/3.12.1`
  - `CF-Client-Version: a-6.3-1922`
- Transport compatibility:
  - TLS must be constrained to TLS 1.2 for the direct client.
  - HTTP/2 must be disabled for the direct client.

The request body should match the ordinary public WARP registration shape observed by `wgcf`:

```json
{
  "fcm_token": "",
  "install_id": "",
  "key": "<wireguard-public-key>",
  "locale": "en_US",
  "model": "PC",
  "tos": "<timestamp>",
  "type": "Android"
}
```

WarpNest may allow the model and locale to become explicit configuration later, but the first implementation should keep the request narrow and deterministic. The request must not include WARP+, Zero Trust, organization-managed enrollment, identity-provider, or license-binding fields.

The successful response must be preserved as raw Public WARP Registration material and normalized into `public_warp_wireguard_observed_v1`. The normalized adapter config must contain the same fields accepted by the observed-material import path:

- `private_key`: the locally generated WireGuard private key.
- `interface_addresses`: the IPv4 and IPv6 interface addresses from the registration response, without relying on host WARP client state.
- `peer_public_key`: the first WARP peer public key from the registration response.
- `peer_endpoint`: the first WARP peer endpoint host from the registration response.
- `allowed_ips`: `0.0.0.0/0` and `::/0`.
- `dns_servers`: `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, and `2606:4700:4700::1001`.
- `device_id`: the returned WARP device identifier when present.

The raw material should retain response fields needed for recovery and future migrations, including the returned device identifier, access token, account data, interface configuration, peer configuration, and any unknown response fields. Logs, status output, test output, and `Debug` implementations must not print the raw material, private key, access token, device identifier, or normalized adapter config.

## Failure Taxonomy

Direct registration failures must be classified before they reach Retry Discipline:

- **Transient**: temporary network, timeout, rate-limit, or malformed remote response conditions that may succeed later.
- **Blocked**: authorization, policy, account, or public-service rejection conditions that require deliberate user action or a compatibility update before retrying.
- **Unsupported**: Cloudflare behavior or returned material shape does not match the current Public WARP Adapter contract.
- **Store**: State Store persistence or migration failure after a registration result is available.

Transient failures may be retried with the existing Retry Discipline. Blocked and unsupported failures must be surfaced as non-tight-retry states. Store failures must not be hidden as remote registration failures.

## Direct Registration Verification

Default tests must stay offline. They must not call Cloudflare, `warp-cli`, `warp-svc`, or a locally installed WARP client.

Real-network verification for a direct Public WARP Registration client must be explicitly enabled with both environment gates:

- `WARPNEST_RUN_WARP_INTEGRATION=1`
- `WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1`

Integration runs must use isolated temporary Configuration File and State Store paths, plus a bounded Registration Budget. Test output must be sanitized and must not print raw registration material, private keys, tokens, device identifiers, or normalized adapter config.

The direct registration opt-in command is:

```sh
WARPNEST_RUN_WARP_INTEGRATION=1 \
WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1 \
cargo test --test public_warp_registration_harness opt_in_public_warp_registration_harness_reports_sanitized_evidence -- --ignored
```

Default `cargo test` must not set these variables and must not contact Cloudflare.

The full real WARP path proof is also opt-in:

```sh
WARPNEST_RUN_WARP_INTEGRATION=1 \
WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1 \
cargo test --test real_warp_full_path opt_in_full_real_warp_path_reports_sanitized_runtime_blocker -- --ignored --nocapture
```

After the direct registration compatibility mapping is implemented, these remaining observations must be proven and documented by opt-in real-network tests before the full real WARP path can be considered verified:

- Which concrete remote failures are transient, blocked, or unsupported in real Cloudflare responses.
- Whether the produced material can establish a real WARP Connection through the User-Space Data Plane without a host WARP client runtime dependency.

## Public WARP Adapter Contract

The Public WARP Adapter is a best-effort compatibility boundary, not a documented stable Cloudflare consumer WARP API. Adapter output persisted in the State Store must include:

- `registration_material`: raw Public WARP Registration material kept for recovery and future migrations.
- `adapter_kind`: the implementation-specific adapter contract, such as `public_warp_wireguard_observed_v1`.
- `adapter_config_version`: the version of the normalized adapter configuration shape.
- `adapter_config`: normalized adapter configuration encoded as JSON for the real User-Space Data Plane.

Unsupported adapter kind/version pairs must fail explicitly as unsupported rather than being retried as transient network failures. Authorization, policy, or compatibility failures that cannot be resolved automatically should become blocked states so Retry Discipline does not create a tight retry loop.

Raw registration material and normalized adapter configuration are sensitive operational state. Pool Status, logs, and `Debug` output must redact them.

Do not add WARP+, Zero Trust enrollment, team device enrollment, or organization-managed fields to `PublicRegistrationRequest` without a new product decision.

Any real-network integration test for this boundary must be explicitly opt-in and must never run as part of the default `cargo test` suite.
