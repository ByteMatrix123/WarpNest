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

Before #27 can implement a direct registration client, these unknowns must be proven and documented:

- The observed direct-registration request shape for ordinary public WARP.
- The observed success response shape and its mapping to `public_warp_wireguard_observed_v1`.
- Which remote failures are transient, blocked, or unsupported.
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
