# Public WARP Registration Boundary

WarpNest models Public WARP Registration behind a `RegistrationClient` boundary. Ordinary automated tests use a mock client so they do not call Cloudflare's public WARP service.

The real client adapter should remain isolated from the Proxy Pool. It is responsible only for creating an ordinary public WARP registration equivalent in product behavior to `warp-cli registration new`, returning registration material to be persisted by the lifecycle service.

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
