# Public WARP Registration Boundary

WarpNest models Public WARP Registration behind a `RegistrationClient` boundary. Ordinary automated tests use a mock client so they do not call Cloudflare's public WARP service.

The real client adapter should remain isolated from the State Store and Proxy Pool. It is responsible only for creating an ordinary public WARP registration equivalent in product behavior to `warp-cli registration new`, returning registration material to be persisted by the lifecycle service.

Do not add WARP+, Zero Trust enrollment, team device enrollment, or organization-managed fields to `PublicRegistrationRequest` without a new product decision.

Any real-network integration test for this boundary must be explicitly opt-in and must never run as part of the default `cargo test` suite.
