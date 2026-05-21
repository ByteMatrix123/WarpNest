# Use wgcf-derived Public WARP Registration compatibility

WarpNest will use the public WARP registration behavior observed in `wgcf` as the first direct Public WARP Registration compatibility mapping. This accepts the risk of an unofficial Cloudflare client contract so WarpNest can provide fully automatic Public WARP Registration without depending on `warp-cli` or `warp-svc` at runtime, while keeping the implementation isolated behind the `RegistrationClient`, Public WARP Adapter, versioned State Store material, and opt-in real-network integration gates.

**Considered Options**

- Keep direct registration blocked until Cloudflare publishes a stable consumer WARP registration API: rejected because it would prevent WarpNest from satisfying fully automatic Public WARP Registration.
- Depend on a locally installed WARP client for registration: rejected as a runtime strategy because WarpNest must own the lifecycle in one process and cannot require `warp-cli` or `warp-svc`.
- Use the `wgcf`-derived compatibility mapping: accepted because it gives a concrete request, response, header, and transport baseline while preserving explicit unsupported and blocked failure states when Cloudflare behavior changes.

**Consequences**

The direct client must send the observed public WARP request shape, preserve raw response material, normalize successful responses to `public_warp_wireguard_observed_v1`, and stay inside Public WARP Scope. Default tests remain offline; real registration verification requires both `WARPNEST_RUN_WARP_INTEGRATION=1` and `WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1`.
