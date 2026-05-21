# Gate real WARP integration tests

WarpNest's normal test suite must not create Public WARP Registrations, connect to Cloudflare, or depend on public network behavior. Real WARP integration tests will run only when explicitly enabled with `WARPNEST_RUN_WARP_INTEGRATION=1` and `WARPNEST_ACCEPT_PUBLIC_WARP_COMPAT_RISK=1`, using an isolated temporary State Store and a bounded Registration Budget.

**Consequences**

Unit and contract tests stay mock-based by default. Opt-in integration tests should prove Public WARP Registration, real WARP Connection setup, TCP proxy traffic, SOCKS5 UDP Association including DNS, Exit Probe behavior through the selected WARP Instance, and Proxy DNS Boundary preservation without reading or mutating a user's default WarpNest state.
