# Use a userspace TCP/IP stack for the real data plane

WarpNest's real Public WARP User-Space Data Plane will combine a WireGuard-compatible packet path with a userspace TCP/IP stack. The current single-request mock `send` boundary is sufficient for contract tests, but real WARP traffic needs long-lived TCP streams, UDP datagram sessions, per-instance packet state, and DNS handling inside the selected WARP Instance path.

**Consequences**

The real data plane interface will evolve beyond one request returning one response. Mock coverage should remain available for pool, selector, proxy, and lifecycle tests, while opt-in real-network tests prove the WireGuard-compatible packet path and userspace TCP/IP stack together.
