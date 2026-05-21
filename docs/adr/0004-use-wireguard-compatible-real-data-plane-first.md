# Use a WireGuard-compatible real data plane first

WarpNest will implement its first real Public WARP User-Space Data Plane through a WireGuard-compatible packet path rather than a MASQUE path. This matches the existing in-process data plane boundary, keeps TCP, UDP, and DNS handling inside one selected WARP Instance, and defers MASQUE until the project intentionally takes on HTTP/3, QUIC, and MASQUE tunnel complexity.

**Considered Options**

- Start with MASQUE: rejected because it would make #11 depend on HTTP/3, QUIC, and MASQUE tunnel behavior before the proxy pool has proven real TCP and UDP routing.
- Start with a WireGuard-compatible path: accepted because it better matches the current User-Space Data Plane boundary and the requirement to route TCP and SOCKS5 UDP Association traffic through a selected WARP Instance.

**Consequences**

WireGuard compatibility is an implementation choice, not a new domain term. The adapter remains replaceable if Cloudflare public WARP behavior changes or if MASQUE becomes the better supported path later.
