# Use boringtun and smoltcp for the real data-plane runtime

WarpNest will build the first real Public WARP User-Space Data Plane by feeding IP packets from a per-instance `smoltcp` TCP/IP stack through `boringtun`'s low-level WireGuard packet engine and an ordinary UDP socket to the WARP peer endpoint. We will use `boringtun::noise::Tunn` rather than BoringTun's OS device path so WarpNest can keep multiple WARP Instances inside one process, preserve per-connection Instance Selector routing, and avoid host-wide TUN or route changes.

**Considered Options**

- Use BoringTun's OS TUN device path: rejected because it would pull the first implementation back toward host network devices and route management, which conflicts with the in-process User-Space Data Plane boundary.
- Use `smoltcp` without a WireGuard packet engine: rejected because WarpNest still needs WireGuard-compatible encapsulation and handshake behavior for the Public WARP Adapter.
- Implement WireGuard cryptography and packet handling directly: rejected because it adds unnecessary protocol risk when a focused Rust implementation is available.
- Depend on a higher-level WireGuard port-forwarding binary or crate as the runtime boundary: rejected for the first implementation because WarpNest needs explicit per-WARP-Instance lifecycle, TCP, UDP, DNS, probing, and observability hooks.

**Consequences**

Each real WARP Instance runtime owns typed normalized adapter configuration, a WireGuard packet engine, a UDP transport to the WARP peer endpoint, a `smoltcp` interface, and TCP/UDP socket state. Default tests must keep network I/O and timers injectable and offline; #26 remains responsible for opt-in proof against Cloudflare's public WARP service. The Proxy DNS Boundary applies to proxied target names and DNS UDP handled by WarpNest; resolving Cloudflare WARP control or peer endpoints is runtime connectivity, not a shortcut for resolving proxied targets.
