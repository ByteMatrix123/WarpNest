# Store raw and normalized registration material

WarpNest will store both raw Public WARP Registration material and normalized adapter configuration in the State Store. Raw material preserves recovery and migration options when observed public WARP behavior changes, while normalized adapter fields give the real data plane explicit connection inputs without turning WireGuard keys, device identifiers, or peer settings into domain concepts.

**Consequences**

State Store migrations for the real Public WARP Adapter should include an adapter kind, adapter configuration version, protected raw registration material, and redacted status output. Domain language remains centered on WARP Registration and WARP Connection rather than implementation-specific key or peer names.
