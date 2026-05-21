# Use a best-effort Public WARP Adapter

WarpNest will implement Public WARP Registration and real WARP Connections through a best-effort adapter based on observed public WARP client behavior rather than a documented stable Cloudflare consumer WARP API. This preserves the product requirement for fully automatic public WARP usage while keeping the adapter isolated behind replaceable boundaries, with opt-in real-network tests and explicit blocked or unsupported states when Cloudflare behavior changes.

**Considered Options**

- Depend only on documented Cloudflare APIs: rejected because the documented device registration APIs target Zero Trust management and do not satisfy WarpNest's Public WARP Scope.
- Require users to import external WARP configuration manually: rejected because WarpNest must support fully automatic Public WARP Registration.
- Implement a best-effort compatibility adapter: accepted because it matches the product goal while making the stability trade-off explicit.
