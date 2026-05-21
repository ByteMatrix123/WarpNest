# Allow local WARP client observation as a bootstrap

WarpNest may use a locally installed WARP client or its local state as a controlled compatibility bootstrap for observing Public WARP Registration material shape. This is allowed to unblock the best-effort Public WARP Adapter, but WarpNest must persist the resulting material through its own Public WARP Adapter contract and must not make `warp-cli` or `warp-svc` a long-term runtime dependency.

**Consequences**

The bootstrap path may help validate raw registration material and normalized adapter configuration before an independent registration client exists. It must remain isolated from Daemon Mode, preserve Public WARP Scope, avoid Zero Trust enrollment, and be replaceable by a direct registration implementation later.
