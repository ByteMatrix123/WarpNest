# Use an in-process user-space data plane

WarpNest needs to run multiple WARP Instances in one process and route each proxy connection through a selected instance. We will carry proxied traffic through an in-process user-space data plane instead of taking over the host system's global TUN route, accepting higher implementation complexity to preserve per-connection instance selection and avoid host-wide routing side effects.
