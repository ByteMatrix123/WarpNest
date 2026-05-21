# Use TOML for configuration and SQLite for local state

WarpNest separates desired behavior from remembered operational state. We will keep user-edited settings in a TOML configuration file and store WARP Registrations, pool restoration data, last observed exits, and lifecycle observations in SQLite, accepting a small embedded database dependency to avoid fragile hand-edited state files.
