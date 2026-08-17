# `dmux_recovery_primitives = false`

This maintained-fork option enables the exact native-node removal primitive
used by the fenced dmux mux-server recovery coordinator.  It is disabled by
default.

```lua
config.dmux_recovery_primitives = true
```

Enable it only in the managed mux-server configuration.  The primitive takes
stable native IDs and validates their exact parent identities; it does not
accept process IDs, shell commands, or workspace ordinals.

The managed service must be launched with the maintained fork's hidden
`--dmux-managed-service` contract. That path prebinds the fixed private Unix
socket while the process is still single-threaded; configuration then claims
the retained listener with `wezterm.mux.dmux_service_bootstrap()`. A missing
claim, mismatched domain, failed sentinel, or attempted default-pane fallback
terminates the service. Config reload is disabled for the lifetime of the
retained recovery capability; changes require a service restart.

See [`wezterm.mux.dmux_recovery_remove_node`](../wezterm.mux/dmux_recovery_remove_node.md).
