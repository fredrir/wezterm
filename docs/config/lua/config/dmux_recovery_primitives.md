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

See [`wezterm.mux.dmux_recovery_remove_node`](../wezterm.mux/dmux_recovery_remove_node.md).
