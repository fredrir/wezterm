# `window:dmux_safe_quit_application()`

This maintained-fork method terminates the GUI process without executing a
`QuitApplication` key assignment. It is available only when
[`dmux_managed_gui`](../config/dmux_managed_gui.md) is enabled; otherwise it
returns an error.

The method is intentionally not representable as a key assignment, menu
item, launcher entry, or mouse action. It is the final platform action for an
authenticated dmux safe-quit request after the bridge has detached persistent
domains and proved that all owner panes survived. Calling it does not itself
perform or verify that proof.

Loaded configuration Lua is part of the trusted computing base: any Lua code
running in that configuration can call this method. Request authentication,
expiry, replay consumption, and the one-shot proof transition therefore stay
in dmux's signed bridge. An additional Lua-callable "arm" method would not
authenticate the caller and is deliberately not provided.

```lua
-- Only after validating and consuming dmux's signed safe-quit proof:
window:dmux_safe_quit_application()
```

Normal native `QuitApplication` actions remain refused in managed mode.
