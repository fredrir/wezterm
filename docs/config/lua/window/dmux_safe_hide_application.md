# `window:dmux_safe_hide_application()`

This maintained-fork method hides the GUI application without executing a
`HideApplication` key assignment. It is available only when
[`dmux_managed_gui`](../config/dmux_managed_gui.md) is enabled; otherwise it
returns an error.

The method is intentionally not representable as a key assignment, menu item,
launcher entry, or mouse action. On macOS it is the final platform action for
an authenticated dmux safe-quit request after the bridge has detached
persistent domains and proved that all owner panes survived. Calling it does
not itself perform or verify that proof.

Loaded configuration Lua is part of the trusted computing base: any Lua code
running in that configuration can call this method. Request authentication,
expiry, replay consumption, and the one-shot proof transition therefore stay
in dmux's signed bridge.

```lua
-- Only after validating and consuming dmux's signed safe-quit proof:
window:dmux_safe_hide_application()
```

Normal native `HideApplication` actions remain refused in managed mode.
