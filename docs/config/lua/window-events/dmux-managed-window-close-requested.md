# `dmux-managed-window-close-requested`

Emitted when the window manager, title-bar close button, or equivalent native
mechanism requests that a window close while
[`dmux_managed_gui`](../config/dmux_managed_gui.md) is enabled.

The native close is always refused.  A dmux configuration can use this event
to ask its signed bridge to detach persistent domains, prove that owner panes
survived, and then hide or safely terminate the GUI.  If no handler is
registered, the managed window remains open.

```lua
wezterm.on('dmux-managed-window-close-requested', function(window, pane)
  -- Dispatch to the authenticated dmux bridge.  Do not close the window here.
end)
```
