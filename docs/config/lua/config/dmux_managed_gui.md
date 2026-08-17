# `dmux_managed_gui = false`

This maintained-fork option enables the fail-closed GUI runtime used by dmux.
It is disabled by default.

When enabled, WezTerm removes native creation, attach/detach, hierarchy-layout,
workspace-switch, close, hide-application, and quit actions from the command
palette, launcher, menubar, and macOS Dock menu. It also refuses those actions at runtime, including direct
`window:perform_action` calls and zero-window native application callbacks.
Tab close buttons and middle-click tab close are refused. Window-manager
close requests emit the
[`dmux-managed-window-close-requested`](../window-events/dmux-managed-window-close-requested.md)
event so the dmux broker can run its authenticated detach-and-survival proof.

```lua
config.dmux_managed_gui = true
```

`QuitApplication` and `HideApplication` remain denied while managed mode is
active. After the authenticated dmux bridge has detached persistent domains
and proved owner pane survival, the exclusive retained
[`wezterm.gui.dmux_bridge_open()`](../wezterm.gui/dmux_bridge_open.md)
capability can consume the exact authenticated request and durable
acknowledgement and complete the application-scoped lifecycle. This works
after the last GUI window disappears. There is deliberately no global or
window quit/hide escape hatch; direct configuration Lua cannot bypass the
bridge proof.

Managed GUI and recovery-service configurations cannot be reloaded in place.
Their native directory, lease, and proof capabilities belong to one Lua
generation, so a process restart is required for configuration changes.

Native tab reordering, pane rotation/swap/resize/zoom, and relative workspace
switches are denied because they bypass dmux's owner journal or exact logical
marker correlation. Focus-only activation of an existing tab or pane remains
available, as do single-window minimize/restore actions.

When the process environment contains `DMUX_WEZ_FIRST=1`, initial GUI startup
also fails before constructing the local mux unless all of the following are
true:

* the user configuration loaded without error;
* this option is enabled;
* the config declares exactly one no-auto-start unix domain named `dmux`, at
  the same absolute socket supplied by the broker in `WEZTERM_UNIX_SOCKET`;
* the invocation is `connect dmux` or the fixed attach-only equivalent, with
  no program, working directory, workspace, or new-tab request.

This catches WezTerm's normal config-error fallback to stock defaults, which
would otherwise be able to create an unmanaged local shell. With
`DMUX_WEZ_FIRST` unset, startup and action execution retain stock behavior.

After an attach, managed mode also requires the target domain to contain at
least one existing pane. If it is empty, startup terminates instead of taking
WezTerm's normal default-pane spawn fallback. The broker's exact
descriptor/sentinel proof remains the authority check; this in-process guard
closes the empty-domain race without creating an owner pane.
