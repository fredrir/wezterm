# `wezterm.mux.dmux_recovery_remove_node(REQUEST)`

This maintained-fork function removes one exact recovery-created native node.
It is available to the mux-server Lua environment and returns `disabled`
unless [`dmux_recovery_primitives`](../config/dmux_recovery_primitives.md) is
enabled.

The request is a closed table with one of these exact shapes:

```lua
-- Split/pane
wezterm.mux.dmux_recovery_remove_node {
  kind = 'pane',
  native_id = pane_id,
  parent_tab_id = tab_id,
  parent_window_id = window_id,
}

-- Group/tab
wezterm.mux.dmux_recovery_remove_node {
  kind = 'tab',
  native_id = tab_id,
  parent_window_id = window_id,
}

-- Space/window. `workspace` is the exact opaque workspace key.
wezterm.mux.dmux_recovery_remove_node {
  kind = 'window',
  native_id = window_id,
  workspace = 'dmux:host:space',
}
```

Unknown fields and non-string keys are rejected.  In particular, the API has
no process-ID, command, or workspace-ordinal input.

The result is a table with these fields:

```lua
{
  schema_version = 1,
  status = 'removed', -- removed | not_found | parent_mismatch |
                      -- postcondition_failed | disabled
  kind = 'pane',
  requested_native_id = pane_id,
  removed_pane_ids = { pane_id },
  removed_tab_ids = {},
  removed_window_ids = {},
  actual_parent_tab_id = tab_id,       -- optional
  actual_parent_window_id = window_id, -- optional
  actual_workspace = nil,              -- optional
  postcondition_error = nil,           -- set on postcondition_failed
}
```

`not_found` is mutation-free and returns empty removal arrays.  A
`parent_mismatch` is also mutation-free and reports the actual parent identity
when it can be resolved.  Callers must independently prove same-epoch absence
before treating `not_found` as an idempotent success.

Removal is exact and checks that every pre-existing neighboring native ID is
still present.  Removing the final pane in a tab synchronously removes that
empty tab; if it was the final tab, it also removes the empty window.  Those
cascade IDs are included in the corresponding arrays.  Tab removal likewise
removes its panes and cascades its window only when the window becomes empty.
Window removal removes only that window and its descendant tabs and panes.
