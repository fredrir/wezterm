# `wezterm.gui.dmux_bridge_open(instance_id)`

This maintained-fork API opens the private dmux presentation spool for one GUI
instance. It is available only with `dmux_managed_gui = true`.

The runtime location is resolved inside WezTerm: Linux uses a verified
`$XDG_RUNTIME_DIR/dmux`, while macOS uses
`confstr(_CS_DARWIN_USER_TEMP_DIR)/dmux`. No caller-supplied path,
`DMUX_RUNTIME_DIR`, or `$TMPDIR` is accepted. Directories remain open by file
descriptor; child files use no-follow, current-user, mode-0600 checks and
atomic no-replace publication where replay evidence must be immutable.

Opening returns a userdata handle and acquires an exclusive lease for the GUI
instance, bound to the current PID and process start token. A duplicate live
consumer fails with `dmux_bridge_duplicate_instance`.

The narrow methods are:

* `key()`
* `identity()`
* `write_heartbeat_atomic(body)`
* `next_request(maximum)`
* `read_consumed(uid, maximum)`
* `consume_request_new(uid)`
* `discard_observed_request(uid)`
* `consume_launcher_witness(origin)`
* `resident_brokered()`
* `read_ack(uid, maximum)`
* `write_ack_new(uid, body)`
* `write_replay_ack_new(uid, body)`
* `complete_safe_lifecycle(uid, platform_action)`
* `read_context(pane_id, maximum)`

They accept identifiers and bounded documents, never filesystem paths or
arbitrary spool kinds. `next_request` may return `maximum + 1` bytes solely so
the bridge can consume and acknowledge an oversized request without parsing
or dispatching it. All other reads enforce the exact bound. Existing or
corrupt consumed/ack evidence is never overwritten.

`complete_safe_lifecycle` is the only managed quit/hide primitive. It accepts
only an exact unexpired `safe_quit` finish request and its matching durable
primary acknowledgement, verifies their HMAC/digest, GUI PID/start-token and
platform action, and consumes that proof once before application-scoped
completion. It is not exposed on `wezterm.gui`, a GUI window, or a key action.

The related read-only
`wezterm.gui.dmux_read_mux_descriptor(maximum)` function returns the fixed
`wez-dmux.json` runtime descriptor as bounded raw bytes (or `nil` when absent)
through the same verified runtime-directory and no-follow file checks. The
caller supplies no path and must still strictly validate the descriptor's JSON
schema and identity fields.
