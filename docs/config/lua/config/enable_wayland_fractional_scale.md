---
tags:
  - appearance
---
# `enable_wayland_fractional_scale = true`

{{since('nightly')}}

If `false`, ignore the `wp_fractional_scale_v1` protocol and fall back to the
integer `wl_output` scale.

When a Wayland compositor is configured with a fractional scale such as `1.5`,
the integer scale reported by `wl_output` is rounded up to the next whole
number (`2`). WezTerm then renders an oversized buffer which the compositor
downsamples to the real scale, which softens text.

When this option is enabled and the compositor supports both
`wp_fractional_scale_v1` and `wp_viewporter`, WezTerm instead renders at the
exact fractional scale and uses `wp_viewport` to map the buffer onto the
logical surface size, so the result is presented without resampling.

This option is only considered on Wayland, and has no effect on compositors
that do not support both protocols.

Setting [dpi](dpi.md) also disables fractional scaling, because an explicit
dpi decouples the rendering metrics from the compositor's scale.

The value is read when the Wayland connection is established, so changing it
requires restarting WezTerm rather than just reloading the configuration.

```lua
config.enable_wayland_fractional_scale = true
```
