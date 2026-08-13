//! Fractional scaling via wp_fractional_scale_v1.
//!
//! Without this the compositor rounds a fractional scale up to the next
//! integer (1.5 becomes 2), we render an oversized buffer, and the
//! compositor downsamples it, which softens text.

use smithay_client_toolkit::globals::GlobalData;
use wayland_client::globals::{BindError, GlobalList};
use wayland_client::protocol::wl_surface::WlSurface;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols::wp::fractional_scale::v1::client::wp_fractional_scale_manager_v1::WpFractionalScaleManagerV1;
use wayland_protocols::wp::fractional_scale::v1::client::wp_fractional_scale_v1::{
    Event as FractionalScaleEvent, WpFractionalScaleV1,
};
use wayland_protocols::wp::viewporter::client::wp_viewport::WpViewport;
use wayland_protocols::wp::viewporter::client::wp_viewporter::WpViewporter;

use super::state::WaylandState;
use super::WaylandConnection;

/// The protocol reports the preferred scale in units of 1/120.
const SCALE_DENOMINATOR: f64 = 120.;

/// Associates a wp_fractional_scale_v1 object with the window it scales.
pub(super) struct FractionalScaleData {
    window_id: usize,
}

/// wp_viewporter is required alongside wp_fractional_scale_v1: the former
/// reports the scale, the latter maps the scaled buffer back onto the
/// logical surface size. Fractional scaling is only enabled when both are
/// available.
pub(super) struct FractionalScaleState {
    manager: WpFractionalScaleManagerV1,
    viewporter: WpViewporter,
}

impl FractionalScaleState {
    pub(super) fn bind(
        globals: &GlobalList,
        qh: &QueueHandle<WaylandState>,
    ) -> Result<Self, BindError> {
        let manager = globals.bind(qh, 1..=1, GlobalData)?;
        let viewporter = globals.bind(qh, 1..=1, GlobalData)?;
        Ok(Self {
            manager,
            viewporter,
        })
    }

    pub(super) fn attach(
        &self,
        surface: &WlSurface,
        window_id: usize,
        qh: &QueueHandle<WaylandState>,
    ) -> (WpFractionalScaleV1, WpViewport) {
        let scale =
            self.manager
                .get_fractional_scale(surface, qh, FractionalScaleData { window_id });
        let viewport = self.viewporter.get_viewport(surface, qh, GlobalData);
        (scale, viewport)
    }
}

impl Dispatch<WpFractionalScaleManagerV1, GlobalData> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &WpFractionalScaleManagerV1,
        _event: <WpFractionalScaleManagerV1 as Proxy>::Event,
        _data: &GlobalData,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // Panicking inside a Wayland dispatch would take down the GUI.
        log::warn!("unexpected wp_fractional_scale_manager_v1 event");
    }
}

impl Dispatch<WpViewporter, GlobalData> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &WpViewporter,
        _event: <WpViewporter as Proxy>::Event,
        _data: &GlobalData,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // Panicking inside a Wayland dispatch would take down the GUI.
        log::warn!("unexpected wp_viewporter event");
    }
}

impl Dispatch<WpViewport, GlobalData> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &WpViewport,
        _event: <WpViewport as Proxy>::Event,
        _data: &GlobalData,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // Panicking inside a Wayland dispatch would take down the GUI.
        log::warn!("unexpected wp_viewport event");
    }
}

impl Dispatch<WpFractionalScaleV1, FractionalScaleData> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &WpFractionalScaleV1,
        event: <WpFractionalScaleV1 as Proxy>::Event,
        data: &FractionalScaleData,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let FractionalScaleEvent::PreferredScale { scale } = event else {
            return;
        };
        // A zero or absurd scale would propagate into a zero dpi and divide by
        // zero in pixels_to_surface; clamp to the same range connection.rs uses.
        let factor = (scale as f64 / SCALE_DENOMINATOR).clamp(0.1, 16.);
        log::trace!(
            "wp_fractional_scale_v1: preferred_scale {scale} ({factor}) for window {}",
            data.window_id
        );
        WaylandConnection::with_window_inner(data.window_id, move |inner| {
            inner.fractional_scale_changed(factor);
            Ok(())
        });
    }
}
