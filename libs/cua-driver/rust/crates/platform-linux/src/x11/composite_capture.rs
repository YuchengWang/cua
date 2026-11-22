// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! XComposite offscreen window capture (`XCompositeRedirectWindow` +
//! `XCompositeNameWindowPixmap`).
//!
//! Captures the complete backing pixmap of a mapped window even when it is
//! occluded by other windows, and frees the named pixmap via RAII (`Drop`) to
//! prevent X server resource leaks. Gracefully returns [`CompositeCaptureOutcome::UnmappedFallback`]
//! when the window is unmapped (`IsUnmapped` / `MapState::UNMAPPED`).

use anyhow::{anyhow, Result};
use x11rb::connection::Connection as _;
use x11rb::protocol::composite::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ConnectionExt as _, MapState, Pixmap, Window};
use x11rb::rust_connection::RustConnection;

use crate::capture::{read_drawable_rgba_with_visual, PixelCatalog, Rect};

/// Result of attempting XComposite offscreen window capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeCaptureOutcome {
    /// PNG-encoded offscreen window image.
    Captured(Vec<u8>),
    /// Window is unmapped (`IsUnmapped`) or Composite backing pixmap is unavailable;
    /// callers should fall back gracefully.
    UnmappedFallback { reason: String },
}

/// RAII guard ensuring `free_pixmap` is always sent on scope exit.
struct PixmapGuard<'a> {
    conn: &'a RustConnection,
    pixmap: Pixmap,
}

impl Drop for PixmapGuard<'_> {
    fn drop(&mut self) {
        let _ = self.conn.free_pixmap(self.pixmap);
        let _ = self.conn.flush();
    }
}

/// Returns `true` when `map_state` means the window has no backing pixmap.
pub(crate) fn should_fallback_for_map_state(map_state: MapState) -> bool {
    map_state == MapState::UNMAPPED
}

/// Capture `window` offscreen via XComposite (`Redirect::AUTOMATIC` + `NameWindowPixmap`).
pub fn capture_window_composite(
    conn: &RustConnection,
    window: Window,
) -> Result<CompositeCaptureOutcome> {
    let version = conn
        .composite_query_version(0, 4)
        .map_err(|e| anyhow!("CompositeQueryVersion request failed: {e}"))?
        .reply()
        .map_err(|e| anyhow!("CompositeQueryVersion reply failed: {e}"))?;
    if version.major_version == 0 && version.minor_version < 2 {
        return Ok(CompositeCaptureOutcome::UnmappedFallback {
            reason: format!(
                "XComposite {}.{} < 0.2 (NameWindowPixmap unsupported)",
                version.major_version, version.minor_version
            ),
        });
    }

    let attrs = conn
        .get_window_attributes(window)
        .map_err(|e| anyhow!("GetWindowAttributes request failed: {e}"))?
        .reply()
        .map_err(|e| anyhow!("GetWindowAttributes reply failed: {e}"))?;
    if should_fallback_for_map_state(attrs.map_state) {
        return Ok(CompositeCaptureOutcome::UnmappedFallback {
            reason: "window is unmapped (MapState::UNMAPPED)".to_owned(),
        });
    }

    // `Redirect::AUTOMATIC` is idempotent if already redirected by the WM.
    if let Err(err) = conn
        .composite_redirect_window(window, composite::Redirect::AUTOMATIC)
        .map_err(|e| anyhow!("CompositeRedirectWindow request failed: {e}"))?
        .check()
    {
        return Ok(CompositeCaptureOutcome::UnmappedFallback {
            reason: format!("CompositeRedirectWindow failed: {err}"),
        });
    }

    let pixmap = conn
        .generate_id()
        .map_err(|e| anyhow!("generate_id for composite pixmap failed: {e}"))?;

    if let Err(err) = conn
        .composite_name_window_pixmap(window, pixmap)
        .map_err(|e| anyhow!("CompositeNameWindowPixmap request failed: {e}"))?
        .check()
    {
        return Ok(CompositeCaptureOutcome::UnmappedFallback {
            reason: format!("CompositeNameWindowPixmap unavailable (IsUnmapped/BadMatch): {err}"),
        });
    }

    // Guarantee `free_pixmap` on every exit path.
    let _pixmap_guard = PixmapGuard { conn, pixmap };

    let geom = conn
        .get_geometry(pixmap)
        .map_err(|e| anyhow!("GetGeometry on composite pixmap failed: {e}"))?
        .reply()
        .map_err(|e| anyhow!("GetGeometry reply on composite pixmap failed: {e}"))?;

    let w = u32::from(geom.width);
    let h = u32::from(geom.height);
    if w == 0 || h == 0 {
        return Ok(CompositeCaptureOutcome::UnmappedFallback {
            reason: "composite pixmap has 0x0 geometry".to_owned(),
        });
    }

    let pixels = PixelCatalog::from_setup(conn.setup());
    let rect = Rect { x: 0, y: 0, w, h };
    // X11 GetImage on a Pixmap always returns visual=0; decode using the
    // owning window's attrs.visual instead.
    let rgba =
        read_drawable_rgba_with_visual(conn, &pixels, pixmap, rect, false, Some(attrs.visual))?;
    let png = cua_driver_core::image_utils::encode_rgba_to_png(&rgba, w, h)?;
    Ok(CompositeCaptureOutcome::Captured(png))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_state_triggers_graceful_fallback() {
        assert!(should_fallback_for_map_state(MapState::UNMAPPED));
        assert!(!should_fallback_for_map_state(MapState::VIEWABLE));
        assert!(!should_fallback_for_map_state(MapState::UNVIEWABLE));
    }

    #[test]
    fn outcome_variants_distinguish_capture_and_fallback() {
        let captured = CompositeCaptureOutcome::Captured(vec![1, 2, 3]);
        assert!(matches!(captured, CompositeCaptureOutcome::Captured(_)));

        let fallback = CompositeCaptureOutcome::UnmappedFallback {
            reason: "IsUnmapped".to_owned(),
        };
        assert!(matches!(
            fallback,
            CompositeCaptureOutcome::UnmappedFallback { .. }
        ));
    }
}
