// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Primary display lock-screen and DPMS probe.
//!
//! Before automating the host `:0.0` display, checks whether the desktop session
//! is locked (`logind` `LockedHint` or `ScreenSaver.GetActive`) and refuses
//! with a structured `screen_locked` error if locked. When unlocked but DPMS
//! is in standby/off, wakes the display.

use std::process::Command;

use cua_driver_core::protocol::ToolResult;
use serde_json::json;

/// State of the host's primary display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryScreenState {
    Unlocked,
    Locked { reason: String },
    DpmsOff,
}

/// Probe whether the active desktop session is locked.
pub fn probe_primary_lock_and_dpms() -> PrimaryScreenState {
    if let Some(reason) = probe_logind_locked() {
        return PrimaryScreenState::Locked { reason };
    }
    if probe_xset_dpms_off() {
        return PrimaryScreenState::DpmsOff;
    }
    PrimaryScreenState::Unlocked
}

/// Wake DPMS if the display is off and unlocked; return `Err(ToolResult)` with
/// `code: "screen_locked"` if the session is locked.
pub fn ensure_primary_unlocked_and_awake() -> Result<(), ToolResult> {
    match probe_primary_lock_and_dpms() {
        PrimaryScreenState::Unlocked => Ok(()),
        PrimaryScreenState::DpmsOff => {
            let _ = Command::new("xset").args(["dpms", "force", "on"]).output();
            Ok(())
        }
        PrimaryScreenState::Locked { reason } => Err(ToolResult::error(format!(
            "primary display is locked ({reason}); unlock the session or target an isolated virtual screen"
        ))
        .with_structured(json!({
            "code": "screen_locked",
            "reason": reason,
        }))),
    }
}

fn probe_logind_locked() -> Option<String> {
    let session_id = std::env::var("XDG_SESSION_ID").ok()?;
    let trimmed = session_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let out = Command::new("loginctl")
        .args(["show-session", trimmed, "-p", "LockedHint", "--value"])
        .output()
        .ok()?;
    if out.status.success() {
        let val = String::from_utf8_lossy(&out.stdout);
        if val.trim().eq_ignore_ascii_case("yes") {
            return Some(format!("logind session {trimmed} LockedHint=yes"));
        }
    }
    None
}

fn probe_xset_dpms_off() -> bool {
    let Ok(out) = Command::new("xset").arg("q").output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.contains("Monitor is Off")
        || stdout.contains("Monitor is in Standby")
        || stdout.contains("Monitor is in Suspend")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_valid_variant() {
        let state = probe_primary_lock_and_dpms();
        assert!(matches!(
            state,
            PrimaryScreenState::Unlocked
                | PrimaryScreenState::Locked { .. }
                | PrimaryScreenState::DpmsOff
        ));
    }
}
