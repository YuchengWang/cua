// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tools for polling and awaiting the unified AT-SPI2 + X11 OS event ring:
//! - `poll_os_events`
//! - `wait_for_os_event`

use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use cua_driver_core::{
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};

use crate::os_events::{
    ensure_watchers_active, global_os_event_bus, OsEvent, OsEventFilter, PollOsEventsResult,
    WaitForOsEventResult, AUTH_GATE_EVENT_KIND, AUTH_GATE_SUGGESTED_ACTION,
};

fn format_auth_gate_line(ev: &OsEvent) -> Option<String> {
    if ev.kind != AUTH_GATE_EVENT_KIND {
        return None;
    }
    let detail = ev.detail.as_ref();
    let window_id = detail
        .and_then(|d| d.get("window_id"))
        .and_then(|v| v.as_u64())
        .or(ev.window_id);
    let pid = detail
        .and_then(|d| d.get("pid"))
        .and_then(|v| v.as_u64())
        .map(|p| p as u32)
        .or(ev.pid);
    let title = detail
        .and_then(|d| d.get("title"))
        .and_then(|v| v.as_str())
        .or(ev.name.as_deref())
        .unwrap_or("");
    let url_hint = detail
        .and_then(|d| d.get("url_hint"))
        .and_then(|v| v.as_str());
    let suggested_action = detail
        .and_then(|d| d.get("suggested_action"))
        .and_then(|v| v.as_str())
        .unwrap_or(AUTH_GATE_SUGGESTED_ACTION);
    let mut parts = Vec::new();
    if let Some(wid) = window_id {
        parts.push(format!("window_id={wid}"));
    }
    if let Some(p) = pid {
        parts.push(format!("pid={p}"));
    }
    parts.push(format!("title={title:?}"));
    if let Some(url) = url_hint {
        parts.push(format!("url_hint={url:?}"));
    }
    parts.push(format!("suggested_action={suggested_action:?}"));
    Some(format!("[AUTH_GATE_DETECTED] {}", parts.join(" ")))
}

fn format_poll_text(result: &PollOsEventsResult) -> String {
    let mut text = format!(
        "Polled {} OS event(s) (next_cursor={}, latest_seq={}, gaps_detected={}).",
        result.count, result.next_cursor, result.latest_seq, result.gaps_detected
    );
    for ev in &result.events {
        if let Some(line) = format_auth_gate_line(ev) {
            text.push('\n');
            text.push_str(&line);
        }
    }
    text
}

fn format_wait_text(result: &WaitForOsEventResult) -> String {
    if let Some(ref ev) = result.event {
        let mut text = format!(
            "Matched OS event seq={} kind={} pid={:?} role={:?} name={:?} in {}ms.",
            ev.seq, ev.kind, ev.pid, ev.role, ev.name, result.elapsed_ms
        );
        if let Some(line) = format_auth_gate_line(ev) {
            text.push('\n');
            text.push_str(&line);
        }
        text
    } else {
        format!(
            "Timed out waiting for OS event after {}ms (next_cursor={}).",
            result.elapsed_ms, result.next_cursor
        )
    }
}

fn parse_filter(args: &Value) -> Result<OsEventFilter, ToolResult> {
    let pid = match args.get("pid") {
        None | Some(Value::Null) => None,
        Some(_) => Some(args.require_u32("pid")?),
    };
    let event_kinds = args.str_array("event_kinds");
    let role = args.opt_str("role");
    let name_regex = args.opt_str("name_regex");
    OsEventFilter::from_params(pid, event_kinds, role, name_regex.as_deref())
        .map_err(|e| ToolResult::error(format!("invalid OS event filter: {e}")))
}

// ── poll_os_events ────────────────────────────────────────────────────────────

pub struct PollOsEventsTool;
static POLL_DEF: OnceLock<ToolDef> = OnceLock::new();

#[async_trait]
impl Tool for PollOsEventsTool {
    fn def(&self) -> &ToolDef {
        POLL_DEF.get_or_init(|| ToolDef {
            name: "poll_os_events".into(),
            description: "Poll buffered OS events (AT-SPI Window/Document/ChildrenChanged/StateChanged(showing) and X11 override-redirect MapNotify/UnmapNotify) from the bounded async event ring using an optional cursor and filters.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "cursor": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Return events with seq > cursor. Omit or pass 0 to scan from the oldest retained event."
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Optional process ID filter."
                    },
                    "event_kinds": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional event kind filters (e.g. window.create, window.activate, window.destroy, document.load_complete, document.reload, object.children_changed.add, object.children_changed.remove, object.state_changed.showing, x11.popup_map, x11.popup_unmap, auth_gate_detected; prefix like 'window' also matches)."
                    },
                    "role": {
                        "type": "string",
                        "description": "Optional case-insensitive AT-SPI role filter (e.g. alert, dialog, push button, popup)."
                    },
                    "name_regex": {
                        "type": "string",
                        "description": "Optional regex matched against event target name or window title."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                        "description": "Maximum number of matching events to return (default 50, max 500)."
                    }
                },
                "additionalProperties": false
            }),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        ensure_watchers_active();
        let filter = match parse_filter(&args) {
            Ok(f) => f,
            Err(err) => return err,
        };
        let cursor = args.opt_u64("cursor");
        let limit = args.u64_or("limit", 50).clamp(1, 500) as usize;
        let result = global_os_event_bus().poll(cursor, &filter, limit);
        let text = format_poll_text(&result);
        ToolResult::text(text).with_structured(json!(result))
    }
}

// ── wait_for_os_event ─────────────────────────────────────────────────────────

pub struct WaitForOsEventTool;
static WAIT_DEF: OnceLock<ToolDef> = OnceLock::new();

#[async_trait]
impl Tool for WaitForOsEventTool {
    fn def(&self) -> &ToolDef {
        WAIT_DEF.get_or_init(|| ToolDef {
            name: "wait_for_os_event".into(),
            description: "Wait asynchronously for the next OS event matching pid, event_kinds, role, and name_regex, starting after cursor (or after the current ring tail when cursor is omitted).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "cursor": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Match events with seq > cursor. Omit to wait only for events arriving after this call begins."
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Optional process ID filter."
                    },
                    "event_kinds": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional event kind filters (e.g. window.create, window.activate, document.load_complete, object.state_changed.showing, x11.popup_map, auth_gate_detected)."
                    },
                    "role": {
                        "type": "string",
                        "description": "Optional case-insensitive AT-SPI role filter."
                    },
                    "name_regex": {
                        "type": "string",
                        "description": "Optional regex matched against event target name or window title."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 100,
                        "maximum": 120_000,
                        "default": 5000,
                        "description": "Maximum wait time in milliseconds (default 5000, min 100, max 120000)."
                    }
                },
                "additionalProperties": false
            }),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        ensure_watchers_active();
        let filter = match parse_filter(&args) {
            Ok(f) => f,
            Err(err) => return err,
        };
        let cursor = args.opt_u64("cursor");
        let timeout_ms = args.u64_or("timeout_ms", 5000).clamp(100, 120_000);
        let result = global_os_event_bus()
            .wait_for(cursor, &filter, Duration::from_millis(timeout_ms))
            .await;
        let text = format_wait_text(&result);
        ToolResult::text(text).with_structured(json!(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_driver_core::tool_schema::shared_schema_violations;

    #[test]
    fn os_event_tools_pass_shared_schema_gate() {
        for tool in [
            PollOsEventsTool.def().clone(),
            WaitForOsEventTool.def().clone(),
        ] {
            let violations = shared_schema_violations(&tool.name, &tool.input_schema);
            assert!(
                violations.is_empty(),
                "{} schema violations: {violations:?}",
                tool.name
            );
        }
    }

    #[test]
    fn poll_and_wait_text_format_auth_gate_detected_details() {
        use crate::os_events::{OsEventBus, OsEventDraft};

        let bus = OsEventBus::new(16);
        bus.push(OsEventDraft {
            source: "atspi".into(),
            kind: "window.activate".into(),
            pid: Some(9001),
            window_id: Some(0x3003),
            role: Some("frame".into()),
            name: Some("Two-factor authentication · GitHub - Google Chrome".into()),
            ..Default::default()
        });

        let poll_res = bus.poll(None, &OsEventFilter::default(), 20);
        let poll_text = format_poll_text(&poll_res);
        assert!(poll_text.contains("[AUTH_GATE_DETECTED]"));
        assert!(poll_text.contains("window_id=12291"));
        assert!(poll_text.contains("pid=9001"));
        assert!(poll_text.contains("url_hint=\"https://github.com\""));
        assert!(poll_text.contains("suggested_action=\"Call resolve_auth_site + focus OTP field + type_totp_from_env or run_app_recipe\""));

        let auth_ev = poll_res
            .events
            .into_iter()
            .find(|e| e.kind == AUTH_GATE_EVENT_KIND)
            .expect("auth_gate_detected event should be present");
        let wait_res = WaitForOsEventResult {
            matched: true,
            timed_out: false,
            event: Some(auth_ev),
            next_cursor: 2,
            elapsed_ms: 5,
        };
        let wait_text = format_wait_text(&wait_res);
        assert!(wait_text.contains("Matched OS event"));
        assert!(wait_text.contains("[AUTH_GATE_DETECTED]"));
        assert!(wait_text.contains("url_hint=\"https://github.com\""));
    }
}
