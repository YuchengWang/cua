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

use crate::os_events::{ensure_watchers_active, global_os_event_bus, OsEventFilter};

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
                        "description": "Optional event kind filters (e.g. window.create, window.activate, window.destroy, document.load_complete, document.reload, object.children_changed.add, object.children_changed.remove, object.state_changed.showing, x11.popup_map, x11.popup_unmap; prefix like 'window' also matches)."
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
        let text = format!(
            "Polled {} OS event(s) (next_cursor={}, latest_seq={}, gaps_detected={}).",
            result.count, result.next_cursor, result.latest_seq, result.gaps_detected
        );
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
                        "description": "Optional event kind filters (e.g. window.create, window.activate, document.load_complete, object.state_changed.showing, x11.popup_map)."
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
        let text = if let Some(ref ev) = result.event {
            format!(
                "Matched OS event seq={} kind={} pid={:?} role={:?} name={:?} in {}ms.",
                ev.seq, ev.kind, ev.pid, ev.role, ev.name, result.elapsed_ms
            )
        } else {
            format!(
                "Timed out waiting for OS event after {}ms (next_cursor={}).",
                result.elapsed_ms, result.next_cursor
            )
        };
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
}
