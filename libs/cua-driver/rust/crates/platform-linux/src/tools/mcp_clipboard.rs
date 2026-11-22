// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Isolated clipboard MCP tools:
//! - `get_clipboard`
//! - `set_clipboard`
//! - `sync_clipboard` (explicit one-shot transfer only; never automatic)

use async_trait::async_trait;
use cua_driver_core::{
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};

use crate::x11::context::{global_screen_pool, DisplayTarget};
use crate::x11::virtual_input::{clipboard_get_for_context, clipboard_set_for_context};
use crate::x11::virtual_screen::global_virtual_screen_manager;

fn resolve_target_display(args: &Value) -> Result<DisplayTarget, ToolResult> {
    let explicit = args.opt_str("display_id");
    let session = args.opt_str("session");
    if let Some(id) =
        global_virtual_screen_manager().resolve_display_for_session(session.as_deref(), explicit.as_deref())
    {
        return DisplayTarget::from_display_id(Some(&id))
            .map_err(|e| ToolResult::error(format!("invalid display_id: {e:#}")));
    }
    DisplayTarget::from_display_id(explicit.as_deref())
        .map_err(|e| ToolResult::error(format!("invalid display_id: {e:#}")))
}

pub struct GetClipboardTool;
static GET_CB_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for GetClipboardTool {
    fn def(&self) -> &ToolDef {
        GET_CB_DEF.get_or_init(|| ToolDef {
            name: "get_clipboard".into(),
            description: "Read CLIPBOARD text from a specific X11 display (primary or virtual) without cross-display auto-sync.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema()
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
        let target = match resolve_target_display(&args) {
            Ok(t) => t,
            Err(r) => return r,
        };
        match tokio::task::spawn_blocking(move || {
            let ctx = global_screen_pool().get_or_connect(&target)?;
            let text = clipboard_get_for_context(&ctx)?;
            Ok::<_, anyhow::Error>((ctx.display_id.clone(), text))
        })
        .await
        {
            Ok(Ok((display_id, text))) => ToolResult::text(text.clone()).with_structured(json!({
                "display_id": display_id,
                "text": text,
            })),
            Ok(Err(e)) => ToolResult::error(format!("get_clipboard failed: {e:#}")),
            Err(e) => ToolResult::error(format!("get_clipboard panicked: {e}")),
        }
    }
}

pub struct SetClipboardTool;
static SET_CB_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for SetClipboardTool {
    fn def(&self) -> &ToolDef {
        SET_CB_DEF.get_or_init(|| ToolDef {
            name: "set_clipboard".into(),
            description: "Write UTF-8 text to CLIPBOARD on a specific X11 display (primary or virtual).".into(),
            input_schema: json!({
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": { "type": "string" },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema()
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let Some(text) = args.opt_str("text") else {
            return ToolResult::error("text is required");
        };
        let target = match resolve_target_display(&args) {
            Ok(t) => t,
            Err(r) => return r,
        };
        match tokio::task::spawn_blocking(move || {
            let ctx = global_screen_pool().get_or_connect(&target)?;
            clipboard_set_for_context(&ctx, &text)?;
            Ok::<_, anyhow::Error>(ctx.display_id.clone())
        })
        .await
        {
            Ok(Ok(display_id)) => ToolResult::text(format!("Updated clipboard on {display_id}"))
                .with_structured(json!({ "display_id": display_id, "ok": true })),
            Ok(Err(e)) => ToolResult::error(format!("set_clipboard failed: {e:#}")),
            Err(e) => ToolResult::error(format!("set_clipboard panicked: {e}")),
        }
    }
}

pub struct SyncClipboardTool;
static SYNC_CB_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for SyncClipboardTool {
    fn def(&self) -> &ToolDef {
        SYNC_CB_DEF.get_or_init(|| ToolDef {
            name: "sync_clipboard".into(),
            description: "Explicitly copy CLIPBOARD text once from source_display_id to target_display_id.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["source_display_id", "target_display_id"],
                "properties": {
                    "source_display_id": { "type": "string" },
                    "target_display_id": { "type": "string" }
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let Some(src) = args.opt_str("source_display_id") else {
            return ToolResult::error("source_display_id is required");
        };
        let Some(dst) = args.opt_str("target_display_id") else {
            return ToolResult::error("target_display_id is required");
        };
        let src_target = match DisplayTarget::from_display_id(Some(&src)) {
            Ok(t) => t,
            Err(e) => return ToolResult::error(format!("invalid source_display_id: {e:#}")),
        };
        let dst_target = match DisplayTarget::from_display_id(Some(&dst)) {
            Ok(t) => t,
            Err(e) => return ToolResult::error(format!("invalid target_display_id: {e:#}")),
        };
        match tokio::task::spawn_blocking(move || {
            let src_ctx = global_screen_pool().get_or_connect(&src_target)?;
            let dst_ctx = global_screen_pool().get_or_connect(&dst_target)?;
            let text = clipboard_get_for_context(&src_ctx)?;
            clipboard_set_for_context(&dst_ctx, &text)?;
            Ok::<_, anyhow::Error>((src_ctx.display_id.clone(), dst_ctx.display_id.clone(), text.len()))
        })
        .await
        {
            Ok(Ok((s, d, bytes))) => {
                ToolResult::text(format!("Synced {bytes} bytes from {s} to {d}"))
                    .with_structured(json!({
                        "source_display_id": s,
                        "target_display_id": d,
                        "bytes": bytes,
                    }))
            }
            Ok(Err(e)) => ToolResult::error(format!("sync_clipboard failed: {e:#}")),
            Err(e) => ToolResult::error(format!("sync_clipboard panicked: {e}")),
        }
    }
}
