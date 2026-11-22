// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tools for managing isolated virtual X11 screens:
//! - `create_virtual_screen`
//! - `list_virtual_screens`
//! - `destroy_virtual_screen`
//! - `launch_in_virtual_screen`

use std::collections::HashMap;

use async_trait::async_trait;
use cua_driver_core::{
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};

use crate::x11::virtual_input::{
    xtest_click, xtest_drag, xtest_focus_window, xtest_hotkey, xtest_press_key, xtest_scroll,
    xtest_type_text,
};
use crate::x11::virtual_screen::{global_virtual_screen_manager, CreateVirtualScreenRequest};

pub(crate) fn resolve_virtual_display_from_args(args: &Value) -> Option<String> {
    let session = args.opt_str("session");
    let explicit = args
        .get("target")
        .and_then(|t| t.get("display_id"))
        .and_then(Value::as_str);
    global_virtual_screen_manager().resolve_display_for_session(session.as_deref(), explicit)
}

fn resolve_target_xy(
    ctx: &crate::x11::context::X11ScreenContext,
    args: &Value,
) -> anyhow::Result<(i16, i16)> {
    let x = args
        .get("x")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow::anyhow!("x is required"))?;
    let y = args
        .get("y")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow::anyhow!("y is required"))?;
    if let Some(wid) = args.opt_u64("window_id") {
        if let Some(info) = crate::x11::window_info_with_context(ctx, wid) {
            return Ok((
                (info.x + x.round() as i32) as i16,
                (info.y + y.round() as i32) as i16,
            ));
        }
    }
    Ok((x.round() as i16, y.round() as i16))
}

pub(crate) async fn virtual_click(display_id: String, args: &Value) -> ToolResult {
    let args = args.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        let (x, y) = resolve_target_xy(&ctx, &args)?;
        let button = match args.opt_str("button").as_deref() {
            Some("right") => 3,
            Some("middle") => 2,
            _ => 1,
        };
        xtest_click(&ctx, x, y, button)?;
        Ok(ToolResult::text(format!("Clicked ({x}, {y}) on {display_id}"))
            .with_structured(json!({ "display_id": display_id, "x": x, "y": y, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual click failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual click panicked: {e}")),
    }
}

pub(crate) async fn virtual_type_text(display_id: String, args: &Value) -> ToolResult {
    let Some(text) = args.opt_str("text") else {
        return ToolResult::error("text is required");
    };
    let window_id = args.opt_u64("window_id");
    let pid = args.opt_u64("pid").map(|v| v as u32);
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        let focus_wid = window_id.or_else(|| {
            pid.and_then(|p| {
                crate::x11::list_windows_with_context(&ctx, Some(p))
                    .into_iter()
                    .next()
                    .map(|w| w.xid)
            })
        });
        if let Some(wid) = focus_wid {
            xtest_focus_window(&ctx, wid)?;
        }
        xtest_type_text(&ctx, &text)?;
        Ok(ToolResult::text(format!("Typed {} chars on {display_id}", text.chars().count()))
            .with_structured(json!({ "display_id": display_id, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual type_text failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual type_text panicked: {e}")),
    }
}

pub(crate) async fn virtual_press_key(display_id: String, args: &Value) -> ToolResult {
    let Some(key) = args.opt_str("key") else {
        return ToolResult::error("key is required");
    };
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        xtest_press_key(&ctx, &key)?;
        Ok(ToolResult::text(format!("Pressed '{key}' on {display_id}"))
            .with_structured(json!({ "display_id": display_id, "key": key, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual press_key failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual press_key panicked: {e}")),
    }
}

pub(crate) async fn virtual_hotkey(display_id: String, args: &Value) -> ToolResult {
    let keys: Vec<String> = args
        .get("keys")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        return ToolResult::error("keys is required");
    }
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        xtest_hotkey(&ctx, &keys)?;
        Ok(ToolResult::text(format!("Pressed hotkey on {display_id}"))
            .with_structured(json!({ "display_id": display_id, "keys": keys, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual hotkey failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual hotkey panicked: {e}")),
    }
}

pub(crate) async fn virtual_scroll(display_id: String, args: &Value) -> ToolResult {
    let args = args.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        let (x, y) = resolve_target_xy(&ctx, &args).unwrap_or((0, 0));
        let amount = args.get("amount").and_then(Value::as_i64).unwrap_or(3) as i32;
        let (dx, dy) = match args.opt_str("direction").as_deref() {
            Some("up") => (0, amount),
            Some("down") => (0, -amount),
            Some("left") => (-amount, 0),
            Some("right") => (amount, 0),
            _ => (0, -amount),
        };
        xtest_scroll(&ctx, x, y, dx, dy)?;
        Ok(ToolResult::text(format!("Scrolled on {display_id}"))
            .with_structured(json!({ "display_id": display_id, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual scroll failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual scroll panicked: {e}")),
    }
}

pub(crate) async fn virtual_drag(display_id: String, args: &Value) -> ToolResult {
    let args = args.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        let x1 = args
            .get("start_x")
            .or_else(|| args.get("from_x"))
            .and_then(Value::as_f64)
            .ok_or_else(|| anyhow::anyhow!("start_x is required"))?
            .round() as i16;
        let y1 = args
            .get("start_y")
            .or_else(|| args.get("from_y"))
            .and_then(Value::as_f64)
            .ok_or_else(|| anyhow::anyhow!("start_y is required"))?
            .round() as i16;
        let x2 = args
            .get("end_x")
            .or_else(|| args.get("to_x"))
            .and_then(Value::as_f64)
            .ok_or_else(|| anyhow::anyhow!("end_x is required"))?
            .round() as i16;
        let y2 = args
            .get("end_y")
            .or_else(|| args.get("to_y"))
            .and_then(Value::as_f64)
            .ok_or_else(|| anyhow::anyhow!("end_y is required"))?
            .round() as i16;
        xtest_drag(&ctx, x1, y1, x2, y2, 1)?;
        Ok(ToolResult::text(format!("Dragged ({x1},{y1})->({x2},{y2}) on {display_id}"))
            .with_structured(json!({ "display_id": display_id, "ok": true })))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual drag failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual drag panicked: {e}")),
    }
}

fn build_virtual_window_state_output(
    info: &crate::x11::WindowInfo,
    fallback_pid: Option<u32>,
    png_bytes: &[u8],
) -> cua_driver_contract::WindowStateOutput {
    let (shot_w, shot_h) = cua_driver_core::image_utils::png_dimensions(png_bytes)
        .unwrap_or((info.width, info.height));
    let (screenshot_width, screenshot_height) = if shot_w > 0 && shot_h > 0 {
        (Some(shot_w), Some(shot_h))
    } else {
        (None, None)
    };
    cua_driver_contract::WindowStateOutput {
        pid: info.pid.or(fallback_pid).unwrap_or(0),
        window_id: info.xid,
        snapshot_id: None,
        app_name: (!info.app_name.is_empty()).then(|| info.app_name.clone()),
        window_title: (!info.title.is_empty()).then(|| info.title.clone()),
        tree_markdown: None,
        elements: None,
        observations: None,
        observations_truncated: None,
        element_count: None,
        total_element_count: None,
        returned_element_count: None,
        filtered_element_count: None,
        elements_complete: None,
        degraded: None,
        degraded_reason: None,
        truncated: None,
        truncation_reason: None,
        truncation_hint: None,
        tree_format: None,
        since: None,
        since_status: None,
        tree_diff: None,
        screenshot_width,
        screenshot_height,
        screenshot_scale: None,
        screenshot_mime_type: Some("image/png".to_owned()),
        screenshot_file_path: None,
        screenshot_frame_valid: Some(true),
        window_bounds: Some(cua_driver_contract::WindowBounds {
            x: f64::from(info.x),
            y: f64::from(info.y),
            width: f64::from(info.width),
            height: f64::from(info.height),
        }),
        images: Vec::new(),
    }
}

pub(crate) async fn virtual_get_window_state(display_id: String, args: &Value) -> ToolResult {
    let args = args.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
        let ctx = global_virtual_screen_manager().connect_context(&display_id)?;
        let pid = args.opt_u64("pid").map(|v| v as u32);
        let xid = args.opt_u64("window_id").or_else(|| {
            crate::x11::list_windows_with_context(&ctx, pid)
                .into_iter()
                .next()
                .map(|w| w.xid)
        });
        let Some(xid) = xid else {
            anyhow::bail!("no matching window found on {display_id}");
        };
        let info = crate::x11::window_info_with_context(&ctx, xid)
            .ok_or_else(|| anyhow::anyhow!("window {xid} not found on {display_id}"))?;
        let png = crate::capture::screenshot_window_bytes_with_context(&ctx, xid)?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &png);
        let output = build_virtual_window_state_output(&info, pid, &png);
        let structured = serde_json::to_value(&output)?;
        let mut res = ToolResult::text(format!(
            "Window {} (\"{}\") on {} ({}x{})",
            info.xid, info.title, ctx.display_id, info.width, info.height
        ))
        .with_structured(structured);
        res.content
            .push(cua_driver_core::protocol::Content::image_png(b64));
        Ok(res)
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => ToolResult::error(format!("virtual get_window_state failed: {e:#}")),
        Err(e) => ToolResult::error(format!("virtual get_window_state panicked: {e}")),
    }
}

// ── create_virtual_screen ─────────────────────────────────────────────────────

pub struct CreateVirtualScreenTool;
static CREATE_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for CreateVirtualScreenTool {
    fn def(&self) -> &ToolDef {
        CREATE_DEF.get_or_init(|| ToolDef {
            name: "create_virtual_screen".into(),
            description: "Create an isolated virtual X11 display (Xvfb + Openbox + D-Bus) in :99..:199 with an independent 0600 XAUTHORITY cookie.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "width": { "type": "integer", "minimum": 320, "maximum": 7680 },
                    "height": { "type": "integer", "minimum": 240, "maximum": 4320 },
                    "preferred_display": { "type": "integer", "minimum": 99, "maximum": 199 },
                    "enable_vnc": { "type": "boolean", "description": "Optional localhost view-only x11vnc with 0600 random passwdfile." },
                    "vnc_interactive": { "type": "boolean", "description": "Allow interactive VNC input when enable_vnc is true (still bound to localhost with 0600 passwdfile). Default false (-viewonly)." },
                    "session": cua_driver_core::tool_schema::session_schema()
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let req = CreateVirtualScreenRequest {
            width: args.opt_u64("width").map(|v| v as u16),
            height: args.opt_u64("height").map(|v| v as u16),
            preferred_display: args.opt_u64("preferred_display").map(|v| v as u16),
            enable_vnc: args.bool_or("enable_vnc", false),
            vnc_interactive: args.bool_or("vnc_interactive", false),
            session_id: args.opt_str("session"),
        };
        match tokio::task::spawn_blocking(move || global_virtual_screen_manager().create(req)).await
        {
            Ok(Ok(info)) => {
                let text = format!(
                    "Created virtual X11 screen {} ({}x{})",
                    info.display_id, info.width, info.height
                );
                ToolResult::text(text).with_structured(json!({ "screen": info }))
            }
            Ok(Err(e)) => ToolResult::error(format!("create_virtual_screen failed: {e:#}")),
            Err(e) => ToolResult::error(format!("create_virtual_screen panicked: {e}")),
        }
    }
}

// ── list_virtual_screens ──────────────────────────────────────────────────────

pub struct ListVirtualScreensTool;
static LIST_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for ListVirtualScreensTool {
    fn def(&self) -> &ToolDef {
        LIST_DEF.get_or_init(|| ToolDef {
            name: "list_virtual_screens".into(),
            description: "List active isolated virtual X11 screens managed by this driver.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
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
        let session_filter = args.opt_str("session");
        let mut screens = global_virtual_screen_manager().list();
        if let Some(ref sid) = session_filter {
            screens.retain(|s| s.session_id.as_deref() == Some(sid.as_str()));
        }
        ToolResult::text(format!("Found {} virtual screens.", screens.len()))
            .with_structured(json!({ "screens": screens }))
    }
}

// ── destroy_virtual_screen ────────────────────────────────────────────────────

pub struct DestroyVirtualScreenTool;
static DESTROY_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for DestroyVirtualScreenTool {
    fn def(&self) -> &ToolDef {
        DESTROY_DEF.get_or_init(|| ToolDef {
            name: "destroy_virtual_screen".into(),
            description: "Terminate an isolated virtual X11 screen and clean up its processes, Xauthority, and locks.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["display_id"],
                "properties": {
                    "display_id": { "type": "string" }
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let Some(display_id) = args.opt_str("display_id") else {
            return ToolResult::error("display_id is required");
        };
        if !cua_driver_core::action_target::is_valid_display_id(&display_id)
            || display_id == "primary"
        {
            return ToolResult::error(format!(
                "invalid virtual display_id '{display_id}': expected ':99'..':199'"
            ));
        }
        match tokio::task::spawn_blocking(move || {
            global_virtual_screen_manager().destroy(&display_id)
        })
        .await
        {
            Ok(Ok(())) => ToolResult::text("Destroyed virtual screen.")
                .with_structured(json!({ "destroyed": true })),
            Ok(Err(e)) => ToolResult::error(format!("destroy_virtual_screen failed: {e:#}")),
            Err(e) => ToolResult::error(format!("destroy_virtual_screen panicked: {e}")),
        }
    }
}

// ── launch_in_virtual_screen ──────────────────────────────────────────────────

pub struct LaunchInVirtualScreenTool;
static LAUNCH_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for LaunchInVirtualScreenTool {
    fn def(&self) -> &ToolDef {
        LAUNCH_DEF.get_or_init(|| ToolDef {
            name: "launch_in_virtual_screen".into(),
            description: "Launch an application inside an isolated virtual X11 screen with DISPLAY, XAUTHORITY, DBUS_SESSION_BUS_ADDRESS, _JAVA_AWT_WM_NONREPARENTING=1, and GTK_IM_MODULE=xim injected.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["display_id", "command"],
                "properties": {
                    "display_id": { "type": "string" },
                    "command": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "string" } },
                    "env": { "type": "object", "additionalProperties": { "type": "string" } }
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let Some(display_id) = args.opt_str("display_id") else {
            return ToolResult::error("display_id is required");
        };
        let Some(command) = args.opt_str("command") else {
            return ToolResult::error("command is required");
        };
        let cmd_args: Vec<String> = args
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let extra_env: HashMap<String, String> = args
            .get("env")
            .and_then(Value::as_object)
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();

        match tokio::task::spawn_blocking(move || {
            global_virtual_screen_manager().launch_app(&display_id, &command, &cmd_args, &extra_env)
        })
        .await
        {
            Ok(Ok(launched)) => {
                let text = format!(
                    "Launched '{}' (pid={}) on {}",
                    launched.command, launched.pid, launched.display_id
                );
                ToolResult::text(text).with_structured(json!({ "launched": launched }))
            }
            Ok(Err(e)) => ToolResult::error(format!("launch_in_virtual_screen failed: {e:#}")),
            Err(e) => ToolResult::error(format!("launch_in_virtual_screen panicked: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_virtual_window_state_output;

    #[test]
    fn virtual_window_state_output_matches_contract_even_without_wm_pid() {
        let info_no_pid = crate::x11::WindowInfo {
            xid: 0x0040_0007,
            pid: None,
            app_name: "XTerm".to_owned(),
            title: "xterm".to_owned(),
            is_on_screen: true,
            z_index: None,
            x: 10,
            y: 20,
            width: 640,
            height: 480,
        };
        let out_no_pid = build_virtual_window_state_output(&info_no_pid, None, &[]);
        let val_no_pid = serde_json::to_value(&out_no_pid).expect("serialize WindowStateOutput");
        assert_eq!(val_no_pid["pid"], 0);
        assert_eq!(val_no_pid["window_id"], 0x0040_0007_u64);
        assert_eq!(val_no_pid["screenshot_width"], 640);
        assert_eq!(val_no_pid["screenshot_height"], 480);
        cua_driver_contract::validate_success_output("get_window_state", val_no_pid)
            .expect("missing _NET_WM_PID must not cause typed_output_mismatch");

        let info_with_pid = crate::x11::WindowInfo {
            pid: Some(4242),
            ..info_no_pid
        };
        let out_with_pid = build_virtual_window_state_output(&info_with_pid, Some(9999), &[]);
        let val_with_pid = serde_json::to_value(&out_with_pid).expect("serialize WindowStateOutput");
        assert_eq!(val_with_pid["pid"], 4242);
        cua_driver_contract::validate_success_output("get_window_state", val_with_pid)
            .expect("WindowStateOutput with pid must pass contract validation");
    }
}
