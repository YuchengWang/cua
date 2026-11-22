// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tools for strong-versioned application flow inspection, recipe
//! generation, and deterministic state-machine execution:
//! - `inspect_app_flow`
//! - `generate_app_recipe`
//! - `run_app_recipe`

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use async_trait::async_trait;
use cua_driver_core::{
    app_recipe::{
        find_best_recipe_for_app, global_recipe_cache, load_recipe, recipes_dir,
        resolve_relative_anchor_xy, save_recipe_to_dir, AppRecipe, AuthGate, ModalHandler,
        RecipeState, RecipeTransition, RelativeAnchor, StateMachine, VerifyResult, VersionGate,
    },
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app_inspector::{inspect_app_flow, InspectAppFlowRequest};
use crate::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};
use crate::x11::virtual_input::{
    clipboard_get_for_context, xtest_click, xtest_focus_window, xtest_hotkey, xtest_press_key,
    xtest_type_text,
};
use crate::x11::virtual_screen::global_virtual_screen_manager;

fn resolve_display_id(args: &Value) -> Option<String> {
    let session = args.opt_str("session");
    let explicit = args.opt_str("display_id");
    global_virtual_screen_manager().resolve_display_for_session(session.as_deref(), explicit.as_deref())
}

// ── inspect_app_flow ──────────────────────────────────────────────────────────

pub struct InspectAppFlowTool;
static INSPECT_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for InspectAppFlowTool {
    fn def(&self) -> &ToolDef {
        INSPECT_DEF.get_or_init(|| ToolDef {
            name: "inspect_app_flow".into(),
            description: "Inspect a running or installed Linux app (X11 WM_CLASS, AT-SPI2 tree, install4j/JAR, .NET deps.json, Electron package.json) and return its version, fp8, tech stack, shortcuts, and menu topology.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "window_id": { "type": "integer" },
                    "app_path": { "type": "string" },
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
        let req = InspectAppFlowRequest {
            pid: args.opt_u64("pid").map(|v| v as u32),
            window_id: args.opt_u64("window_id"),
            app_path: args.opt_str("app_path"),
            display_id: resolve_display_id(&args),
        };
        match tokio::task::spawn_blocking(move || inspect_app_flow(req)).await {
            Ok(Ok(info)) => {
                let text = format!(
                    "{} v{} (fp8={}, stack={}, channel={})",
                    info.app_id, info.app_version, info.fp8, info.tech_stack, info.channel
                );
                ToolResult::text(text).with_structured(json!({ "inspection": info }))
            }
            Ok(Err(e)) => ToolResult::error(format!("inspect_app_flow failed: {e:#}")),
            Err(e) => ToolResult::error(format!("inspect_app_flow panicked: {e}")),
        }
    }
}

// ── generate_app_recipe ───────────────────────────────────────────────────────

pub struct GenerateAppRecipeTool;
static GENERATE_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for GenerateAppRecipeTool {
    fn def(&self) -> &ToolDef {
        GENERATE_DEF.get_or_init(|| ToolDef {
            name: "generate_app_recipe".into(),
            description: "Compile and persist a strong-versioned AppRecipe (<app_id>_v<version>_<fp8>.json) from live inspection or recorded steps.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "app_id": { "type": "string" },
                    "pid": { "type": "integer" },
                    "window_id": { "type": "integer" },
                    "app_path": { "type": "string" },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "recording_steps": { "type": "array", "items": { "type": "object" } },
                    "save": { "type": "boolean" }
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
        let override_app_id = args.opt_str("app_id");
        let save = args.bool_or("save", true);
        let recording_steps = args
            .get("recording_steps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let req = InspectAppFlowRequest {
            pid: args.opt_u64("pid").map(|v| v as u32),
            window_id: args.opt_u64("window_id"),
            app_path: args.opt_str("app_path"),
            display_id: resolve_display_id(&args),
        };

        match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
            let inspection = inspect_app_flow(req)?;
            if inspection.channel == "browser_exempt" {
                return Ok(ToolResult::error(
                    inspection
                        .exempt_reason
                        .clone()
                        .unwrap_or_else(|| "browser_exempt".to_owned()),
                )
                .with_structured(json!({ "inspection": inspection })));
            }

            let app_id = override_app_id.unwrap_or(inspection.app_id.clone());
            let mut transitions = Vec::new();
            let mut states = vec![RecipeState {
                id: "ready".to_owned(),
                description: Some(format!("Initial state for {app_id}")),
                title_regex: inspection.window_title.clone(),
                expected_roles: inspection.sample_roles.clone(),
                auth_gate: None,
                captcha_patterns: vec![
                    "Verify you are human".to_owned(),
                    "CAPTCHA".to_owned(),
                    "Turnstile".to_owned(),
                ],
            }];

            for (idx, step) in recording_steps.iter().enumerate() {
                let from = if idx == 0 {
                    "ready".to_owned()
                } else {
                    format!("step_{idx}")
                };
                let to = format!("step_{}", idx + 1);
                let action = step
                    .get("tool")
                    .or_else(|| step.get("action"))
                    .and_then(Value::as_str)
                    .unwrap_or("press_key")
                    .to_owned();
                let step_args = step.get("args").cloned().unwrap_or_else(|| step.clone());
                states.push(RecipeState {
                    id: to.clone(),
                    description: None,
                    title_regex: None,
                    expected_roles: Vec::new(),
                    auth_gate: None,
                    captcha_patterns: Vec::new(),
                });
                transitions.push(RecipeTransition {
                    from_state: from,
                    to_state: to,
                    action,
                    args: step_args,
                    wait_for_stable_frame_ms: step
                        .get("wait_for_stable_frame_ms")
                        .and_then(Value::as_u64),
                    on_error: step
                        .get("on_error")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                });
            }

            let relative_anchors: Vec<RelativeAnchor> = if !inspection.discovered_anchors.is_empty()
            {
                inspection.discovered_anchors.clone()
            } else {
                inspection
                    .visual_hotspots
                    .iter()
                    .map(|h| RelativeAnchor {
                        name: h.id.clone(),
                        role: None,
                        title_pattern: inspection.window_title.clone(),
                        rel_x: h.rel_x,
                        rel_y: h.rel_y,
                    })
                    .collect()
            };

            let mut modal_handlers = Vec::new();
            if inspection.tech_stack == "java_install4j" {
                modal_handlers.push(ModalHandler {
                    pattern: ".*(Pending Tasks|Login Messages|Warning).*".to_owned(),
                    action: "press_key".to_owned(),
                    key: Some("Escape".to_owned()),
                });
                if transitions.is_empty() {
                    states.push(RecipeState {
                        id: "workspace".to_owned(),
                        description: Some("Main workspace after initial settle".to_owned()),
                        title_regex: None,
                        expected_roles: Vec::new(),
                        auth_gate: None,
                        captcha_patterns: Vec::new(),
                    });
                    transitions.push(RecipeTransition {
                        from_state: "ready".to_owned(),
                        to_state: "workspace".to_owned(),
                        action: "wait_for_stable_frame".to_owned(),
                        args: json!({ "wait_for_stable_frame_ms": 500 }),
                        wait_for_stable_frame_ms: Some(500),
                        on_error: Some("dismiss_modal_and_retry".to_owned()),
                    });
                }
            }

            let recipe = AppRecipe {
                schema_version: 1,
                app_id,
                app_version: inspection.app_version,
                version_source: inspection.version_source,
                fingerprint_sha256: inspection.fingerprint_sha256,
                tech_stack: Some(inspection.tech_stack),
                atspi_blind: inspection.atspi_blind,
                recommended_interaction: Some(inspection.recommended_interaction),
                launch_isolation_hints: inspection.launch_isolation_hints,
                verified_shortcuts: inspection.verified_shortcuts,
                menu_topology: inspection.menu_topology,
                relative_anchors,
                modal_handlers,
                flows: HashMap::new(),
                state_machine: StateMachine {
                    initial_state: "ready".to_owned(),
                    states,
                    transitions,
                },
            };

            let saved_path = if save {
                let dir = recipes_dir()
                    .ok_or_else(|| anyhow::anyhow!("cannot resolve app_recipes directory"))?;
                Some(
                    save_recipe_to_dir(&dir, &recipe)
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .display()
                        .to_string(),
                )
            } else {
                None
            };

            global_recipe_cache().insert(recipe.clone());
            Ok(ToolResult::text(format!(
                "Generated recipe {}",
                recipe.canonical_filename()
            ))
            .with_structured(json!({
                "recipe": recipe,
                "saved_path": saved_path,
            })))
        })
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => ToolResult::error(format!("generate_app_recipe failed: {e:#}")),
            Err(e) => ToolResult::error(format!("generate_app_recipe panicked: {e}")),
        }
    }
}

// ── run_app_recipe ────────────────────────────────────────────────────────────

pub struct RunAppRecipeTool;
static RUN_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for RunAppRecipeTool {
    fn def(&self) -> &ToolDef {
        RUN_DEF.get_or_init(|| ToolDef {
            name: "run_app_recipe".into(),
            description: "Execute a strong-versioned AppRecipe state machine with VersionGate verification, in-memory hot cache, out-of-band zeroized auth_gate, and human_verification_required CAPTCHA pause.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["app_id"],
                "properties": {
                    "app_id": { "type": "string" },
                    "flow": { "type": "string", "description": "Optional named flow in recipe.flows to execute with fast non-screenshot verification." },
                    "recipe_path": { "type": "string" },
                    "pid": { "type": "integer" },
                    "window_id": { "type": "integer" },
                    "app_path": { "type": "string" },
                    "display_id": { "type": "string" },
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
        let Some(app_id) = args.opt_str("app_id") else {
            return ToolResult::error("app_id is required");
        };
        let flow_name = args.opt_str("flow");
        let recipe_path = args.opt_str("recipe_path").map(PathBuf::from);
        let display_id = resolve_display_id(&args);
        let mut req = InspectAppFlowRequest {
            pid: args.opt_u64("pid").map(|v| v as u32),
            window_id: args.opt_u64("window_id"),
            app_path: args.opt_str("app_path"),
            display_id: display_id.clone(),
        };

        match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
            // Auto-resolve target window on display_id when pid/window_id/app_path are omitted.
            if req.pid.is_none() && req.window_id.is_none() && req.app_path.is_none() {
                if let Ok(target) = DisplayTarget::from_display_id(display_id.as_deref()) {
                    if let Ok(ctx) = global_screen_pool().get_or_connect(&target) {
                        if let Some(win) = find_window_for_app(&ctx, &app_id) {
                            req.window_id = Some(win.xid);
                            req.pid = win.pid;
                        }
                    }
                }
            }

            let target_window_id = req.window_id;
            let target_pid = req.pid;
            let inspection = inspect_app_flow(req)?;
            if inspection.channel == "browser_exempt" {
                return Ok(ToolResult::error(
                    inspection
                        .exempt_reason
                        .clone()
                        .unwrap_or_else(|| "browser_exempt".to_owned()),
                )
                .with_structured(json!({ "inspection": inspection })));
            }

            // Resolve recipe: explicit recipe_path -> hot cache -> best recipe in recipes_dir().
            let recipe = if let Some(ref p) = recipe_path {
                let loaded = load_recipe(p).map_err(|e| anyhow::anyhow!("{e}"))?;
                global_recipe_cache().insert(loaded.clone());
                loaded
            } else if let Some(cached) = global_recipe_cache().get(
                &app_id,
                &inspection.app_version,
                &inspection.fingerprint_sha256,
            ) {
                (*cached).clone()
            } else if let Some(dir) = recipes_dir() {
                let found = find_best_recipe_for_app(
                    &dir,
                    &app_id,
                    Some(&inspection.app_version),
                    Some(&inspection.fingerprint_sha256),
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no matching recipe for {app_id} v{} ({})",
                        inspection.app_version,
                        inspection.fp8
                    )
                })?;
                global_recipe_cache().insert(found.clone());
                found
            } else {
                anyhow::bail!("app_recipes directory unavailable");
            };

            // Mandatory VersionGate verification (unless explicitly seeded template).
            let is_seeded =
                recipe.app_version == "seeded" || recipe.fingerprint_sha256 == "seeded";
            if !is_seeded {
                let verify = VersionGate::verify(
                    &recipe,
                    &inspection.app_version,
                    &inspection.fingerprint_sha256,
                );
                if let VerifyResult::VersionMismatch { ref reason, .. } = verify {
                    return Ok(ToolResult::error(reason.clone())
                        .with_structured(serde_json::to_value(&verify)?));
                }
            }

            let target = DisplayTarget::from_display_id(display_id.as_deref())?;
            let ctx = global_screen_pool().get_or_connect(&target).ok();

            if let Some(ref flow) = flow_name {
                let steps = recipe.flows.get(flow).ok_or_else(|| {
                    let available: Vec<&str> = recipe.flows.keys().map(String::as_str).collect();
                    anyhow::anyhow!(
                        "flow '{flow}' not found in recipe {} (available: {:?})",
                        recipe.canonical_filename(),
                        available
                    )
                })?;
                let mut executed_steps = Vec::with_capacity(steps.len());
                for (idx, step) in steps.iter().enumerate() {
                    if let Some(ms) = step.wait_for_stable_frame_ms {
                        std::thread::sleep(std::time::Duration::from_millis(ms.min(5_000)));
                    }
                    let outcome = execute_recipe_step(
                        ctx.as_deref(),
                        &recipe,
                        target_window_id,
                        target_pid,
                        &step.action,
                        &step.args,
                    );
                    match outcome {
                        Ok(details) => {
                            executed_steps.push(json!({
                                "step": idx,
                                "action": step.action,
                                "description": step.description,
                                "ok": true,
                                "details": details,
                            }));
                        }
                        Err(err) => {
                            executed_steps.push(json!({
                                "step": idx,
                                "action": step.action,
                                "description": step.description,
                                "ok": false,
                                "error": format!("{err:#}"),
                            }));
                            return Ok(ToolResult::error(format!(
                                "flow '{flow}' failed at step {idx} ({}): {err:#}",
                                step.action
                            ))
                            .with_structured(json!({
                                "status": "failed",
                                "app_id": recipe.app_id,
                                "app_version": recipe.app_version,
                                "fp8": recipe.fp8(),
                                "flow": flow,
                                "steps": executed_steps,
                            })));
                        }
                    }
                }
                return Ok(ToolResult::text(format!(
                    "Completed flow '{}' of {} ({} steps, non-screenshot verified)",
                    flow,
                    recipe.canonical_filename(),
                    executed_steps.len()
                ))
                .with_structured(json!({
                    "status": "completed",
                    "app_id": recipe.app_id,
                    "app_version": recipe.app_version,
                    "fp8": recipe.fp8(),
                    "flow": flow,
                    "steps": executed_steps,
                })));
            }

            let mut executed_steps = Vec::new();
            let mut current_state_id = recipe.state_machine.initial_state.clone();

            for _ in 0..=recipe.state_machine.transitions.len() {
                if let Some(state) = recipe
                    .state_machine
                    .states
                    .iter()
                    .find(|s| s.id == current_state_id)
                {
                    // Check CAPTCHA / human verification boundary.
                    if let Some(ref title) = inspection.window_title {
                        for pat in &state.captcha_patterns {
                            if title.to_ascii_lowercase().contains(&pat.to_ascii_lowercase()) {
                                return Ok(ToolResult::error(format!(
                                    "human verification required: matched '{pat}'"
                                ))
                                .with_structured(json!({
                                    "status": "human_verification_required",
                                    "state": state.id,
                                    "pattern": pat,
                                })));
                            }
                        }
                    }

                    // Out-of-band auth_gate handling (never logs or returns plaintext).
                    if let Some(ref gate) = state.auth_gate {
                        let secret = resolve_auth_gate_secret(gate)?;
                        if let Some(ref xctx) = ctx {
                            xtest_type_text(xctx, &secret)?;
                        }
                        drop(secret);
                        executed_steps.push(json!({
                            "state": state.id,
                            "status": "auth_step_completed",
                        }));
                    }
                }

                let Some(tx) = recipe
                    .state_machine
                    .transitions
                    .iter()
                    .find(|t| t.from_state == current_state_id)
                else {
                    break;
                };

                if let Some(ms) = tx.wait_for_stable_frame_ms {
                    std::thread::sleep(std::time::Duration::from_millis(ms.min(5_000)));
                }
                let details = execute_recipe_step(
                    ctx.as_deref(),
                    &recipe,
                    target_window_id,
                    target_pid,
                    &tx.action,
                    &tx.args,
                )?;
                executed_steps.push(json!({
                    "from": tx.from_state,
                    "to": tx.to_state,
                    "action": tx.action,
                    "ok": true,
                    "details": details,
                }));
                current_state_id = tx.to_state.clone();
            }

            Ok(ToolResult::text(format!(
                "Completed recipe {} ({} steps)",
                recipe.canonical_filename(),
                executed_steps.len()
            ))
            .with_structured(json!({
                "status": "completed",
                "app_id": recipe.app_id,
                "app_version": recipe.app_version,
                "fp8": recipe.fp8(),
                "final_state": current_state_id,
                "steps": executed_steps,
            })))
        })
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => ToolResult::error(format!("run_app_recipe failed: {e:#}")),
            Err(e) => ToolResult::error(format!("run_app_recipe panicked: {e}")),
        }
    }
}

fn resolve_auth_gate_secret(gate: &AuthGate) -> anyhow::Result<Zeroizing<String>> {
    use zeroize::Zeroize as _;

    if let (Some(svc), Some(acc)) = (&gate.keyring_service, &gate.keyring_account) {
        if let Ok(mut out) = Command::new("secret-tool")
            .args(["lookup", "service", svc, "account", acc])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                out.stdout.zeroize();
                if !s.is_empty() {
                    return Ok(Zeroizing::new(s));
                }
            }
            out.stdout.zeroize();
        }
    }

    let mut out = Command::new("zenity")
        .args(["--password", "--title", &gate.prompt_title])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to launch out-of-band auth dialog (zenity): {e}"))?;
    if !out.status.success() {
        out.stdout.zeroize();
        anyhow::bail!("user cancelled out-of-band auth_gate prompt");
    }
    let secret = String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_owned();
    out.stdout.zeroize();
    Ok(Zeroizing::new(secret))
}

fn find_window_for_app(
    ctx: &X11ScreenContext,
    app_id: &str,
) -> Option<crate::x11::WindowInfo> {
    let needle = app_id.to_ascii_lowercase();
    let windows = crate::x11::list_windows_with_context(ctx, None);
    windows.into_iter().find(|w| {
        let title = w.title.to_ascii_lowercase();
        let app = w.app_name.to_ascii_lowercase();
        title.contains(&needle)
            || app.contains(&needle)
            || (needle == "tws" && title.contains("trader workstation"))
            || (needle == "thinkorswim" && title.contains("thinkorswim"))
    })
}

fn parse_shortcut_keys(args: &Value) -> Vec<String> {
    if let Some(arr) = args.get("keys").and_then(Value::as_array) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
    }
    if let Some(raw) = args
        .get("key")
        .or_else(|| args.get("shortcut"))
        .and_then(Value::as_str)
    {
        return raw
            .split('+')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    Vec::new()
}

fn expand_home_path(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    if raw.contains("${HOME}") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(raw.replace("${HOME}", &home));
        }
    }
    PathBuf::from(raw)
}

pub(crate) fn verify_log_pattern_in_file(
    path: &Path,
    pattern: &str,
    tail_bytes: usize,
) -> anyhow::Result<bool> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| anyhow::anyhow!("invalid regex '{pattern}': {e}"))?;
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", path.display()))?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let read_len = len.min(tail_bytes as u64) as usize;
    if len > read_len as u64 {
        file.seek(SeekFrom::End(-(read_len as i64)))?;
    }
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(re.is_match(&text))
}

fn execute_recipe_step(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    action: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    match action {
        "wait_for_stable_frame" => {
            let ms = args
                .get("ms")
                .or_else(|| args.get("wait_for_stable_frame_ms"))
                .and_then(Value::as_u64)
                .unwrap_or(300)
                .min(5_000);
            std::thread::sleep(std::time::Duration::from_millis(ms));
            Ok(json!({ "waited_ms": ms }))
        }
        "click_anchor" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let anchor_name = args
                .get("anchor")
                .or_else(|| args.get("name"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("click_anchor requires 'anchor' or 'name'"))?;
            let anchor = recipe
                .relative_anchors
                .iter()
                .find(|a| a.name == anchor_name)
                .ok_or_else(|| anyhow::anyhow!("anchor '{anchor_name}' not found in recipe"))?;
            let win_info = target_window_id
                .and_then(|wid| crate::x11::window_info_with_context(xctx, wid))
                .or_else(|| {
                    let wins = crate::x11::list_windows_with_context(xctx, target_pid);
                    if let Some(ref pat) = anchor.title_pattern {
                        if let Ok(re) = regex::Regex::new(pat) {
                            if let Some(w) = wins.iter().find(|w| re.is_match(&w.title)) {
                                return Some(w.clone());
                            }
                        }
                    }
                    wins.into_iter().next()
                })
                .ok_or_else(|| anyhow::anyhow!("no target window found for click_anchor"))?;
            let (x, y) = resolve_relative_anchor_xy(
                anchor,
                win_info.x,
                win_info.y,
                win_info.width,
                win_info.height,
            );
            let button = match args.get("button").and_then(Value::as_str) {
                Some("right") => 3,
                Some("middle") => 2,
                _ => 1,
            };
            let _ = xtest_focus_window(xctx, win_info.xid);
            xtest_click(xctx, x, y, button)?;
            Ok(json!({
                "anchor": anchor_name,
                "window_id": win_info.xid,
                "x": x,
                "y": y,
                "button": button,
            }))
        }
        "press_key" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let key = args
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("press_key requires 'key'"))?;
            xtest_press_key(xctx, key)?;
            Ok(json!({ "key": key }))
        }
        "hotkey" | "shortcut" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let keys = parse_shortcut_keys(args);
            if keys.is_empty() {
                anyhow::bail!("{action} requires 'keys' array or 'key' string");
            }
            xtest_hotkey(xctx, &keys)?;
            Ok(json!({ "keys": keys }))
        }
        "click" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let x = args.get("x").and_then(Value::as_f64).unwrap_or(0.0).round() as i16;
            let y = args.get("y").and_then(Value::as_f64).unwrap_or(0.0).round() as i16;
            xtest_click(xctx, x, y, 1)?;
            Ok(json!({ "x": x, "y": y }))
        }
        "type_text" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("type_text requires 'text'"))?;
            if let Some(wid) = target_window_id {
                let _ = xtest_focus_window(xctx, wid);
            }
            xtest_type_text(xctx, text)?;
            Ok(json!({ "chars": text.chars().count() }))
        }
        "verify_window_title_regex" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let pattern = args
                .get("pattern")
                .or_else(|| args.get("regex"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("verify_window_title_regex requires 'pattern'"))?;
            let re = regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("invalid regex '{pattern}': {e}"))?;
            let mut titles = Vec::new();
            if let Some(wid) = target_window_id {
                if let Some(info) = crate::x11::window_info_with_context(xctx, wid) {
                    titles.push(info.title);
                }
            } else {
                for w in crate::x11::list_windows_with_context(xctx, target_pid) {
                    titles.push(w.title);
                }
            }
            let matched = titles.iter().find(|t| re.is_match(t)).cloned();
            if let Some(title) = matched {
                Ok(json!({ "pattern": pattern, "matched_title": title }))
            } else {
                anyhow::bail!("no window title matched /{pattern}/ (saw: {:?})", titles)
            }
        }
        "verify_window_count_min" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let min = args.get("min").and_then(Value::as_u64).unwrap_or(1) as usize;
            let pid_filter = args
                .get("pid")
                .and_then(Value::as_u64)
                .map(|v| v as u32)
                .or(target_pid);
            let title_re = args
                .get("title_regex")
                .and_then(Value::as_str)
                .map(regex::Regex::new)
                .transpose()
                .map_err(|e| anyhow::anyhow!("invalid title_regex: {e}"))?;
            let wins = crate::x11::list_windows_with_context(xctx, pid_filter);
            let count = wins
                .iter()
                .filter(|w| title_re.as_ref().is_none_or(|re| re.is_match(&w.title)))
                .count();
            if count >= min {
                Ok(json!({ "count": count, "min": min }))
            } else {
                anyhow::bail!("expected at least {min} windows, found {count}")
            }
        }
        "verify_log_pattern" => {
            let raw_path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("verify_log_pattern requires 'path'"))?;
            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("verify_log_pattern requires 'pattern'"))?;
            let tail_bytes = args
                .get("tail_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(65_536) as usize;
            let path = expand_home_path(raw_path);
            let matched = verify_log_pattern_in_file(&path, pattern, tail_bytes)?;
            if matched {
                Ok(json!({ "path": path.display().to_string(), "pattern": pattern }))
            } else {
                anyhow::bail!("log {} did not match /{pattern}/", path.display())
            }
        }
        "verify_clipboard_nonempty" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let min_len = args.get("min_len").and_then(Value::as_u64).unwrap_or(1) as usize;
            let text = clipboard_get_for_context(xctx)?;
            let len = text.trim().len();
            if len >= min_len {
                Ok(json!({ "length": len, "min_len": min_len }))
            } else {
                anyhow::bail!("clipboard length {len} < min_len {min_len}")
            }
        }
        other => anyhow::bail!("unsupported recipe action '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shortcut_keys_from_array_or_plus_string() {
        assert_eq!(
            parse_shortcut_keys(&json!({ "keys": ["ctrl", "l"] })),
            vec!["ctrl", "l"]
        );
        assert_eq!(
            parse_shortcut_keys(&json!({ "key": "ctrl+shift+p" })),
            vec!["ctrl", "shift", "p"]
        );
    }

    #[test]
    fn verify_log_pattern_reads_tail_and_matches_regex() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        std::fs::write(&log_path, "booting...\n2026-11-22 INFO Main@thinkorswim ready\n").unwrap();

        assert!(verify_log_pattern_in_file(&log_path, r"Main@thinkorswim\s+ready", 4096).unwrap());
        assert!(!verify_log_pattern_in_file(&log_path, r"FATAL_CRASH", 4096).unwrap());
    }
}
