// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tools for strong-versioned application flow inspection, recipe
//! generation, and deterministic state-machine execution:
//! - `inspect_app_flow`
//! - `generate_app_recipe`
//! - `run_app_recipe`
//! - `acquire_app_data`

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cua_driver_core::{
    app_recipe::{
        find_best_recipe_with_path, global_recipe_cache, load_recipe, recipes_dir,
        resolve_relative_anchor_xy, save_recipe_to_dir, AppRecipe, AuthGate, CapabilitySpec,
        DataChannel, ModalHandler, RecipeState, RecipeStep, RecipeTransition, RelativeAnchor,
        SafetyLevel, StateMachine, VerifyResult, VersionGate,
    },
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app_inspector::{inspect_app_flow, InspectAppFlowRequest};
use crate::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};
use crate::tools::mcp_type_secret::{resolve_secret_from_env, type_secret_into_context, validate_env_key};
use crate::x11::virtual_input::{
    clipboard_get_for_context, clipboard_set_for_context, xtest_click, xtest_focus_window,
    xtest_hotkey, xtest_press_key, xtest_type_text,
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
                capabilities: HashMap::new(),
                safety_policy: None,
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
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "allow_safety_level": {
                        "type": "string",
                        "enum": ["read_only", "auth_only", "restricted"],
                        "default": "auth_only",
                        "description": "Maximum SafetyLevel permitted for this invocation (default: auth_only)."
                    }
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
        let allow_safety_level = match parse_safety_level(
            args.opt_str("allow_safety_level").as_deref(),
            SafetyLevel::AuthOnly,
        ) {
            Ok(lvl) => lvl,
            Err(e) => return ToolResult::error(e.to_string()),
        };
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
                global_recipe_cache().insert_with_path(loaded.clone(), Some(p.clone()));
                loaded
            } else if let Some(cached) = global_recipe_cache().get(
                &app_id,
                &inspection.app_version,
                &inspection.fingerprint_sha256,
            ) {
                (*cached).clone()
            } else if let Some(dir) = recipes_dir() {
                let (found, found_path) = find_best_recipe_with_path(
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
                global_recipe_cache().insert_with_path(found.clone(), Some(found_path));
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
                if let Err(blocked) = check_safety_gate(
                    &recipe,
                    Some(flow),
                    steps,
                    SafetyLevel::ReadOnly,
                    allow_safety_level,
                ) {
                    return Ok(blocked);
                }
                let FlowExecutionResult {
                    steps: executed_steps,
                    artifacts,
                    error: step_err,
                } = execute_flow_steps(
                    ctx.as_deref(),
                    &recipe,
                    target_window_id,
                    target_pid,
                    steps,
                );
                if let Some((idx, action, err)) = step_err {
                    return Ok(ToolResult::error(format!(
                        "flow '{flow}' failed at step {idx} ({action}): {err:#}"
                    ))
                    .with_structured(json!({
                        "status": "failed",
                        "app_id": recipe.app_id,
                        "app_version": recipe.app_version,
                        "fp8": recipe.fp8(),
                        "flow": flow,
                        "steps": executed_steps,
                        "artifacts": artifacts,
                    })));
                }
                let summary = format_artifacts_summary(&artifacts);
                let msg = if summary.is_empty() {
                    format!(
                        "Completed flow '{}' of {} ({} steps, non-screenshot verified)",
                        flow,
                        recipe.canonical_filename(),
                        executed_steps.len()
                    )
                } else {
                    format!(
                        "Completed flow '{}' of {} ({} steps, non-screenshot verified)\n\n{}",
                        flow,
                        recipe.canonical_filename(),
                        executed_steps.len(),
                        summary
                    )
                };
                return Ok(ToolResult::text(msg)
                .with_structured(json!({
                    "status": "completed",
                    "app_id": recipe.app_id,
                    "app_version": recipe.app_version,
                    "fp8": recipe.fp8(),
                    "flow": flow,
                    "steps": executed_steps,
                    "artifacts": artifacts,
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

// ── acquire_app_data ──────────────────────────────────────────────────────────

pub struct AcquireAppDataTool;
static ACQUIRE_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for AcquireAppDataTool {
    fn def(&self) -> &ToolDef {
        ACQUIRE_DEF.get_or_init(|| ToolDef {
            name: "acquire_app_data".into(),
            description: "Acquire structured application data via a recipe's 4-tier capability routing (AT-SPI/CDP, Clipboard/FileExport/Log, WindowMeta, or ScreenshotROI) with SafetyLevel enforcement and automatic fallback.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["app_id", "capability"],
                "properties": {
                    "app_id": { "type": "string" },
                    "capability": { "type": "string", "description": "Named capability in recipe.capabilities." },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "recipe_path": { "type": "string" },
                    "fallback": { "type": "boolean", "default": true },
                    "allow_safety_level": {
                        "type": "string",
                        "enum": ["read_only", "auth_only", "restricted"],
                        "default": "read_only",
                        "description": "Maximum SafetyLevel permitted (default: read_only)."
                    }
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
        let Some(capability) = args.opt_str("capability") else {
            return ToolResult::error("capability is required");
        };
        let recipe_path = args.opt_str("recipe_path").map(PathBuf::from);
        let fallback = args.bool_or("fallback", true);
        let allow_safety_level = match parse_safety_level(
            args.opt_str("allow_safety_level").as_deref(),
            SafetyLevel::ReadOnly,
        ) {
            Ok(lvl) => lvl,
            Err(e) => return ToolResult::error(e.to_string()),
        };
        let display_id = resolve_display_id(&args);
        let mut req = InspectAppFlowRequest {
            pid: None,
            window_id: None,
            app_path: None,
            display_id: display_id.clone(),
        };

        match tokio::task::spawn_blocking(move || -> anyhow::Result<ToolResult> {
            if let Ok(target) = DisplayTarget::from_display_id(display_id.as_deref()) {
                if let Ok(ctx) = global_screen_pool().get_or_connect(&target) {
                    if let Some(win) = find_window_for_app(&ctx, &app_id) {
                        req.window_id = Some(win.xid);
                        req.pid = win.pid;
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

            let recipe = if let Some(ref p) = recipe_path {
                let loaded = load_recipe(p).map_err(|e| anyhow::anyhow!("{e}"))?;
                global_recipe_cache().insert_with_path(loaded.clone(), Some(p.clone()));
                loaded
            } else if let Some(cached) = global_recipe_cache().get(
                &app_id,
                &inspection.app_version,
                &inspection.fingerprint_sha256,
            ) {
                (*cached).clone()
            } else if let Some(dir) = recipes_dir() {
                let (found, found_path) = find_best_recipe_with_path(
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
                global_recipe_cache().insert_with_path(found.clone(), Some(found_path));
                found
            } else {
                anyhow::bail!("app_recipes directory unavailable");
            };

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

            let spec = lookup_capability(&recipe, &capability)?;
            let flow_steps: &[RecipeStep] = spec
                .flow
                .as_deref()
                .and_then(|f| recipe.flows.get(f))
                .map(Vec::as_slice)
                .unwrap_or(&[]);

            if let Err(blocked) = check_safety_gate(
                &recipe,
                spec.flow.as_deref(),
                flow_steps,
                spec.safety_level,
                allow_safety_level,
            ) {
                return Ok(blocked);
            }

            let target = DisplayTarget::from_display_id(display_id.as_deref())?;
            let ctx = global_screen_pool().get_or_connect(&target).ok();

            match execute_capability_primary(
                ctx.as_deref(),
                &recipe,
                &inspection,
                target_window_id,
                target_pid,
                &capability,
                spec,
            ) {
                Ok((steps, artifacts)) => {
                    let summary = format_artifacts_summary(&artifacts);
                    let msg = if summary.is_empty() {
                        format!(
                            "Acquired capability '{capability}' for {} ({} artifacts)",
                            recipe.canonical_filename(),
                            artifacts.len()
                        )
                    } else {
                        format!(
                            "Acquired capability '{capability}' for {} ({} artifacts)\n\n{}",
                            recipe.canonical_filename(),
                            artifacts.len(),
                            summary
                        )
                    };
                    Ok(ToolResult::text(msg).with_structured(json!({
                        "status": "completed",
                        "app_id": recipe.app_id,
                        "app_version": recipe.app_version,
                        "fp8": recipe.fp8(),
                        "capability": capability,
                        "data_channel": spec.data_channel,
                        "fallback_used": false,
                        "steps": steps,
                        "artifacts": artifacts,
                    })))
                }
                Err(primary_err) if fallback => {
                    if let Some(fb_method) = spec.fallback_method {
                        let fb_artifact = execute_fallback_channel(
                            ctx.as_deref(),
                            &recipe,
                            &inspection,
                            target_window_id,
                            target_pid,
                            fb_method,
                            spec,
                        )?;
                        let fb_artifacts = vec![fb_artifact];
                        let summary = format_artifacts_summary(&fb_artifacts);
                        let msg = if summary.is_empty() {
                            format!(
                                "Acquired capability '{capability}' for {} via fallback {:?}",
                                recipe.canonical_filename(),
                                fb_method
                            )
                        } else {
                            format!(
                                "Acquired capability '{capability}' for {} via fallback {:?}\n\n{}",
                                recipe.canonical_filename(),
                                fb_method,
                                summary
                            )
                        };
                        return Ok(ToolResult::text(msg).with_structured(json!({
                            "status": "completed_with_fallback",
                            "app_id": recipe.app_id,
                            "app_version": recipe.app_version,
                            "fp8": recipe.fp8(),
                            "capability": capability,
                            "data_channel": fb_method,
                            "fallback_used": true,
                            "primary_error": format!("{primary_err:#}"),
                            "steps": [],
                            "artifacts": fb_artifacts,
                        })));
                    }
                    if let Some(ref fb_cap_name) = spec.fallback_capability {
                        let fb_spec = lookup_capability(&recipe, fb_cap_name)?;
                        let fb_steps: &[RecipeStep] = fb_spec
                            .flow
                            .as_deref()
                            .and_then(|f| recipe.flows.get(f))
                            .map(Vec::as_slice)
                            .unwrap_or(&[]);
                        if let Err(blocked) = check_safety_gate(
                            &recipe,
                            fb_spec.flow.as_deref(),
                            fb_steps,
                            fb_spec.safety_level,
                            allow_safety_level,
                        ) {
                            return Ok(blocked);
                        }
                        let (steps, artifacts) = execute_capability_primary(
                            ctx.as_deref(),
                            &recipe,
                            &inspection,
                            target_window_id,
                            target_pid,
                            fb_cap_name,
                            fb_spec,
                        )?;
                        let summary = format_artifacts_summary(&artifacts);
                        let msg = if summary.is_empty() {
                            format!(
                                "Acquired capability '{capability}' for {} via fallback capability '{fb_cap_name}'",
                                recipe.canonical_filename()
                            )
                        } else {
                            format!(
                                "Acquired capability '{capability}' for {} via fallback capability '{fb_cap_name}'\n\n{}",
                                recipe.canonical_filename(),
                                summary
                            )
                        };
                        return Ok(ToolResult::text(msg).with_structured(json!({
                            "status": "completed_with_fallback",
                            "app_id": recipe.app_id,
                            "app_version": recipe.app_version,
                            "fp8": recipe.fp8(),
                            "capability": capability,
                            "fallback_capability": fb_cap_name,
                            "data_channel": fb_spec.data_channel,
                            "fallback_used": true,
                            "primary_error": format!("{primary_err:#}"),
                            "steps": steps,
                            "artifacts": artifacts,
                        })));
                    }
                    Err(primary_err)
                }
                Err(primary_err) => Err(primary_err),
            }
        })
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => ToolResult::error(format!("acquire_app_data failed: {e:#}")),
            Err(e) => ToolResult::error(format!("acquire_app_data panicked: {e}")),
        }
    }
}

pub(crate) fn parse_safety_level(raw: Option<&str>, default: SafetyLevel) -> anyhow::Result<SafetyLevel> {
    match raw {
        None => Ok(default),
        Some("read_only") => Ok(SafetyLevel::ReadOnly),
        Some("auth_only") => Ok(SafetyLevel::AuthOnly),
        Some("restricted") => Ok(SafetyLevel::Restricted),
        Some(other) => anyhow::bail!(
            "invalid allow_safety_level '{other}' (expected read_only, auth_only, or restricted)"
        ),
    }
}

pub(crate) fn lookup_capability<'a>(
    recipe: &'a AppRecipe,
    capability: &str,
) -> anyhow::Result<&'a CapabilitySpec> {
    recipe.capabilities.get(capability).ok_or_else(|| {
        let available: Vec<&str> = recipe.capabilities.keys().map(String::as_str).collect();
        anyhow::anyhow!(
            "capability '{capability}' not found in recipe {} (available: {:?})",
            recipe.canonical_filename(),
            available
        )
    })
}

fn normalize_shortcut_str(keys: &[String]) -> String {
    keys.iter()
        .map(|k| k.trim().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("+")
}

fn default_step_safety_level(action: &str) -> SafetyLevel {
    match action {
        "type_secret_from_env" => SafetyLevel::AuthOnly,
        _ => SafetyLevel::ReadOnly,
    }
}

fn effective_step_safety_level(step: &RecipeStep) -> SafetyLevel {
    step.safety_level
        .unwrap_or_else(|| default_step_safety_level(&step.action))
}

#[allow(clippy::result_large_err)]
pub(crate) fn check_safety_gate(
    recipe: &AppRecipe,
    flow_name: Option<&str>,
    steps: &[RecipeStep],
    required_level: SafetyLevel,
    allow_level: SafetyLevel,
) -> Result<(), ToolResult> {
    let block = |reason: String, req: SafetyLevel| -> ToolResult {
        ToolResult::error(reason.clone()).with_structured(json!({
            "status": "safety_gate_blocked",
            "code": "safety_gate_blocked",
            "app_id": recipe.app_id,
            "flow": flow_name,
            "required_level": req.as_str(),
            "allowed_level": allow_level.as_str(),
            "reason": reason,
        }))
    };

    if required_level > allow_level {
        return Err(block(
            format!(
                "safety_gate_blocked: required level '{}' exceeds allowed '{}'",
                required_level.as_str(),
                allow_level.as_str()
            ),
            required_level,
        ));
    }

    if let Some(ref policy) = recipe.safety_policy {
        if let Some(f) = flow_name {
            if policy.blocked_flows.iter().any(|b| b == f) {
                return Err(block(
                    format!("safety_gate_blocked: flow '{f}' is blocked by recipe safety_policy"),
                    SafetyLevel::Restricted,
                ));
            }
        }
    }

    for (idx, step) in steps.iter().enumerate() {
        let step_lvl = effective_step_safety_level(step);
        if step_lvl > allow_level {
            return Err(block(
                format!(
                    "safety_gate_blocked: step {idx} ({}) requires '{}' > allowed '{}'",
                    step.action,
                    step_lvl.as_str(),
                    allow_level.as_str()
                ),
                step_lvl,
            ));
        }
        if let Some(ref policy) = recipe.safety_policy {
            if matches!(step.action.as_str(), "hotkey" | "shortcut" | "press_key") {
                let keys = parse_shortcut_keys(&step.args);
                let norm = normalize_shortcut_str(&keys);
                if !norm.is_empty()
                    && policy
                        .blocked_shortcuts
                        .iter()
                        .any(|b| b.trim().to_ascii_lowercase() == norm)
                {
                    return Err(block(
                        format!(
                            "safety_gate_blocked: shortcut '{norm}' at step {idx} is blocked by safety_policy"
                        ),
                        SafetyLevel::Restricted,
                    ));
                }
            }
        }
    }

    Ok(())
}

struct FlowExecutionResult {
    steps: Vec<Value>,
    artifacts: Vec<Value>,
    error: Option<(usize, String, anyhow::Error)>,
}

fn execute_flow_steps(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    steps: &[RecipeStep],
) -> FlowExecutionResult {
    let mut executed_steps = Vec::with_capacity(steps.len());
    let mut artifacts = Vec::new();
    for (idx, step) in steps.iter().enumerate() {
        if let Some(ms) = step.wait_for_stable_frame_ms {
            std::thread::sleep(std::time::Duration::from_millis(ms.min(5_000)));
        }
        match execute_recipe_step(
            ctx,
            recipe,
            target_window_id,
            target_pid,
            &step.action,
            &step.args,
        ) {
            Ok(details) => {
                if let Some(art) = details.get("artifact") {
                    artifacts.push(art.clone());
                }
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
                return FlowExecutionResult {
                    steps: executed_steps,
                    artifacts,
                    error: Some((idx, step.action.clone(), err)),
                };
            }
        }
    }
    FlowExecutionResult {
        steps: executed_steps,
        artifacts,
        error: None,
    }
}

fn execute_capability_primary(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    inspection: &crate::app_inspector::AppFlowInspection,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    capability: &str,
    spec: &CapabilitySpec,
) -> anyhow::Result<(Vec<Value>, Vec<Value>)> {
    if let Some(ref flow_name) = spec.flow {
        let steps = recipe.flows.get(flow_name).ok_or_else(|| {
            anyhow::anyhow!(
                "capability '{capability}' references missing flow '{flow_name}'"
            )
        })?;
        let FlowExecutionResult {
            steps: executed,
            mut artifacts,
            error,
        } = execute_flow_steps(ctx, recipe, target_window_id, target_pid, steps);
        if let Some((idx, action, e)) = error {
            anyhow::bail!("flow '{flow_name}' failed at step {idx} ({action}): {e:#}");
        }
        if artifacts.is_empty() {
            if let Some(ref path) = spec.artifact_path {
                if spec.data_channel == DataChannel::FileExport {
                    let details = verify_file_export_at_path(&expand_home_path(path), 0, 1, 20)?;
                    if let Some(art) = details.get("artifact") {
                        artifacts.push(art.clone());
                    }
                }
            }
        }
        return Ok((executed, artifacts));
    }

    let artifact = execute_fallback_channel(
        ctx,
        recipe,
        inspection,
        target_window_id,
        target_pid,
        spec.data_channel,
        spec,
    )?;
    Ok((Vec::new(), vec![artifact]))
}

fn execute_fallback_channel(
    ctx: Option<&X11ScreenContext>,
    _recipe: &AppRecipe,
    inspection: &crate::app_inspector::AppFlowInspection,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    channel: DataChannel,
    spec: &CapabilitySpec,
) -> anyhow::Result<Value> {
    match channel {
        DataChannel::WindowMeta => Ok(json!({
            "kind": "window_meta",
            "app_id": inspection.app_id,
            "app_version": inspection.app_version,
            "window_id": target_window_id,
            "pid": target_pid,
            "window_title": inspection.window_title,
            "wm_class": inspection.wm_class,
        })),
        DataChannel::ScreenshotRoi => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let roi = spec.output_schema.as_ref().and_then(|s| s.roi_norm);
            capture_screenshot_roi_artifact(xctx, target_window_id, target_pid, roi, "screenshot_roi")
        }
        DataChannel::ScreenshotFull => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            capture_screenshot_roi_artifact(xctx, target_window_id, target_pid, None, "screenshot_full")
        }
        DataChannel::FileExport => {
            let raw_path = spec
                .artifact_path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("file_export channel requires artifact_path"))?;
            let details = verify_file_export_at_path(&expand_home_path(raw_path), 0, 1, 20)?;
            Ok(details.get("artifact").cloned().unwrap_or(details))
        }
        DataChannel::Clipboard => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let text = clipboard_get_for_context(xctx)?;
            build_clipboard_artifact(&text, 1, 65_536)
        }
        DataChannel::Log => {
            let raw_path = spec
                .artifact_path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("log channel requires artifact_path"))?;
            let details = verify_file_export_at_path(&expand_home_path(raw_path), 0, 1, 30)?;
            Ok(details.get("artifact").cloned().unwrap_or(details))
        }
        DataChannel::Atspi | DataChannel::Cdp => {
            anyhow::bail!("direct {:?} channel requires a named flow in recipe", channel)
        }
    }
}

fn capture_screenshot_roi_artifact(
    ctx: &X11ScreenContext,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    roi_norm: Option<[f64; 4]>,
    kind: &str,
) -> anyhow::Result<Value> {
    let xid = target_window_id
        .or_else(|| {
            crate::x11::list_windows_with_context(ctx, target_pid)
                .into_iter()
                .next()
                .map(|w| w.xid)
        })
        .ok_or_else(|| anyhow::anyhow!("no target window found for {kind}"))?;
    let png_bytes = crate::capture::screenshot_window_bytes_with_context(ctx, xid)?;
    let img = image::load_from_memory(&png_bytes)?;
    let (img_w, img_h) = (img.width(), img.height());
    let out_img = if let Some([rx, ry, rw, rh]) = roi_norm {
        let rx = rx.clamp(0.0, 1.0);
        let ry = ry.clamp(0.0, 1.0);
        let rw = rw.clamp(0.0, 1.0 - rx);
        let rh = rh.clamp(0.0, 1.0 - ry);
        let x0 = ((rx * f64::from(img_w)).round() as u32).min(img_w.saturating_sub(1));
        let y0 = ((ry * f64::from(img_h)).round() as u32).min(img_h.saturating_sub(1));
        let cw = ((rw * f64::from(img_w)).round() as u32).max(1).min(img_w - x0);
        let ch = ((rh * f64::from(img_h)).round() as u32).max(1).min(img_h - y0);
        img.crop_imm(x0, y0, cw, ch)
    } else {
        img
    };
    let (out_w, out_h) = (out_img.width(), out_img.height());
    let mut buf = std::io::Cursor::new(Vec::new());
    out_img.write_to(&mut buf, image::ImageFormat::Png)?;
    let out_png = buf.into_inner();
    let b64 = B64.encode(&out_png);
    Ok(json!({
        "kind": kind,
        "mime_type": "image/png",
        "window_id": xid,
        "width": out_w,
        "height": out_h,
        "roi_norm": roi_norm,
        "bytes": out_png.len(),
        "data_base64": b64,
    }))
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
        "type_secret_from_env" => {
            let env_key = args
                .get("env_key")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("type_secret_from_env requires 'env_key'"))?;
            validate_env_key(env_key)?;
            let env_file = args.get("env_file").and_then(Value::as_str);
            let press_enter = args
                .get("press_enter")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let secret = resolve_secret_from_env(env_key, env_file)?;
            if let Some(wid) = target_window_id {
                let _ = xtest_focus_window(xctx, wid);
            }
            let char_len = type_secret_into_context(xctx, env_key, &secret, press_enter)?;
            drop(secret);
            Ok(json!({
                "env_key": env_key,
                "length": char_len,
                "press_enter": press_enter,
            }))
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
        "set_clipboard" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            clipboard_set_for_context(xctx, text)?;
            Ok(json!({ "bytes": text.len() }))
        }
        "read_clipboard" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let min_len = args.get("min_len").and_then(Value::as_u64).unwrap_or(1) as usize;
            let max_bytes = args
                .get("max_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(65_536) as usize;
            let clear_after = args
                .get("clear_after")
                .or_else(|| args.get("clear_before"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let text = clipboard_get_for_context(xctx)?;
            let artifact = build_clipboard_artifact(&text, min_len, max_bytes)?;
            if clear_after {
                let _ = clipboard_set_for_context(xctx, "");
            }
            Ok(json!({
                "artifact": artifact,
                "bytes": text.len(),
                "min_len": min_len,
            }))
        }
        "verify_file_export" => {
            let raw_path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("verify_file_export requires 'path'"))?;
            let wait_ms = args.get("wait_ms").and_then(Value::as_u64).unwrap_or(0).min(15_000);
            let min_bytes = args.get("min_bytes").and_then(Value::as_u64).unwrap_or(1);
            let preview_lines = args
                .get("preview_lines")
                .and_then(Value::as_u64)
                .unwrap_or(20) as usize;
            let path = expand_home_path(raw_path);
            verify_file_export_at_path(&path, wait_ms, min_bytes, preview_lines)
        }
        other => anyhow::bail!("unsupported recipe action '{other}'"),
    }
}

pub(crate) fn build_clipboard_artifact(
    text: &str,
    min_len: usize,
    max_bytes: usize,
) -> anyhow::Result<Value> {
    let trimmed_len = text.trim().len();
    if trimmed_len < min_len {
        anyhow::bail!("clipboard length {trimmed_len} < min_len {min_len}");
    }
    let truncated = text.len() > max_bytes;
    let slice = if truncated {
        let mut end = max_bytes;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    Ok(json!({
        "kind": "clipboard",
        "bytes": text.len(),
        "truncated": truncated,
        "content": slice,
    }))
}

pub(crate) fn verify_file_export_at_path(
    path: &Path,
    wait_ms: u64,
    min_bytes: u64,
    preview_lines: usize,
) -> anyhow::Result<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    let bytes = loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.is_file() && meta.len() >= min_bytes {
                break meta.len();
            }
        }
        if std::time::Instant::now() >= deadline {
            let actual = std::fs::metadata(path).map(|m| m.len()).ok();
            anyhow::bail!(
                "exported file {} missing or smaller than {} bytes (actual: {:?})",
                path.display(),
                min_bytes,
                actual
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", path.display()))?;
    let reader = BufReader::new(file.take(262_144));
    let mut lines = Vec::new();
    for line in reader.lines().take(preview_lines) {
        lines.push(line?);
    }
    let preview = lines.join("\n");
    Ok(json!({
        "artifact": {
            "kind": "file_export",
            "path": path.display().to_string(),
            "bytes": bytes,
            "preview_lines": lines,
            "preview": preview,
        },
        "path": path.display().to_string(),
        "bytes": bytes,
        "min_bytes": min_bytes,
    }))
}

pub(crate) fn format_artifacts_summary(artifacts: &[Value]) -> String {
    if artifacts.is_empty() {
        return String::new();
    }
    let mut parts = Vec::with_capacity(artifacts.len());
    for (idx, art) in artifacts.iter().enumerate() {
        let kind = art.get("kind").and_then(Value::as_str).unwrap_or("unknown");
        match kind {
            "file_export" => {
                let path = art.get("path").and_then(Value::as_str).unwrap_or("");
                let bytes = art.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                let preview = art.get("preview").and_then(Value::as_str).unwrap_or("");
                let snippet = truncate_utf8_snippet(preview, 2000);
                parts.push(format!(
                    "[artifact {idx} file_export] path={path} bytes={bytes}\n{snippet}"
                ));
            }
            "clipboard" => {
                let bytes = art.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                let content = art.get("content").and_then(Value::as_str).unwrap_or("");
                let line_count = content.lines().count();
                let snippet = truncate_utf8_snippet(content, 2000);
                parts.push(format!(
                    "[artifact {idx} clipboard] bytes={bytes} line_count={line_count}\n{snippet}"
                ));
            }
            "screenshot_roi" | "screenshot_full" => {
                let width = art.get("width").and_then(Value::as_u64).unwrap_or(0);
                let height = art.get("height").and_then(Value::as_u64).unwrap_or(0);
                let bytes = art.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                parts.push(format!(
                    "[artifact {idx} {kind}] {width}x{height} bytes={bytes}"
                ));
            }
            "window_meta" => {
                let title = art.get("window_title").and_then(Value::as_str).unwrap_or("");
                let pid = art.get("pid").and_then(Value::as_u64);
                parts.push(format!(
                    "[artifact {idx} window_meta] pid={pid:?} title={title:?}"
                ));
            }
            _ => {
                parts.push(format!("[artifact {idx} {kind}] {art}"));
            }
        }
    }
    parts.join("\n\n")
}

fn truncate_utf8_snippet(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
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

    #[test]
    fn type_secret_from_env_recipe_step_validates_prefix_and_required_key() {
        let dummy_recipe = AppRecipe {
            schema_version: 1,
            app_id: "thinkorswim".to_owned(),
            app_version: "seeded".to_owned(),
            version_source: cua_driver_core::app_recipe::VersionSource::Install4j,
            fingerprint_sha256: "seeded".to_owned(),
            tech_stack: None,
            atspi_blind: false,
            recommended_interaction: None,
            launch_isolation_hints: Vec::new(),
            verified_shortcuts: Vec::new(),
            menu_topology: Vec::new(),
            relative_anchors: Vec::new(),
            modal_handlers: Vec::new(),
            flows: HashMap::new(),
            capabilities: HashMap::new(),
            safety_policy: None,
            state_machine: StateMachine {
                initial_state: "ready".to_owned(),
                states: Vec::new(),
                transitions: Vec::new(),
            },
        };

        let missing_err = execute_recipe_step(
            None,
            &dummy_recipe,
            None,
            None,
            "type_secret_from_env",
            &json!({}),
        )
        .unwrap_err();
        assert!(missing_err.to_string().contains("env_key"));

        let prefix_err = execute_recipe_step(
            None,
            &dummy_recipe,
            None,
            None,
            "type_secret_from_env",
            &json!({ "env_key": "HOME" }),
        )
        .unwrap_err();
        assert!(prefix_err.to_string().contains("CUA_YCWANG_"));
    }

    #[test]
    fn verify_file_export_reads_preview_and_enforces_min_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("statement.csv");
        std::fs::write(&csv_path, "Account,Cash\n12345,100000.00\n").unwrap();

        let res = verify_file_export_at_path(&csv_path, 0, 10, 5).unwrap();
        assert_eq!(res["artifact"]["kind"], "file_export");
        assert_eq!(res["artifact"]["preview_lines"].as_array().unwrap().len(), 2);

        let err = verify_file_export_at_path(&csv_path, 0, 10_000, 5).unwrap_err();
        assert!(err.to_string().contains("smaller than 10000 bytes"));
    }

    #[test]
    fn parse_clipboard_artifact_truncates_utf8_safely_and_enforces_min_len() {
        let art = build_clipboard_artifact("测试_ABC", 1, 7).unwrap();
        assert_eq!(art["kind"], "clipboard");
        assert_eq!(art["truncated"], true);
        assert_eq!(art["content"], "测试_");

        let err = build_clipboard_artifact("  ", 1, 100).unwrap_err();
        assert!(err.to_string().contains("min_len"));
    }

    #[test]
    fn safety_gate_blocks_restricted_and_blocked_flows_and_shortcuts() {
        use cua_driver_core::app_recipe::SafetyPolicy;

        let mut recipe = AppRecipe {
            schema_version: 1,
            app_id: "thinkorswim".to_owned(),
            app_version: "seeded".to_owned(),
            version_source: cua_driver_core::app_recipe::VersionSource::Install4j,
            fingerprint_sha256: "seeded".to_owned(),
            tech_stack: None,
            atspi_blind: true,
            recommended_interaction: None,
            launch_isolation_hints: Vec::new(),
            verified_shortcuts: Vec::new(),
            menu_topology: Vec::new(),
            relative_anchors: Vec::new(),
            modal_handlers: Vec::new(),
            flows: HashMap::new(),
            capabilities: HashMap::new(),
            safety_policy: Some(SafetyPolicy {
                default_max_level: SafetyLevel::ReadOnly,
                blocked_shortcuts: vec!["ctrl+enter".to_owned()],
                blocked_flows: vec!["submit_order".to_owned()],
                notes: None,
            }),
            state_machine: StateMachine {
                initial_state: "ready".to_owned(),
                states: Vec::new(),
                transitions: Vec::new(),
            },
        };
        recipe.capabilities.insert(
            "account_statement".to_owned(),
            CapabilitySpec {
                data_channel: DataChannel::FileExport,
                flow: Some("export_account_statement_csv".to_owned()),
                safety_level: SafetyLevel::ReadOnly,
                latency_ms_est: Some(2500),
                artifact_path: Some("/tmp/tos.csv".to_owned()),
                fallback_method: Some(DataChannel::ScreenshotRoi),
                fallback_capability: None,
                output_schema: None,
            },
        );

        assert!(lookup_capability(&recipe, "account_statement").is_ok());
        assert!(lookup_capability(&recipe, "missing_cap").is_err());

        // Restricted level blocked under ReadOnly / AuthOnly
        let blocked_res = check_safety_gate(
            &recipe,
            Some("trade"),
            &[],
            SafetyLevel::Restricted,
            SafetyLevel::AuthOnly,
        )
        .unwrap_err();
        assert_eq!(blocked_res.structured_content.as_ref().unwrap()["code"], "safety_gate_blocked");

        // Blocked flow name rejected
        let blocked_flow = check_safety_gate(
            &recipe,
            Some("submit_order"),
            &[],
            SafetyLevel::ReadOnly,
            SafetyLevel::Restricted,
        )
        .unwrap_err();
        assert_eq!(blocked_flow.structured_content.as_ref().unwrap()["code"], "safety_gate_blocked");

        // Blocked shortcut in step rejected
        let step = RecipeStep {
            action: "hotkey".to_owned(),
            args: json!({ "keys": ["ctrl", "Enter"] }),
            wait_for_stable_frame_ms: None,
            description: None,
            method: None,
            safety_level: None,
            latency_ms_est: None,
            fallback_method: None,
        };
        let blocked_key = check_safety_gate(
            &recipe,
            Some("custom"),
            &[step],
            SafetyLevel::ReadOnly,
            SafetyLevel::AuthOnly,
        )
        .unwrap_err();
        assert_eq!(blocked_key.structured_content.as_ref().unwrap()["code"], "safety_gate_blocked");

        // type_secret_from_env defaults to AuthOnly when step.safety_level is None:
        // rejected under allow_safety_level=read_only, allowed under auth_only.
        let secret_step = RecipeStep {
            action: "type_secret_from_env".to_owned(),
            args: json!({ "env_key": "CUA_YCWANG_TOS_LIVE_USERNAME" }),
            wait_for_stable_frame_ms: None,
            description: None,
            method: None,
            safety_level: None,
            latency_ms_est: None,
            fallback_method: None,
        };
        let blocked_secret = check_safety_gate(
            &recipe,
            Some("login_live_from_env"),
            std::slice::from_ref(&secret_step),
            SafetyLevel::ReadOnly,
            SafetyLevel::ReadOnly,
        )
        .unwrap_err();
        assert_eq!(
            blocked_secret.structured_content.as_ref().unwrap()["code"],
            "safety_gate_blocked"
        );
        assert_eq!(
            blocked_secret.structured_content.as_ref().unwrap()["required_level"],
            "auth_only"
        );
        assert!(check_safety_gate(
            &recipe,
            Some("login_live_from_env"),
            &[secret_step],
            SafetyLevel::ReadOnly,
            SafetyLevel::AuthOnly,
        )
        .is_ok());
    }

    #[test]
    fn format_artifacts_summary_renders_file_clipboard_and_screenshot_details() {
        let artifacts = vec![
            json!({
                "kind": "file_export",
                "path": "/tmp/tos.csv",
                "bytes": 42,
                "preview": "Account,Cash\n123,456",
            }),
            json!({
                "kind": "clipboard",
                "bytes": 18,
                "content": "Date\tProb\n2026\t50%",
            }),
            json!({
                "kind": "screenshot_roi",
                "width": 800,
                "height": 600,
                "bytes": 12345,
            }),
        ];
        let summary = format_artifacts_summary(&artifacts);
        assert!(summary.contains("path=/tmp/tos.csv bytes=42"));
        assert!(summary.contains("Account,Cash"));
        assert!(summary.contains("bytes=18 line_count=2"));
        assert!(summary.contains("Date\tProb"));
        assert!(summary.contains("800x600 bytes=12345"));
    }
}
