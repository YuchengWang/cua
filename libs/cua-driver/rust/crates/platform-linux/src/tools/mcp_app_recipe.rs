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
        auto_upgrade_recipe_version, find_best_recipe_with_path, global_recipe_cache, load_recipe,
        recipes_dir, resolve_relative_anchor_xy, save_recipe_to_dir, AppRecipe, AuthGate,
        CapabilitySpec, DataChannel, ModalHandler, RecipeState, RecipeStep, RecipeTransition,
        RelativeAnchor, SafetyLevel, StateMachine, VerifyResult, VersionGate,
    },
    authorization::{configured_permission_mode, launch_grant_enabled, PermissionMode},
    browser::{
        cdp_ws::{
            redacted_loopback_ws_endpoint, validate_loopback_ws_url, CdpConnection, CdpMethodPolicy,
        },
        fetch_json_version_ws_url, is_electron_app_layout, loopback_websocket_port, BrowserProduct,
    },
    protocol::ToolResult,
    session_authorization::EffectiveAuthorizationContext,
    tool::{current_dispatch_authorization_context, Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app_inspector::{inspect_app_flow, InspectAppFlowRequest};
use crate::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};
use cua_driver_core::totp::{TotpConfig, DEFAULT_MIN_REMAINING_SECS};

use crate::tools::mcp_type_secret::{
    resolve_secret_from_env, resolve_totp_outcome_from_env, type_secret_into_context,
    validate_env_key,
};
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
        let auth_ctx = current_dispatch_authorization_context();
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

            let (mut recipe, resolved_recipe_path) = resolve_recipe_with_path_for_invocation(
                recipe_path.as_deref(),
                &app_id,
                &inspection,
            )?;

            // Check VersionGate (unless explicitly seeded template).
            // On VersionMismatch, keep compatibility and run the existing flows/state_machine
            // first: auto-upgrade on success, or preserve original version + report on failure.
            let is_seeded =
                recipe.app_version == "seeded" || recipe.fingerprint_sha256 == "seeded";
            let version_mismatch = if !is_seeded {
                match VersionGate::verify(
                    &recipe,
                    &inspection.app_version,
                    &inspection.fingerprint_sha256,
                ) {
                    VerifyResult::Matched { .. } => None,
                    mismatch @ VerifyResult::VersionMismatch { .. } => {
                        tracing::info!(
                            app_id = %recipe.app_id,
                            expected_version = %recipe.app_version,
                            actual_version = %inspection.app_version,
                            "VersionGate mismatch detected; attempting compatible execution with existing recipe"
                        );
                        Some(mismatch)
                    }
                }
            } else {
                None
            };

            let target = DisplayTarget::from_display_id(display_id.as_deref())?;
            let ctx = global_screen_pool().get_or_connect(&target).ok();

            let exec_result = execute_run_app_recipe_body(
                ctx.as_deref(),
                &recipe,
                &inspection,
                flow_name.as_deref(),
                target_window_id,
                target_pid,
                allow_safety_level,
                auth_ctx.as_deref(),
            );

            match exec_result {
                Ok(RecipeRunOutcome::Completed {
                    mut message,
                    mut structured,
                }) => {
                    if let Some(VerifyResult::VersionMismatch {
                        expected_version,
                        actual_version,
                        expected_fp8,
                        actual_fp8,
                        ..
                    }) = version_mismatch
                    {
                        match auto_upgrade_recipe_version(
                            global_recipe_cache(),
                            &mut recipe,
                            resolved_recipe_path.as_deref(),
                            &actual_version,
                            &inspection.fingerprint_sha256,
                        ) {
                            Ok(()) => {
                                if let Some(obj) = structured.as_object_mut() {
                                    obj.insert("app_version".into(), json!(recipe.app_version));
                                    obj.insert("fp8".into(), json!(recipe.fp8()));
                                    obj.insert("version_upgraded".into(), json!(true));
                                    obj.insert("previous_version".into(), json!(expected_version));
                                    obj.insert("previous_fp8".into(), json!(expected_fp8));
                                }
                                message.push_str(&format!(
                                    "\n\n[VersionGate] Auto-upgraded recipe {} from v{} ({}) to v{} ({}) and persisted to disk & hot cache.",
                                    recipe.app_id,
                                    expected_version,
                                    expected_fp8,
                                    recipe.app_version,
                                    recipe.fp8()
                                ));
                            }
                            Err(upgrade_err) => {
                                tracing::warn!(
                                    app_id = %recipe.app_id,
                                    error = %upgrade_err,
                                    "failed to persist auto-upgraded recipe version"
                                );
                                if let Some(obj) = structured.as_object_mut() {
                                    obj.insert("version_upgraded".into(), json!(false));
                                    obj.insert(
                                        "version_upgrade_error".into(),
                                        json!(upgrade_err),
                                    );
                                    obj.insert("actual_version".into(), json!(actual_version));
                                    obj.insert("actual_fp8".into(), json!(actual_fp8));
                                }
                                message.push_str(&format!(
                                    "\n\n[VersionGate] Warning: flow succeeded on v{actual_version} ({actual_fp8}), but failed to persist version upgrade: {upgrade_err}"
                                ));
                            }
                        }
                    }
                    Ok(ToolResult::text(message).with_structured(structured))
                }
                Ok(RecipeRunOutcome::EarlyToolResult(mut res)) => {
                    if let Some(VerifyResult::VersionMismatch {
                        expected_version,
                        actual_version,
                        expected_fp8,
                        actual_fp8,
                        ..
                    }) = version_mismatch
                    {
                        if res.is_error == Some(true) {
                            let orig_text = res
                                .content
                                .iter()
                                .filter_map(|c| match c {
                                    cua_driver_core::protocol::Content::Text { text, .. } => {
                                        Some(text.as_str())
                                    }
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            let enriched = format!(
                                "VersionGate mismatch (recipe v{expected_version} ({expected_fp8}) vs live v{actual_version} ({actual_fp8})), and compatible execution failed: {orig_text}. Recipe was NOT updated; please update the recipe JSON flows/state_machine for the new version."
                            );
                            let mut structured = res.structured_content.take().unwrap_or_else(|| json!({}));
                            if let Some(obj) = structured.as_object_mut() {
                                obj.insert("expected_version".into(), json!(expected_version));
                                obj.insert("actual_version".into(), json!(actual_version));
                                obj.insert("expected_fp8".into(), json!(expected_fp8));
                                obj.insert("actual_fp8".into(), json!(actual_fp8));
                                obj.insert("version_upgraded".into(), json!(false));
                            }
                            return Ok(ToolResult::error(enriched).with_structured(structured));
                        }
                    }
                    Ok(res)
                }
                Err(err) => {
                    if let Some(VerifyResult::VersionMismatch {
                        expected_version,
                        actual_version,
                        expected_fp8,
                        actual_fp8,
                        ..
                    }) = version_mismatch
                    {
                        return Ok(ToolResult::error(format!(
                            "VersionGate mismatch (recipe v{expected_version} ({expected_fp8}) vs live v{actual_version} ({actual_fp8})), and existing recipe execution failed: {err:#}. Recipe was NOT updated; please update the recipe JSON flows/state_machine for the new version."
                        ))
                        .with_structured(json!({
                            "status": "failed",
                            "app_id": recipe.app_id,
                            "expected_version": expected_version,
                            "actual_version": actual_version,
                            "expected_fp8": expected_fp8,
                            "actual_fp8": actual_fp8,
                            "version_upgraded": false,
                            "error": format!("{err:#}"),
                        })));
                    }
                    Err(err)
                }
            }
        })
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => ToolResult::error(format!("run_app_recipe failed: {e:#}")),
            Err(e) => ToolResult::error(format!("run_app_recipe panicked: {e}")),
        }
    }
}

enum RecipeRunOutcome {
    Completed {
        message: String,
        structured: Value,
    },
    EarlyToolResult(ToolResult),
}

#[allow(clippy::too_many_arguments)]
fn execute_run_app_recipe_body(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    inspection: &crate::app_inspector::AppFlowInspection,
    flow_name: Option<&str>,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    allow_safety_level: SafetyLevel,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> anyhow::Result<RecipeRunOutcome> {
    if let Some(flow) = flow_name {
        let steps = recipe.flows.get(flow).ok_or_else(|| {
            let available: Vec<&str> = recipe.flows.keys().map(String::as_str).collect();
            anyhow::anyhow!(
                "flow '{flow}' not found in recipe {} (available: {:?})",
                recipe.canonical_filename(),
                available
            )
        })?;
        if let Err(blocked) = check_safety_gate(
            recipe,
            Some(flow),
            steps,
            SafetyLevel::ReadOnly,
            allow_safety_level,
        ) {
            return Ok(RecipeRunOutcome::EarlyToolResult(blocked));
        }
        let FlowExecutionResult {
            steps: executed_steps,
            artifacts,
            error: step_err,
        } = execute_flow_steps_with_auth(
            ctx,
            recipe,
            target_window_id,
            target_pid,
            steps,
            auth_ctx,
        );
        if let Some((idx, action, err)) = step_err {
            return Ok(RecipeRunOutcome::EarlyToolResult(
                ToolResult::error(format!(
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
                })),
            ));
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
        return Ok(RecipeRunOutcome::Completed {
            message: msg,
            structured: json!({
                "status": "completed",
                "app_id": recipe.app_id,
                "app_version": recipe.app_version,
                "fp8": recipe.fp8(),
                "flow": flow,
                "steps": executed_steps,
                "artifacts": artifacts,
            }),
        });
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
                        return Ok(RecipeRunOutcome::EarlyToolResult(
                            ToolResult::error(format!(
                                "human verification required: matched '{pat}'"
                            ))
                            .with_structured(json!({
                                "status": "human_verification_required",
                                "state": state.id,
                                "pattern": pat,
                            })),
                        ));
                    }
                }
            }

            // Out-of-band auth_gate handling (never logs or returns plaintext).
            if let Some(ref gate) = state.auth_gate {
                if allow_safety_level < SafetyLevel::AuthOnly {
                    return Ok(RecipeRunOutcome::EarlyToolResult(
                        ToolResult::error(
                            "safety_gate_blocked: auth_gate requires 'auth_only' or higher",
                        )
                        .with_structured(json!({
                            "status": "safety_gate_blocked",
                            "code": "safety_gate_blocked",
                            "app_id": recipe.app_id,
                            "state": state.id,
                            "required_level": SafetyLevel::AuthOnly.as_str(),
                            "allowed_level": allow_safety_level.as_str(),
                        })),
                    ));
                }
                let details = execute_auth_gate(ctx, target_window_id, gate)?;
                executed_steps.push(json!({
                    "state": state.id,
                    "status": "auth_step_completed",
                    "details": details,
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
        let tx_step = RecipeStep {
            action: tx.action.clone(),
            args: tx.args.clone(),
            wait_for_stable_frame_ms: tx.wait_for_stable_frame_ms,
            description: None,
            method: None,
            safety_level: None,
            latency_ms_est: None,
            fallback_method: None,
        };
        if let Err(blocked) = check_safety_gate(
            recipe,
            None,
            std::slice::from_ref(&tx_step),
            SafetyLevel::ReadOnly,
            allow_safety_level,
        ) {
            return Ok(RecipeRunOutcome::EarlyToolResult(blocked));
        }
        let details = execute_recipe_step_with_auth(
            ctx,
            recipe,
            target_window_id,
            target_pid,
            &tx.action,
            &tx.args,
            auth_ctx,
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

    Ok(RecipeRunOutcome::Completed {
        message: format!(
            "Completed recipe {} ({} steps)",
            recipe.canonical_filename(),
            executed_steps.len()
        ),
        structured: json!({
            "status": "completed",
            "app_id": recipe.app_id,
            "app_version": recipe.app_version,
            "fp8": recipe.fp8(),
            "final_state": current_state_id,
            "steps": executed_steps,
        }),
    })
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
                    "recipe_path": { "type": "string" },
                    "pid": { "type": "integer" },
                    "window_id": { "type": "integer" },
                    "app_path": { "type": "string" },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema(),
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
        let auth_ctx = current_dispatch_authorization_context();
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

            let recipe = resolve_recipe_for_invocation(recipe_path.as_deref(), &app_id, &inspection)?;

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
                effective_capability_safety_level(spec),
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
                auth_ctx.as_deref(),
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
                        let fb_required = if fb_method == DataChannel::Cdp {
                            SafetyLevel::AuthOnly
                        } else {
                            SafetyLevel::ReadOnly
                        };
                        if let Err(blocked) = check_safety_gate(
                            &recipe,
                            None,
                            &[],
                            fb_required,
                            allow_safety_level,
                        ) {
                            return Ok(blocked);
                        }
                        let fb_artifact = execute_fallback_channel_with_auth(
                            ctx.as_deref(),
                            &recipe,
                            &inspection,
                            target_window_id,
                            target_pid,
                            fb_method,
                            spec,
                            auth_ctx.as_deref(),
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
                            effective_capability_safety_level(fb_spec),
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
                            auth_ctx.as_deref(),
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
        "type_secret_from_env"
        | "type_totp_from_env"
        | "cdp_call"
        | "atspi_click"
        | "atspi_set_value"
        | "interact_popup" => SafetyLevel::AuthOnly,
        _ => SafetyLevel::ReadOnly,
    }
}

fn effective_capability_safety_level(spec: &CapabilitySpec) -> SafetyLevel {
    let min_level = match spec.data_channel {
        DataChannel::Cdp => SafetyLevel::AuthOnly,
        _ => SafetyLevel::ReadOnly,
    };
    spec.safety_level.max(min_level)
}

fn effective_step_safety_level(step: &RecipeStep) -> SafetyLevel {
    let base = default_step_safety_level(&step.action);
    let inferred = if step.action == "atspi_match_dialog"
        && (step
            .args
            .get("env_key")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
            || step
                .args
                .get("rule")
                .and_then(|r| r.get("env_key"))
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty()))
    {
        SafetyLevel::AuthOnly
    } else {
        base
    };
    step.safety_level.map_or(inferred, |explicit| explicit.max(inferred))
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

fn execute_flow_steps_with_auth(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    steps: &[RecipeStep],
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> FlowExecutionResult {
    let _ime_guard = match ctx {
        Some(c) => crate::ime::ImeGuard::acquire_for_target(&c.target),
        None => crate::ime::ImeGuard::acquire(),
    };
    let mut executed_steps = Vec::with_capacity(steps.len());
    let mut artifacts = Vec::new();
    for (idx, step) in steps.iter().enumerate() {
        if let Some(ms) = step.wait_for_stable_frame_ms {
            std::thread::sleep(std::time::Duration::from_millis(ms.min(5_000)));
        }
        match execute_recipe_step_with_auth(
            ctx,
            recipe,
            target_window_id,
            target_pid,
            &step.action,
            &step.args,
            auth_ctx,
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
    auth_ctx: Option<&EffectiveAuthorizationContext>,
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
        } = execute_flow_steps_with_auth(
            ctx,
            recipe,
            target_window_id,
            target_pid,
            steps,
            auth_ctx,
        );
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

    let artifact = execute_fallback_channel_with_auth(
        ctx,
        recipe,
        inspection,
        target_window_id,
        target_pid,
        spec.data_channel,
        spec,
        auth_ctx,
    )?;
    Ok((Vec::new(), vec![artifact]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn execute_fallback_channel(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    inspection: &crate::app_inspector::AppFlowInspection,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    channel: DataChannel,
    spec: &CapabilitySpec,
) -> anyhow::Result<Value> {
    execute_fallback_channel_with_auth(
        ctx,
        recipe,
        inspection,
        target_window_id,
        target_pid,
        channel,
        spec,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_fallback_channel_with_auth(
    ctx: Option<&X11ScreenContext>,
    _recipe: &AppRecipe,
    inspection: &crate::app_inspector::AppFlowInspection,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    channel: DataChannel,
    spec: &CapabilitySpec,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
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
        DataChannel::Atspi => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, &json!({}));
            let pid = pid_opt.ok_or_else(|| {
                anyhow::anyhow!("atspi channel requires target pid or mapped window_id")
            })?;
            let xid = wid_opt.unwrap_or(0);
            let args = json!({ "max_elements": 250, "max_depth": 20 });
            let (walked, indices) = query_atspi_nodes(pid, xid, &args)?;
            let nodes = atspi_nodes_json(&walked, &indices, 80);
            Ok(json!({
                "kind": "atspi",
                "pid": pid,
                "window_id": wid_opt,
                "count": nodes.len(),
                "total_walked": walked.nodes.len(),
                "truncated": walked.truncated,
                "degraded_reason": walked.degraded_reason,
                "nodes": nodes,
            }))
        }
        DataChannel::Cdp => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, &json!({}));
            execute_cdp_channel(pid_opt, wid_opt, spec, auth_ctx)
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

fn execute_auth_gate(
    ctx: Option<&X11ScreenContext>,
    target_window_id: Option<u64>,
    gate: &AuthGate,
) -> anyhow::Result<Value> {
    let press_enter = gate.press_enter.unwrap_or(false);
    if gate.kind.eq_ignore_ascii_case("totp") || gate.kind.eq_ignore_ascii_case("totp_env") {
        let min_remaining_secs = gate
            .min_remaining_secs
            .unwrap_or(DEFAULT_MIN_REMAINING_SECS);
        let outcome = if let Some(ref env_key) = gate.env_key {
            validate_env_key(env_key)?;
            resolve_totp_outcome_from_env(env_key, gate.env_file.as_deref(), min_remaining_secs)?
        } else {
            let raw = resolve_auth_gate_secret(gate)?;
            let cfg = TotpConfig::from_secret_or_uri(&raw)?;
            drop(raw);
            cfg.generate_now_with_guard(min_remaining_secs)?
        };
        if let Some(xctx) = ctx {
            if let Some(wid) = target_window_id {
                let _ = xtest_focus_window(xctx, wid);
            }
            let key_label = gate.env_key.as_deref().unwrap_or("auth_gate_totp");
            type_secret_into_context(xctx, key_label, &outcome.code, press_enter)?;
        }
        let meta = json!({
            "kind": gate.kind,
            "digits": outcome.digits,
            "period": outcome.period,
            "waited_boundary": outcome.waited_boundary,
            "waited_ms": outcome.waited_ms,
            "remaining_secs": outcome.remaining_secs,
            "press_enter": press_enter,
        });
        drop(outcome);
        return Ok(meta);
    }

    let secret = if let Some(ref env_key) = gate.env_key {
        validate_env_key(env_key)?;
        resolve_secret_from_env(env_key, gate.env_file.as_deref())?
    } else {
        resolve_auth_gate_secret(gate)?
    };
    let char_len = secret.chars().count();
    if let Some(xctx) = ctx {
        if let Some(wid) = target_window_id {
            let _ = xtest_focus_window(xctx, wid);
        }
        xtest_type_text(xctx, &secret)?;
        if press_enter {
            xtest_press_key(xctx, "Return")?;
        }
    }
    drop(secret);
    Ok(json!({
        "kind": gate.kind,
        "length": char_len,
        "press_enter": press_enter,
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

fn resolve_recipe_for_invocation(
    recipe_path: Option<&Path>,
    app_id: &str,
    inspection: &crate::app_inspector::AppFlowInspection,
) -> anyhow::Result<AppRecipe> {
    resolve_recipe_with_path_for_invocation(recipe_path, app_id, inspection).map(|(r, _)| r)
}

fn resolve_recipe_with_path_for_invocation(
    recipe_path: Option<&Path>,
    app_id: &str,
    inspection: &crate::app_inspector::AppFlowInspection,
) -> anyhow::Result<(AppRecipe, Option<PathBuf>)> {
    if let Some(p) = recipe_path {
        let loaded = load_recipe(p).map_err(|e| anyhow::anyhow!("{e}"))?;
        let path_buf = p.to_path_buf();
        global_recipe_cache().insert_with_path(loaded.clone(), Some(path_buf.clone()));
        return Ok((loaded, Some(path_buf)));
    }
    if let Some(cached) = global_recipe_cache().get(
        app_id,
        &inspection.app_version,
        &inspection.fingerprint_sha256,
    ) {
        return Ok(((*cached).clone(), None));
    }
    let dir = recipes_dir().ok_or_else(|| anyhow::anyhow!("app_recipes directory unavailable"))?;
    let (found, found_path) = find_best_recipe_with_path(
        &dir,
        app_id,
        Some(&inspection.app_version),
        Some(&inspection.fingerprint_sha256),
    )
    .ok_or_else(|| {
        if inspection.channel == "browser_exempt" {
            anyhow::anyhow!(
                "no matching recipe for {app_id} v{} ({}); for web DOM/network automation use chrome_devtools MCP, or deploy google-chrome.json for OS-layer flows",
                inspection.app_version,
                inspection.fp8
            )
        } else {
            anyhow::anyhow!(
                "no matching recipe for {app_id} v{} ({})",
                inspection.app_version,
                inspection.fp8
            )
        }
    })?;
    global_recipe_cache().insert_with_path(found.clone(), Some(found_path.clone()));
    Ok((found, Some(found_path)))
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
            || (needle == "google-chrome"
                && (title.contains("google chrome")
                    || app.contains("google-chrome")
                    || app.contains("chrome")))
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

fn resolve_consent_target(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    args: &Value,
) -> anyhow::Result<(i64, u64)> {
    let mut pid = args
        .get("pid")
        .and_then(Value::as_i64)
        .or_else(|| target_pid.map(i64::from));
    let mut window_id = args
        .get("window_id")
        .and_then(Value::as_u64)
        .or(target_window_id);

    if (pid.is_none() || window_id.is_none()) && ctx.is_some() {
        let xctx = ctx.unwrap();
        let wins = crate::x11::list_windows_with_context(xctx, None);
        let matched = if let Some(wid) = window_id {
            wins.into_iter().find(|w| w.xid == wid)
        } else if let Some(p) = pid {
            wins.into_iter().find(|w| w.pid.map(i64::from) == Some(p))
        } else {
            let app_lower = recipe.app_id.to_ascii_lowercase();
            wins.into_iter().find(|w| {
                w.app_name.to_ascii_lowercase().contains(&app_lower)
                    || w.title.to_ascii_lowercase().contains("chrome")
            })
        };
        if let Some(w) = matched {
            if pid.is_none() {
                pid = w.pid.map(i64::from);
            }
            if window_id.is_none() {
                window_id = Some(w.xid);
            }
        }
    }

    let pid = pid.ok_or_else(|| {
        anyhow::anyhow!("approve_remote_debugging_consent requires target 'pid' (or mapped window)")
    })?;
    let window_id = window_id.ok_or_else(|| {
        anyhow::anyhow!(
            "approve_remote_debugging_consent requires target 'window_id' (or mapped window)"
        )
    })?;
    Ok((pid, window_id))
}

fn run_async_step<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            tokio::task::block_in_place(|| handle.block_on(fut))
        } else {
            std::thread::scope(|s| {
                s.spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("tokio runtime for recipe step")
                        .block_on(fut)
                })
                .join()
                .expect("recipe step async helper thread panicked")
            })
        }
    } else {
        tokio::runtime::Runtime::new()
            .expect("tokio runtime for recipe step")
            .block_on(fut)
    }
}

fn run_async_consent<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    run_async_step(fut)
}

fn resolve_step_pid_window(
    ctx: Option<&X11ScreenContext>,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    args: &Value,
) -> (Option<u32>, Option<u64>) {
    let wid = args.get("window_id").and_then(Value::as_u64).or(target_window_id);
    let mut pid = args
        .get("pid")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .or(target_pid);
    if pid.is_none() {
        if let Some(xid) = wid {
            pid = ctx
                .and_then(|c| crate::x11::window_info_with_context(c, xid))
                .and_then(|w| w.pid)
                .or_else(|| crate::x11::window_pid(xid));
        }
    }
    (pid, wid)
}

fn query_atspi_nodes(
    pid: u32,
    xid: u64,
    args: &Value,
) -> anyhow::Result<(crate::atspi::AtspiTreeResult, Vec<usize>)> {
    let query = args.get("query").and_then(Value::as_str);
    let role_filter = args.get("role").and_then(Value::as_str);
    let role_re = role_filter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(regex::Regex::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid 'role' regex: {e}"))?;
    let name_re = args
        .get("name_regex")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(regex::Regex::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid 'name_regex' regex: {e}"))?;
    let max_elements = args
        .get("max_elements")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).clamp(1, 2000))
        .unwrap_or(300);
    let max_depth = args
        .get("max_depth")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).clamp(1, 64))
        .unwrap_or(24);
    let skip_web_content = args
        .get("skip_web_content")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(4_000)
        .clamp(300, 15_000);

    let walked = crate::atspi::walk_tree_bounded_within_options(
        pid,
        xid,
        query,
        Some(max_elements),
        Some(max_depth),
        std::time::Duration::from_millis(timeout_ms),
        skip_web_content,
    );
    let mut matched = Vec::new();
    for (idx, node) in walked.nodes.iter().enumerate() {
        if let Some(ref re) = role_re {
            let exact_ci = role_filter.is_some_and(|r| node.role.eq_ignore_ascii_case(r.trim()));
            if !exact_ci && !re.is_match(&node.role) {
                continue;
            }
        }
        if let Some(ref re) = name_re {
            let name = node.name.as_deref().unwrap_or("");
            if !re.is_match(name) {
                continue;
            }
        }
        matched.push(idx);
    }
    Ok((walked, matched))
}

fn atspi_nodes_json(
    walked: &crate::atspi::AtspiTreeResult,
    indices: &[usize],
    limit: usize,
) -> Vec<Value> {
    let bounds_by_idx: HashMap<usize, (i32, i32, u32, u32)> = walked
        .bounds
        .iter()
        .map(|(i, x, y, w, h)| (*i, (*x, *y, *w, *h)))
        .collect();
    indices
        .iter()
        .take(limit)
        .filter_map(|idx| walked.nodes.get(*idx))
        .map(|n| {
            let bounds = n
                .element_index
                .and_then(|ei| bounds_by_idx.get(&ei).copied())
                .map(|(x, y, w, h)| json!([x, y, w, h]));
            json!({
                "element_index": n.element_index,
                "role": n.role,
                "name": n.name,
                "value": n.value,
                "enabled": n.enabled,
                "focused": n.focused,
                "actions": n.actions,
                "bounds": bounds,
            })
        })
        .collect()
}

struct AuthorizedCdpTarget {
    ws_url: String,
    method_policy: CdpMethodPolicy,
}

fn is_consumer_browser_product(product: BrowserProduct) -> bool {
    matches!(
        product,
        BrowserProduct::GoogleChrome
            | BrowserProduct::Chromium
            | BrowserProduct::MicrosoftEdge
            | BrowserProduct::Brave
            | BrowserProduct::Vivaldi
            | BrowserProduct::Opera
            | BrowserProduct::Arc
    )
}

fn evaluate_cdp_target_policy(
    pid: u32,
    wid: Option<u64>,
    product: BrowserProduct,
    is_electron_layout: bool,
    mode: PermissionMode,
    has_existing_profile_grant: bool,
    manifest: Option<&cua_driver_core::session_manifest::SessionManifest>,
) -> anyhow::Result<CdpMethodPolicy> {
    if product == BrowserProduct::Firefox {
        anyhow::bail!("pid {pid} is Firefox, which does not expose a supported CDP endpoint");
    }
    if !is_electron_layout && is_consumer_browser_product(product) {
        match mode {
            PermissionMode::Unrestricted => {}
            PermissionMode::Bounded => {
                let m = manifest.ok_or_else(|| {
                    anyhow::anyhow!(
                        "consumer browser pid {pid} requires an approved capability manifest in bounded mode"
                    )
                })?;
                m.authorize_call(
                    "browser_prepare",
                    &json!({
                        "pid": pid,
                        "window_id": wid,
                        "strategy": { "kind": "existing_profile" },
                    }),
                )
                .map_err(|msg| {
                    anyhow::anyhow!("consumer browser CDP access denied for pid {pid}: {msg}")
                })?;
            }
            PermissionMode::Standard => {
                if !has_existing_profile_grant {
                    anyhow::bail!(
                        "consumer browser CDP access for pid {pid} ({product:?}) requires --grant existing-profile in standard mode; use browser_prepare with strategy=existing_profile"
                    );
                }
            }
        }
        return Ok(CdpMethodPolicy::ExistingProfile);
    }
    Ok(CdpMethodPolicy::Unrestricted)
}

fn inspect_process_for_cdp(pid: u32) -> anyhow::Result<(BrowserProduct, bool)> {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        anyhow::bail!("target process {pid} is not running or inaccessible for CDP authorization");
    }
    let exe_path = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let electron_layout = exe_path.as_deref().is_some_and(is_electron_app_layout);
    let identity = exe_path
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| {
            anyhow::anyhow!("cannot inspect target process {pid} identity for CDP authorization")
        })?;
    let product = if electron_layout {
        BrowserProduct::Electron
    } else {
        crate::browser_platform::browser_product(&identity)
    };
    Ok((product, electron_layout))
}

fn classify_and_authorize_cdp_pid(
    pid: u32,
    wid: Option<u64>,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> anyhow::Result<CdpMethodPolicy> {
    if pid <= 1 {
        anyhow::bail!("refusing CDP access for invalid or system pid {pid}");
    }
    #[cfg(not(test))]
    if pid == std::process::id() {
        anyhow::bail!("refusing CDP access targeting cua-driver's own process");
    }
    let (product, electron_layout) = inspect_process_for_cdp(pid)?;
    let mode = auth_ctx
        .map(|ctx| ctx.mode())
        .map(Ok)
        .unwrap_or_else(configured_permission_mode)
        .map_err(|e| anyhow::anyhow!("permission mode unavailable: {e}"))?;
    let manifest = auth_ctx.and_then(|ctx| ctx.capability_manifest());
    evaluate_cdp_target_policy(
        pid,
        wid,
        product,
        electron_layout,
        mode,
        launch_grant_enabled("existing_profile"),
        manifest,
    )
}

fn find_loopback_listener_pids(port: u16) -> anyhow::Result<Vec<u32>> {
    let mut inodes = std::collections::HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for (p, inode) in crate::browser_platform::parse_proc_net_loopback_listeners(&text) {
                if p == port && inode > 0 {
                    inodes.insert(inode);
                }
            }
        }
    }
    if inodes.is_empty() {
        anyhow::bail!(
            "cannot verify target process permission: no loopback listener found on port {port}"
        );
    }
    let mut owners = Vec::new();
    let entries = std::fs::read_dir("/proc")
        .map_err(|e| anyhow::anyhow!("cannot scan /proc to verify port {port} owner: {e}"))?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let owns = fds.flatten().any(|fd| {
            std::fs::read_link(fd.path()).ok().is_some_and(|target| {
                let s = target.to_string_lossy();
                s.strip_prefix("socket:[")
                    .and_then(|v| v.strip_suffix(']'))
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|inode| inodes.contains(&inode))
            })
        });
        if owns {
            owners.push(pid);
        }
    }
    if owners.is_empty() {
        anyhow::bail!(
            "cannot verify target process permission for loopback port {port} (unowned or inaccessible /proc/<pid>/fd)"
        );
    }
    owners.sort_unstable();
    Ok(owners)
}

fn verify_port_owned_by_pid(pid: u32, port: u16) -> anyhow::Result<()> {
    let owned_ports = crate::browser_platform::loopback_ports_for_pid(i64::from(pid))
        .map_err(|refusal| anyhow::anyhow!("{}", refusal.message))?;
    if !owned_ports.contains(&port) {
        anyhow::bail!(
            "CDP loopback port {port} is not owned by target pid {pid} process tree"
        );
    }
    Ok(())
}

fn redact_ws_url(text: &str, ws_url: &str, redacted: &str) -> String {
    let mut out = text.replace(ws_url, redacted);
    if let Some(rest) = ws_url.strip_prefix("ws://") {
        if let Some(idx) = rest.find('/') {
            let path = &rest[idx..];
            if path.len() > 1 {
                out = out.replace(path, "/[redacted]");
            }
        }
    }
    out
}

fn cdp_policy_label(policy: CdpMethodPolicy) -> &'static str {
    match policy {
        CdpMethodPolicy::ExistingProfile => "existing_profile",
        CdpMethodPolicy::Unrestricted => "unrestricted",
    }
}

async fn resolve_and_authorize_cdp_target_async(
    pid: Option<u32>,
    wid: Option<u64>,
    explicit_ws: Option<&str>,
    port: Option<u16>,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> anyhow::Result<AuthorizedCdpTarget> {
    let explicit_ws = explicit_ws.map(str::trim).filter(|s| !s.is_empty());
    if let Some(ws) = explicit_ws {
        validate_loopback_ws_url(ws).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if port == Some(0) {
        anyhow::bail!("CDP port 0 is invalid");
    }
    let port_hint = port.or_else(|| explicit_ws.and_then(loopback_websocket_port));
    if explicit_ws.is_some() && port_hint.is_none() {
        anyhow::bail!("explicit ws_url must specify a valid loopback TCP port");
    }

    let explicit_target_pid = match (pid, wid) {
        (Some(p), _) => Some(p),
        (None, Some(w)) => Some(crate::x11::window_pid(w).ok_or_else(|| {
            anyhow::anyhow!("cannot resolve _NET_WM_PID for window_id {w} to verify CDP permission")
        })?),
        (None, None) => None,
    };

    let (target_pid, mut method_policy) = if let Some(tpid) = explicit_target_pid {
        let mut policy = classify_and_authorize_cdp_pid(tpid, wid, auth_ctx)?;
        if let Some(p) = port_hint {
            verify_port_owned_by_pid(tpid, p)?;
            for owner in find_loopback_listener_pids(p)? {
                if classify_and_authorize_cdp_pid(owner, wid, auth_ctx)?
                    == CdpMethodPolicy::ExistingProfile
                {
                    policy = CdpMethodPolicy::ExistingProfile;
                }
            }
        }
        (tpid, policy)
    } else if let Some(p) = port_hint {
        let owners = find_loopback_listener_pids(p)?;
        let mut combined = CdpMethodPolicy::Unrestricted;
        for owner in &owners {
            if classify_and_authorize_cdp_pid(*owner, None, auth_ctx)?
                == CdpMethodPolicy::ExistingProfile
            {
                combined = CdpMethodPolicy::ExistingProfile;
            }
        }
        (owners[0], combined)
    } else {
        anyhow::bail!(
            "CDP access requires target pid, window_id, or verifiable loopback endpoint"
        );
    };

    let ws_url = if let Some(ws) = explicit_ws {
        ws.to_owned()
    } else if let Some(p) = port {
        let ws_url = fetch_json_version_ws_url(p)
            .await
            .ok_or_else(|| anyhow::anyhow!("no /json/version WebSocket URL on loopback port {p}"))?;
        validate_loopback_ws_url(&ws_url).map_err(|e| anyhow::anyhow!("{e}"))?;
        let resolved_port = loopback_websocket_port(&ws_url).ok_or_else(|| {
            anyhow::anyhow!("/json/version WebSocket URL is missing a valid loopback port")
        })?;
        verify_port_owned_by_pid(target_pid, resolved_port)?;
        for owner in find_loopback_listener_pids(resolved_port)? {
            if classify_and_authorize_cdp_pid(owner, wid, auth_ctx)?
                == CdpMethodPolicy::ExistingProfile
            {
                method_policy = CdpMethodPolicy::ExistingProfile;
            }
        }
        ws_url
    } else {
        let report =
            crate::webview_probe::probe_webview_targets(Some(target_pid), wid, true, None).await?;
        let mut selected = None;
        'outer: for ep in &report.endpoints {
            if let Some(ref ws) = ep.browser_ws_url {
                if validate_loopback_ws_url(ws).is_ok() {
                    if let Some(resolved_port) = loopback_websocket_port(ws) {
                        if verify_port_owned_by_pid(target_pid, resolved_port).is_ok() {
                            selected = Some((ws.clone(), resolved_port));
                            break 'outer;
                        }
                    }
                }
            }
            for page in &ep.page_targets {
                if page.target_type.as_deref() == Some("page") {
                    if let Some(ref ws) = page.ws_url {
                        if validate_loopback_ws_url(ws).is_ok() {
                            if let Some(resolved_port) = loopback_websocket_port(ws) {
                                if verify_port_owned_by_pid(target_pid, resolved_port).is_ok() {
                                    selected = Some((ws.clone(), resolved_port));
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            }
        }
        let (ws_url, resolved_port) = selected.ok_or_else(|| {
            anyhow::anyhow!(
                "no verified owned loopback CDP endpoint found for pid={} window_id={:?} (listening_ports={:?})",
                target_pid,
                wid,
                report.listening_ports
            )
        })?;
        for owner in find_loopback_listener_pids(resolved_port)? {
            if classify_and_authorize_cdp_pid(owner, wid, auth_ctx)?
                == CdpMethodPolicy::ExistingProfile
            {
                method_policy = CdpMethodPolicy::ExistingProfile;
            }
        }
        ws_url
    };

    Ok(AuthorizedCdpTarget {
        ws_url,
        method_policy,
    })
}

async fn execute_cdp_call_async(
    pid: Option<u32>,
    wid: Option<u64>,
    args: &Value,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> anyhow::Result<Value> {
    let method = args
        .get("method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("cdp_call requires 'method'"))?;
    let explicit_ws = args
        .get("ws_url")
        .or_else(|| args.get("ws_endpoint"))
        .and_then(Value::as_str);
    let port = args.get("port").and_then(Value::as_u64).map(|p| p as u16);
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(10_000)
        .clamp(500, 60_000);
    let params = args.get("params").cloned().unwrap_or_else(|| json!({}));
    let explicit_session = args
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let target_url_re = args
        .get("target_url_regex")
        .and_then(Value::as_str)
        .map(regex::Regex::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid target_url_regex: {e}"))?;
    let auto_attach_page = args
        .get("auto_attach_page")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let target = resolve_and_authorize_cdp_target_async(pid, wid, explicit_ws, port, auth_ctx).await?;
    let ws_url = target.ws_url;
    let method_policy = target.method_policy;
    let redacted_endpoint = redacted_loopback_ws_endpoint(&ws_url);
    let policy_label = cdp_policy_label(method_policy);

    let fut = async {
        let conn = CdpConnection::connect(&ws_url)
            .await
            .map_err(|e| anyhow::anyhow!("{}", redact_ws_url(&e.to_string(), &ws_url, &redacted_endpoint)))?;
        if method_policy == CdpMethodPolicy::ExistingProfile {
            conn.restrict_to_existing_profile();
        }
        let mut session_id = explicit_session;
        let is_browser_endpoint = ws_url.contains("/devtools/browser/");
        let is_browser_method = method.starts_with("Target.") || method.starts_with("Browser.");
        if session_id.is_none() && is_browser_endpoint && !is_browser_method && auto_attach_page {
            let targets_val = conn
                .call(None, "Target.getTargets", json!({}))
                .await
                .map_err(|e| anyhow::anyhow!("{}", redact_ws_url(&e.to_string(), &ws_url, &redacted_endpoint)))?;
            let chosen = targets_val
                .get("targetInfos")
                .and_then(Value::as_array)
                .and_then(|arr| {
                    arr.iter().find(|t| {
                        let is_page = t.get("type").and_then(Value::as_str) == Some("page");
                        if !is_page {
                            return false;
                        }
                        match &target_url_re {
                            Some(re) => t
                                .get("url")
                                .and_then(Value::as_str)
                                .is_some_and(|u| re.is_match(u)),
                            None => true,
                        }
                    })
                })
                .and_then(|t| t.get("targetId").and_then(Value::as_str))
                .map(str::to_owned);
            if let Some(tid) = chosen {
                let attached = conn
                    .call(
                        None,
                        "Target.attachToTarget",
                        json!({ "targetId": tid, "flatten": true }),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", redact_ws_url(&e.to_string(), &ws_url, &redacted_endpoint)))?;
                session_id = attached
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
        let result = conn
            .call(session_id.as_deref(), method, params)
            .await
            .map_err(|e| anyhow::anyhow!("{}", redact_ws_url(&e.to_string(), &ws_url, &redacted_endpoint)))?;
        Ok::<Value, anyhow::Error>(json!({
            "artifact": {
                "kind": "cdp",
                "method": method,
                "endpoint": redacted_endpoint,
                "method_policy": policy_label,
                "session_id": session_id,
                "result": result,
            },
            "method": method,
            "endpoint": redacted_endpoint,
            "method_policy": policy_label,
            "session_id": session_id,
            "result": result,
        }))
    };

    tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut)
        .await
        .map_err(|_| anyhow::anyhow!("cdp_call '{method}' timed out after {timeout_ms}ms"))?
}

fn execute_cdp_channel(
    pid: Option<u32>,
    wid: Option<u64>,
    spec: &CapabilitySpec,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
) -> anyhow::Result<Value> {
    let artifact_hint = spec.artifact_path.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let (explicit_ws, explicit_port): (Option<String>, Option<u16>) = match artifact_hint {
        Some(raw) if raw.starts_with("ws://") || raw.starts_with("wss://") => {
            (Some(raw.to_owned()), None)
        }
        Some(raw) if raw.starts_with("http://") => {
            let p = crate::webview_probe::parse_loopback_port_value(raw).ok_or_else(|| {
                anyhow::anyhow!("cdp channel artifact_path '{raw}' must be a loopback http/ws endpoint")
            })?;
            (None, Some(p))
        }
        Some(raw) => {
            if let Ok(p) = raw.parse::<u16>() {
                (None, Some(p))
            } else {
                (None, None)
            }
        }
        None => (None, None),
    };

    run_async_step(async move {
        let target = resolve_and_authorize_cdp_target_async(
            pid,
            wid,
            explicit_ws.as_deref(),
            explicit_port,
            auth_ctx,
        )
        .await?;
        let ws_url = target.ws_url;
        let method_policy = target.method_policy;
        let redacted_endpoint = redacted_loopback_ws_endpoint(&ws_url);
        let policy_label = cdp_policy_label(method_policy);

        let conn = CdpConnection::connect(&ws_url)
            .await
            .map_err(|e| anyhow::anyhow!("{}", redact_ws_url(&e.to_string(), &ws_url, &redacted_endpoint)))?;
        if method_policy == CdpMethodPolicy::ExistingProfile {
            conn.restrict_to_existing_profile();
        }
        let targets = conn.call(None, "Target.getTargets", json!({})).await.ok();
        let mut page_summary = Value::Null;
        if let Some(tid) = targets
            .as_ref()
            .and_then(|v| v.get("targetInfos"))
            .and_then(Value::as_array)
            .and_then(|arr| arr.iter().find(|t| t.get("type").and_then(Value::as_str) == Some("page")))
            .and_then(|t| t.get("targetId").and_then(Value::as_str))
        {
            if let Ok(attached) = conn
                .call(None, "Target.attachToTarget", json!({ "targetId": tid, "flatten": true }))
                .await
            {
                if let Some(sid) = attached.get("sessionId").and_then(Value::as_str) {
                    if let Ok(eval_res) = conn
                        .call(
                            Some(sid),
                            "Runtime.evaluate",
                            json!({
                                "expression": "JSON.stringify({ url: location.href, title: document.title, text: (document.body?.innerText || '').slice(0, 2000) })",
                                "returnByValue": true
                            }),
                        )
                        .await
                    {
                        page_summary = eval_res;
                    }
                }
            }
        }
        Ok(json!({
            "kind": "cdp",
            "endpoint": redacted_endpoint,
            "method_policy": policy_label,
            "targets": targets,
            "page_summary": page_summary,
        }))
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn execute_recipe_step(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    action: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    execute_recipe_step_with_auth(ctx, recipe, target_window_id, target_pid, action, args, None)
}

fn execute_recipe_step_with_auth(
    ctx: Option<&X11ScreenContext>,
    recipe: &AppRecipe,
    target_window_id: Option<u64>,
    target_pid: Option<u32>,
    action: &str,
    args: &Value,
    auth_ctx: Option<&EffectiveAuthorizationContext>,
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
            let scope = args.get("scope").and_then(Value::as_str);
            if scope != Some("desktop") {
                if let Some(wid) = target_window_id {
                    let _ = xtest_focus_window(xctx, wid);
                }
            }
            xtest_press_key(xctx, key)?;
            Ok(json!({ "key": key, "scope": scope.unwrap_or("window") }))
        }
        "approve_remote_debugging_consent" => {
            let (pid, window_id) =
                resolve_consent_target(ctx, recipe, target_window_id, target_pid, args)?;
            let attempt = args.get("attempt").and_then(Value::as_u64).unwrap_or(0) as u8;
            let request = cua_driver_core::browser::BrowserConsentRequest {
                action: cua_driver_core::browser::platform::BrowserConsentAction::default(),
                pid,
                window_id,
                attempt,
                wait_ms: None,
            };
            let outcome = run_async_consent(crate::browser_consent_ui::handle(request))
                .map_err(|refusal| anyhow::anyhow!("{} ({:?})", refusal.message, refusal.code))?;
            Ok(json!({
                "pid": pid,
                "window_id": window_id,
                "outcome": format!("{outcome:?}"),
            }))
        }
        "dismiss_modals" => {
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let wins = crate::x11::list_windows_with_context(xctx, None);
            let mut dismissed = Vec::new();
            for win in &wins {
                if let Some(handler) = recipe.modal_handlers.iter().find(|h| {
                    regex::Regex::new(&h.pattern)
                        .map(|re| re.is_match(&win.title))
                        .unwrap_or(false)
                }) {
                    let _ = xtest_focus_window(xctx, win.xid);
                    match handler.action.as_str() {
                        "hotkey" | "shortcut" => {
                            let keys = handler
                                .key
                                .as_deref()
                                .map(|k| parse_shortcut_keys(&json!({ "key": k })))
                                .unwrap_or_default();
                            if !keys.is_empty() {
                                xtest_hotkey(xctx, &keys)?;
                            }
                        }
                        _ => {
                            let key = handler.key.as_deref().unwrap_or("Escape");
                            xtest_press_key(xctx, key)?;
                        }
                    }
                    dismissed.push(json!({
                        "window_id": win.xid,
                        "title": win.title,
                        "action": handler.action,
                        "key": handler.key,
                    }));
                }
            }
            Ok(json!({ "dismissed": dismissed, "count": dismissed.len() }))
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
        "type_totp_from_env" => {
            let env_key = args
                .get("env_key")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("type_totp_from_env requires 'env_key'"))?;
            validate_env_key(env_key)?;
            let env_file = args.get("env_file").and_then(Value::as_str);
            let press_enter = args
                .get("press_enter")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let min_remaining_secs = args
                .get("min_remaining_secs")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_MIN_REMAINING_SECS);
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let outcome = resolve_totp_outcome_from_env(env_key, env_file, min_remaining_secs)?;
            if let Some(wid) = target_window_id {
                let _ = xtest_focus_window(xctx, wid);
            }
            let char_len = type_secret_into_context(xctx, env_key, &outcome.code, press_enter)?;
            let meta = json!({
                "env_key": env_key,
                "length": char_len,
                "digits": outcome.digits,
                "period": outcome.period,
                "waited_boundary": outcome.waited_boundary,
                "waited_ms": outcome.waited_ms,
                "remaining_secs": outcome.remaining_secs,
                "press_enter": press_enter,
            });
            drop(outcome);
            Ok(meta)
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
        "wait_for_os_event" => {
            crate::os_events::ensure_watchers_active();
            let (pid_opt, _) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let pid = if args.get("pid").is_some()
                || args.get("use_target_pid").and_then(Value::as_bool).unwrap_or(false)
            {
                pid_opt
            } else {
                None
            };
            let mut event_kinds = Vec::new();
            if let Some(arr) = args.get("event_kinds").and_then(Value::as_array) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        event_kinds.push(s.to_owned());
                    }
                }
            } else if let Some(s) = args.get("event_kinds").and_then(Value::as_str) {
                event_kinds.push(s.to_owned());
            }
            let role = args.get("role").and_then(Value::as_str).map(str::to_owned);
            let name_regex = args.get("name_regex").and_then(Value::as_str);
            let filter =
                crate::os_events::OsEventFilter::from_params(pid, event_kinds, role, name_regex)?;
            let cursor = args.get("cursor").and_then(Value::as_u64);
            let timeout_ms = args
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(5_000)
                .clamp(50, 60_000);
            let res = run_async_step(crate::os_events::global_os_event_bus().wait_for(
                cursor,
                &filter,
                std::time::Duration::from_millis(timeout_ms),
            ));
            if res.timed_out || !res.matched {
                anyhow::bail!("wait_for_os_event timed out after {}ms", res.elapsed_ms);
            }
            Ok(serde_json::to_value(res)?)
        }
        "atspi_query" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let pid = pid_opt.ok_or_else(|| anyhow::anyhow!("atspi_query requires target 'pid'"))?;
            let xid = wid_opt.unwrap_or(0);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .map(|v| (v as usize).clamp(1, 200))
                .unwrap_or(50);
            let (walked, indices) = query_atspi_nodes(pid, xid, args)?;
            let nodes = atspi_nodes_json(&walked, &indices, limit);
            Ok(json!({
                "artifact": {
                    "kind": "atspi",
                    "pid": pid,
                    "window_id": wid_opt,
                    "count": nodes.len(),
                    "nodes": nodes,
                },
                "pid": pid,
                "window_id": wid_opt,
                "matched_count": indices.len(),
                "nodes": nodes,
            }))
        }
        "atspi_click" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let pid = pid_opt.ok_or_else(|| anyhow::anyhow!("atspi_click requires target 'pid'"))?;
            let xid = wid_opt.unwrap_or(0);
            let focus_policy = cua_driver_core::delivery::FocusPolicy::from_args(args)
                .map_err(|m| anyhow::anyhow!("{m}"))?;
            let match_index = args.get("match_index").and_then(Value::as_u64).unwrap_or(0) as usize;
            let (walked, indices) = query_atspi_nodes(pid, xid, args)?;
            let node_idx = *indices
                .get(match_index)
                .ok_or_else(|| anyhow::anyhow!("atspi_click matched {} node(s), index {match_index} out of range", indices.len()))?;
            let node = &walked.nodes[node_idx];
            let ((action_name, suspected_noop, unacknowledged), _guard) =
                if focus_policy.is_preserve_host() || (xid != 0 && crate::x11::window_is_override_redirect(xid)) {
                    (crate::atspi::perform_action_walked(pid, xid, node)?, None)
                } else {
                    crate::input::focus_guard::guarded(Some(pid), || {
                        crate::atspi::perform_action_walked(pid, xid, node)
                    })?
                };
            Ok(json!({
                "pid": pid,
                "window_id": wid_opt,
                "role": node.role,
                "name": node.name,
                "action": action_name,
                "suspected_noop": suspected_noop,
                "unacknowledged": unacknowledged,
                "focus_policy": focus_policy.as_str(),
            }))
        }
        "atspi_set_value" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let pid = pid_opt.ok_or_else(|| anyhow::anyhow!("atspi_set_value requires target 'pid'"))?;
            let xid = wid_opt.unwrap_or(0);
            let value = args
                .get("value")
                .or_else(|| args.get("text"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("atspi_set_value requires 'value'"))?;
            let match_index = args.get("match_index").and_then(Value::as_u64).unwrap_or(0) as usize;
            let (walked, indices) = query_atspi_nodes(pid, xid, args)?;
            let node_idx = *indices
                .get(match_index)
                .ok_or_else(|| anyhow::anyhow!("atspi_set_value matched {} node(s), index {match_index} out of range", indices.len()))?;
            let node = &walked.nodes[node_idx];
            let obj_ref = node
                .object_ref
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("matched AT-SPI node lacks a live D-Bus object_ref"))?;
            crate::atspi::native::set_value_ref(obj_ref, value)?;
            Ok(json!({
                "pid": pid,
                "window_id": wid_opt,
                "role": node.role,
                "name": node.name,
                "bytes": value.len(),
            }))
        }
        "atspi_match_dialog" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let focus_policy = args
                .get("focus_policy")
                .is_some()
                .then(|| cua_driver_core::delivery::FocusPolicy::from_args(args))
                .transpose()
                .map_err(|m| anyhow::anyhow!("{m}"))?;
            let inline_rule = args
                .get("rule")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| anyhow::anyhow!("invalid inline dialog rule: {e}"))?;
            let req = crate::dialog_matcher::MatchAndActRequest {
                pid: pid_opt,
                window_id: wid_opt,
                display_id: args
                    .get("display_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                rule_id: args
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                inline_rule,
                focus_policy,
                env_key: args
                    .get("env_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                env_file: args
                    .get("env_file")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                verify_disappeared: args.get("verify_disappeared").and_then(Value::as_bool),
                wait_ms: args.get("wait_ms").and_then(Value::as_u64),
                dry_run: args.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
            };
            let outcome = crate::dialog_matcher::match_and_act(req)?;
            Ok(serde_json::to_value(outcome)?)
        }
        "interact_popup" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let focus_policy = if args.get("focus_policy").is_some() {
                cua_driver_core::delivery::FocusPolicy::from_args(args)
                    .map_err(|m| anyhow::anyhow!("{m}"))?
            } else {
                cua_driver_core::delivery::FocusPolicy::PreserveHost
            };
            if args.get("query").is_some()
                || args.get("role").is_some()
                || args.get("name_regex").is_some()
            {
                let pid = pid_opt.ok_or_else(|| anyhow::anyhow!("interact_popup AT-SPI match requires 'pid'"))?;
                let xid = wid_opt.unwrap_or(0);
                let match_index = args.get("match_index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let (walked, indices) = query_atspi_nodes(pid, xid, args)?;
                let node_idx = *indices
                    .get(match_index)
                    .ok_or_else(|| anyhow::anyhow!("interact_popup matched 0 nodes"))?;
                let node = &walked.nodes[node_idx];
                let (action_name, suspected_noop, unacknowledged) = if focus_policy.is_preserve_host() {
                    crate::atspi::perform_action_walked(pid, xid, node)?
                } else {
                    crate::input::focus_guard::guarded(Some(pid), || {
                        crate::atspi::perform_action_walked(pid, xid, node)
                    })?
                    .0
                };
                return Ok(json!({
                    "mode": "atspi",
                    "pid": pid,
                    "window_id": wid_opt,
                    "focus_policy": focus_policy.as_str(),
                    "action": action_name,
                    "suspected_noop": suspected_noop,
                    "unacknowledged": unacknowledged,
                }));
            }
            let xctx = ctx.ok_or_else(|| anyhow::anyhow!("X11 display context unavailable"))?;
            let keys = parse_shortcut_keys(args);
            if !keys.is_empty() {
                if !focus_policy.is_preserve_host() {
                    if let Some(wid) = wid_opt {
                        let _ = xtest_focus_window(xctx, wid);
                    }
                }
                if keys.len() == 1 {
                    xtest_press_key(xctx, &keys[0])?;
                } else {
                    xtest_hotkey(xctx, &keys)?;
                }
                return Ok(json!({
                    "mode": "key",
                    "window_id": wid_opt,
                    "keys": keys,
                    "focus_policy": focus_policy.as_str(),
                }));
            }
            let x = args.get("x").and_then(Value::as_f64);
            let y = args.get("y").and_then(Value::as_f64);
            if let (Some(rx), Some(ry)) = (x, y) {
                let desktop = args.get("coordinate_frame").and_then(Value::as_str) == Some("desktop")
                    || args.get("scope").and_then(Value::as_str) == Some("desktop");
                let (sx, sy) = if !desktop {
                    if let Some(wid) = wid_opt {
                        if let Some(win) = crate::x11::window_info_with_context(xctx, wid) {
                            (win.x as f64 + rx, win.y as f64 + ry)
                        } else {
                            (rx, ry)
                        }
                    } else {
                        (rx, ry)
                    }
                } else {
                    (rx, ry)
                };
                let button = match args.get("button").and_then(Value::as_str) {
                    Some("right") => 3,
                    Some("middle") => 2,
                    _ => 1,
                };
                if !focus_policy.is_preserve_host() {
                    if let Some(wid) = wid_opt {
                        let _ = xtest_focus_window(xctx, wid);
                    }
                }
                xtest_click(xctx, sx.round() as i16, sy.round() as i16, button)?;
                return Ok(json!({
                    "mode": "pointer",
                    "window_id": wid_opt,
                    "screen_x": sx.round() as i32,
                    "screen_y": sy.round() as i32,
                    "button": button,
                    "focus_policy": focus_policy.as_str(),
                }));
            }
            anyhow::bail!("interact_popup requires AT-SPI filter (query/role/name_regex), keys/key, or x/y coordinates")
        }
        "probe_webview_targets" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            let probe_http = args
                .get("probe_http")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let cfg_path = match args.get("config_path").and_then(Value::as_str) {
                Some(raw) => Some(
                    crate::tools::mcp_webview_probe::validate_config_path(raw)
                        .map_err(|msg| anyhow::anyhow!("{msg}"))?,
                ),
                None => None,
            };
            let report = run_async_step(crate::webview_probe::probe_webview_targets(
                pid_opt,
                wid_opt,
                probe_http,
                cfg_path.as_deref(),
            ))?;
            let val = serde_json::to_value(&report)?;
            let mut art = val.clone();
            if let Some(obj) = art.as_object_mut() {
                obj.insert("kind".into(), json!("webview_probe"));
            }
            Ok(json!({
                "artifact": art,
                "report": val,
            }))
        }
        "cdp_call" => {
            let (pid_opt, wid_opt) = resolve_step_pid_window(ctx, target_window_id, target_pid, args);
            run_async_step(execute_cdp_call_async(pid_opt, wid_opt, args, auth_ctx))
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
            "atspi" => {
                let count = art.get("count").and_then(Value::as_u64).unwrap_or(0);
                let pid = art.get("pid").and_then(Value::as_u64);
                parts.push(format!(
                    "[artifact {idx} atspi] pid={pid:?} nodes={count}: {}",
                    truncate_utf8_snippet(&art.to_string(), 1500)
                ));
            }
            "cdp" => {
                let method = art.get("method").and_then(Value::as_str).unwrap_or("targets");
                parts.push(format!(
                    "[artifact {idx} cdp] method={method}: {}",
                    truncate_utf8_snippet(&art.to_string(), 1500)
                ));
            }
            "webview_probe" => {
                let pid = art.get("pid").and_then(Value::as_u64);
                parts.push(format!(
                    "[artifact {idx} webview_probe] pid={pid:?}: {}",
                    truncate_utf8_snippet(&art.to_string(), 1500)
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

        let totp_missing_err = execute_recipe_step(
            None,
            &dummy_recipe,
            None,
            None,
            "type_totp_from_env",
            &json!({}),
        )
        .unwrap_err();
        assert!(totp_missing_err.to_string().contains("env_key"));

        let totp_prefix_err = execute_recipe_step(
            None,
            &dummy_recipe,
            None,
            None,
            "type_totp_from_env",
            &json!({ "env_key": "HOME" }),
        )
        .unwrap_err();
        assert!(totp_prefix_err.to_string().contains("CUA_YCWANG_"));
    }

    #[test]
    fn auth_gate_totp_deserializes_and_executes_without_x11_leaking_code() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env.totp");
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        std::fs::write(&env_path, format!("CUA_YCWANG_TEST_TOTP_SEED={seed}\n")).unwrap();

        let gate_json = json!({
            "kind": "totp",
            "prompt_title": "IBKR 2FA",
            "env_key": "CUA_YCWANG_TEST_TOTP_SEED",
            "env_file": env_path.display().to_string(),
            "press_enter": true,
            "min_remaining_secs": 0
        });
        let gate: AuthGate = serde_json::from_value(gate_json).unwrap();
        let meta = execute_auth_gate(None, None, &gate).unwrap();
        assert_eq!(meta["kind"], "totp");
        assert_eq!(meta["digits"], 6);
        assert_eq!(meta["period"], 30);
        assert_eq!(meta["press_enter"], true);
        assert!(!meta.to_string().contains(seed));
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

    #[test]
    fn acquire_app_data_schema_includes_pid_window_id_and_app_path() {
        let def = AcquireAppDataTool.def();
        let props = def.input_schema["properties"]
            .as_object()
            .expect("properties must be an object");
        for key in [
            "app_id",
            "capability",
            "recipe_path",
            "pid",
            "window_id",
            "app_path",
            "display_id",
            "session",
            "fallback",
            "allow_safety_level",
        ] {
            assert!(props.contains_key(key), "acquire_app_data missing '{key}'");
        }
        assert_eq!(props["pid"]["type"], "integer");
        assert_eq!(props["window_id"]["type"], "integer");
        assert_eq!(props["app_path"]["type"], "string");
    }

    #[test]
    fn tws_curated_recipe_parses_with_auth_only_login_and_safe_modals() {
        let raw = include_str!("../../../../../../../deploy/linux/user/app_recipes/tws.json");
        let recipe: AppRecipe = serde_json::from_str(raw).expect("tws.json must parse as AppRecipe");
        assert_eq!(recipe.app_id, "tws");

        // Verify login_from_env steps are all auth_only, clear existing fields, and use desktop Tab.
        let login = recipe
            .flows
            .get("login_from_env")
            .expect("tws.json must define login_from_env");
        assert!(
            login
                .iter()
                .all(|s| s.safety_level == Some(SafetyLevel::AuthOnly)),
            "every step in login_from_env must be marked auth_only"
        );
        let has_ctrl_a = login
            .iter()
            .filter(|s| s.action == "hotkey" && s.args["keys"] == json!(["ctrl", "a"]))
            .count();
        let has_backspace = login
            .iter()
            .filter(|s| s.action == "press_key" && s.args["key"] == "BackSpace")
            .count();
        assert_eq!(has_ctrl_a, 2, "expected Ctrl+a before both username and password");
        assert_eq!(
            has_backspace, 2,
            "expected BackSpace before both username and password"
        );
        assert!(
            login.iter().any(|s| s.action == "press_key"
                && s.args["key"] == "Tab"
                && s.args["scope"] == "desktop"),
            "login_from_env Tab must use scope=desktop"
        );

        // Verify dismiss_startup_modals never sends a blind Alt+F4 hotkey; Daily Lineup is targeted via modal_handlers.
        let dismiss = recipe
            .flows
            .get("dismiss_startup_modals")
            .expect("tws.json must define dismiss_startup_modals");
        assert!(
            !dismiss
                .iter()
                .any(|s| s.action == "hotkey" || s.action == "shortcut"),
            "dismiss_startup_modals must not send blind Alt+F4 hotkey"
        );
        assert!(dismiss.iter().any(|s| s.action == "dismiss_modals"));
        assert!(
            !dismiss
                .iter()
                .any(|s| s.action == "press_key" && s.args["key"] == "Escape"),
            "dismiss_startup_modals must not send blind Escape (would reject Paper Warning)"
        );
        assert!(dismiss
            .iter()
            .any(|s| s.action == "click_anchor" && s.args["anchor"] == "warning_dismiss"));
        assert!(dismiss
            .iter()
            .any(|s| s.action == "verify_window_count_min"));

        assert!(recipe
            .modal_handlers
            .iter()
            .any(|h| h.pattern.contains("Daily Lineup")
                && h.action == "hotkey"
                && h.key.as_deref() == Some("alt+F4")));
        assert!(recipe.capabilities.contains_key("workspace_health"));
        assert!(recipe.capabilities.contains_key("watchlist_snapshot"));
        assert!(recipe.capabilities.contains_key("portfolio_export"));

        // Verify SafetyLevel gate blocks login_from_env under ReadOnly and allows under AuthOnly.
        assert!(check_safety_gate(
            &recipe,
            Some("login_from_env"),
            login,
            SafetyLevel::ReadOnly,
            SafetyLevel::ReadOnly,
        )
        .is_err());
        assert!(check_safety_gate(
            &recipe,
            Some("login_from_env"),
            login,
            SafetyLevel::ReadOnly,
            SafetyLevel::AuthOnly,
        )
        .is_ok());
    }

    #[test]
    fn google_chrome_curated_recipe_parses_with_hybrid_capabilities_and_safety_policy() {
        let raw =
            include_str!("../../../../../../../deploy/linux/user/app_recipes/google-chrome.json");
        let recipe: AppRecipe =
            serde_json::from_str(raw).expect("google-chrome.json must parse as AppRecipe");
        assert_eq!(recipe.app_id, "google-chrome");
        assert_eq!(recipe.app_version, "seeded");
        assert_eq!(recipe.version_source, cua_driver_core::app_recipe::VersionSource::Dpkg);
        assert_eq!(recipe.fingerprint_sha256, "seeded");
        assert_eq!(recipe.tech_stack.as_deref(), Some("chromium_browser"));
        assert!(!recipe.atspi_blind);
        assert_eq!(
            recipe.recommended_interaction.as_deref(),
            Some("hybrid_cdp_and_os_chrome")
        );
        assert!(!recipe.launch_isolation_hints.is_empty());

        for flow in [
            "verify_browser_ready",
            "dismiss_native_bubbles",
            "paste_from_clipboard",
            "open_incognito_window",
            "toggle_fullscreen",
            "copy_current_url",
        ] {
            assert!(
                recipe.flows.contains_key(flow),
                "google-chrome.json missing flow '{flow}'"
            );
        }
        let copy_url = &recipe.flows["copy_current_url"];
        assert_eq!(
            copy_url.last().map(|s| s.action.as_str()),
            Some("read_clipboard"),
            "copy_current_url must end with read_clipboard"
        );

        for cap in [
            "dom_and_network_cdp",
            "browser_window_health",
            "active_url_clipboard",
            "browser_chrome_roi",
        ] {
            assert!(
                lookup_capability(&recipe, cap).is_ok(),
                "google-chrome.json missing capability '{cap}'"
            );
        }
        assert_eq!(
            lookup_capability(&recipe, "dom_and_network_cdp")
                .unwrap()
                .data_channel,
            DataChannel::Cdp
        );
        assert_eq!(
            lookup_capability(&recipe, "browser_window_health")
                .unwrap()
                .data_channel,
            DataChannel::WindowMeta
        );
        assert_eq!(
            lookup_capability(&recipe, "active_url_clipboard")
                .unwrap()
                .data_channel,
            DataChannel::Clipboard
        );
        assert_eq!(
            lookup_capability(&recipe, "browser_chrome_roi")
                .unwrap()
                .data_channel,
            DataChannel::ScreenshotRoi
        );

        let policy = recipe
            .safety_policy
            .as_ref()
            .expect("google-chrome.json must define safety_policy");
        assert_eq!(policy.default_max_level, SafetyLevel::ReadOnly);
        assert!(policy.blocked_shortcuts.contains(&"ctrl+shift+delete".to_owned()));
        assert!(policy.blocked_shortcuts.contains(&"ctrl+q".to_owned()));
    }

    #[tokio::test]
    async fn google_chrome_run_and_acquire_resolve_recipe_while_generate_remains_exempt() {
        let dir = tempfile::tempdir().unwrap();
        let recipe_path = dir.path().join("google-chrome.json");
        let raw =
            include_str!("../../../../../../../deploy/linux/user/app_recipes/google-chrome.json");
        std::fs::write(&recipe_path, raw).unwrap();

        // GenerateAppRecipeTool must continue blocking browser_exempt targets.
        let gen_res = GenerateAppRecipeTool
            .invoke(json!({
                "app_path": "/opt/google/chrome/chrome",
                "save": false
            }))
            .await;
        assert_eq!(
            gen_res.is_error,
            Some(true),
            "generate_app_recipe must block browser_exempt"
        );

        // RunAppRecipeTool and AcquireAppDataTool proceed past browser_exempt and resolve the recipe.
        let inspection = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some("/opt/google/chrome/chrome".to_owned()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(inspection.channel, "browser_exempt");
        let resolved = resolve_recipe_for_invocation(
            Some(&recipe_path),
            "google-chrome",
            &inspection,
        )
        .expect("run/acquire recipe resolution must succeed for browser_exempt");
        assert_eq!(resolved.app_id, "google-chrome");
        assert!(lookup_capability(&resolved, "browser_window_health").is_ok());

        // Invoking AcquireAppDataTool with explicit recipe_path and unknown capability proves it
        // bypassed browser_exempt and reached capability lookup.
        let acq_res = AcquireAppDataTool
            .invoke(json!({
                "app_id": "google-chrome",
                "capability": "nonexistent_cap",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": "/opt/google/chrome/chrome"
            }))
            .await;
        assert_eq!(acq_res.is_error, Some(true));
        let err_text = serde_json::to_string(&acq_res.content).unwrap();
        assert!(
            err_text.contains("nonexistent_cap"),
            "expected capability lookup error after bypassing browser_exempt, got: {err_text}"
        );

        // Invoking RunAppRecipeTool with explicit recipe_path and unknown flow proves it
        // bypassed browser_exempt and reached flow lookup.
        let run_res = RunAppRecipeTool
            .invoke(json!({
                "app_id": "google-chrome",
                "flow": "nonexistent_flow",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": "/opt/google/chrome/chrome"
            }))
            .await;
        assert_eq!(run_res.is_error, Some(true));
        let run_err = serde_json::to_string(&run_res.content).unwrap();
        assert!(
            run_err.contains("nonexistent_flow"),
            "expected flow lookup error after bypassing browser_exempt, got: {err_text}"
        );

        // Verify P0-2: google-chrome.json must not bind Return to Allow remote debugging?
        // and approve_remote_debugging flow must use approve_remote_debugging_consent.
        assert!(
            !resolved
                .modal_handlers
                .iter()
                .any(|h| h.pattern.contains("Allow remote debugging") && h.key.as_deref() == Some("Return")),
            "google-chrome.json modal_handlers must not send Return to Allow remote debugging? (would hit Cancel)"
        );
        let approve_flow = resolved
            .flows
            .get("approve_remote_debugging")
            .expect("google-chrome.json must define approve_remote_debugging flow");
        assert!(
            approve_flow
                .iter()
                .any(|s| s.action == "approve_remote_debugging_consent"),
            "approve_remote_debugging flow must use approve_remote_debugging_consent"
        );
        assert!(
            !approve_flow.iter().any(|s| s.action == "dismiss_modals"),
            "approve_remote_debugging flow must not use X11 dismiss_modals"
        );
    }

    #[test]
    fn resolve_consent_target_uses_explicit_args_or_fails_closed() {
        let recipe: AppRecipe = serde_json::from_value(json!({
            "schema_version": 1,
            "app_id": "google-chrome",
            "app_version": "1",
            "version_source": "dpkg",
            "fingerprint_sha256": "test",
            "state_machine": { "initial_state": "ready", "states": [], "transitions": [] }
        }))
        .expect("minimal AppRecipe deserializes");
        let (pid, wid) = super::resolve_consent_target(
            None,
            &recipe,
            Some(99),
            Some(42),
            &json!({}),
        )
        .expect("explicit target_pid and target_window_id should resolve");
        assert_eq!(pid, 42);
        assert_eq!(wid, 99);

        let (pid2, wid2) = super::resolve_consent_target(
            None,
            &recipe,
            None,
            None,
            &json!({ "pid": 123, "window_id": 456 }),
        )
        .expect("args pid and window_id should resolve");
        assert_eq!(pid2, 123);
        assert_eq!(wid2, 456);

        let err = super::resolve_consent_target(None, &recipe, None, None, &json!({}))
            .expect_err("missing target without X11 context must fail");
        assert!(err.to_string().contains("pid") || err.to_string().contains("window_id"));
    }

    #[test]
    fn atspi_match_dialog_with_env_key_escalates_safety_level_to_auth_only() {
        let plain_step: RecipeStep = serde_json::from_value(json!({
            "action": "atspi_match_dialog",
            "args": { "rule_id": "generic" }
        }))
        .expect("step");
        assert_eq!(effective_step_safety_level(&plain_step), SafetyLevel::ReadOnly);

        let secret_step: RecipeStep = serde_json::from_value(json!({
            "action": "atspi_match_dialog",
            "args": { "env_key": "CUA_YCWANG_TEST_PIN" }
        }))
        .expect("secret step");
        assert_eq!(effective_step_safety_level(&secret_step), SafetyLevel::AuthOnly);
    }

    #[test]
    fn recipe_step_wait_for_os_event_receives_published_event() {
        let recipe: AppRecipe = serde_json::from_value(json!({
            "schema_version": 1,
            "app_id": "test-app",
            "app_version": "1",
            "version_source": "dpkg",
            "fingerprint_sha256": "test",
            "state_machine": { "initial_state": "ready", "states": [], "transitions": [] }
        }))
        .expect("recipe");

        let cursor = crate::os_events::global_os_event_bus().latest_seq();
        let pid = std::process::id();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            crate::os_events::global_os_event_bus().push(crate::os_events::OsEventDraft {
                source: "atspi".into(),
                kind: "window.activate".into(),
                pid: Some(pid),
                role: Some("frame".into()),
                name: Some("Phase2 Recipe Event".into()),
                ..Default::default()
            });
        });

        let res = super::execute_recipe_step(
            None,
            &recipe,
            None,
            Some(pid),
            "wait_for_os_event",
            &json!({
                "cursor": cursor,
                "pid": pid,
                "event_kinds": ["window.activate"],
                "name_regex": "Phase2 Recipe",
                "timeout_ms": 2000
            }),
        )
        .expect("wait_for_os_event step");
        assert_eq!(res.get("matched").and_then(Value::as_bool), Some(true));
        assert_eq!(
            res.get("event").and_then(|e| e.get("pid")).and_then(Value::as_u64),
            Some(u64::from(pid))
        );
    }

    #[test]
    fn recipe_step_cdp_call_and_fallback_channel_validate_loopback() {
        let recipe: AppRecipe = serde_json::from_value(json!({
            "schema_version": 1,
            "app_id": "test-app",
            "app_version": "1",
            "version_source": "dpkg",
            "fingerprint_sha256": "test",
            "state_machine": { "initial_state": "ready", "states": [], "transitions": [] }
        }))
        .expect("recipe");

        let err = super::execute_recipe_step(
            None,
            &recipe,
            None,
            None,
            "cdp_call",
            &json!({
                "ws_url": "ws://evil.example:9222/devtools/page/1",
                "method": "Runtime.evaluate"
            }),
        )
        .expect_err("non-loopback ws_url must fail");
        assert!(err.to_string().contains("loopback") || err.to_string().contains("127.0.0.1"));

        let inspection = crate::app_inspector::AppFlowInspection {
            channel: "desktop_recipe".into(),
            exempt_reason: None,
            app_id: "test-app".into(),
            app_version: "1".into(),
            version_source: serde_json::from_value(json!("dpkg")).expect("version_source"),
            tech_stack: "electron".into(),
            fingerprint_sha256: "test".into(),
            fp8: "testtest".into(),
            executable_path: None,
            wm_class: None,
            window_title: None,
            verified_shortcuts: Vec::new(),
            menu_topology: Vec::new(),
            interactive_elements_count: 0,
            atspi_blind: false,
            recommended_interaction: "atspi_semantic".into(),
            remediation_hints: Vec::new(),
            launch_isolation_hints: Vec::new(),
            visual_hotspots: Vec::new(),
            discovered_anchors: Vec::new(),
            sample_roles: Vec::new(),
            notes: Vec::new(),
        };
        let spec_atspi: CapabilitySpec =
            serde_json::from_value(json!({ "data_channel": "atspi" })).expect("spec");
        let err_atspi = super::execute_fallback_channel(
            None,
            &recipe,
            &inspection,
            None,
            None,
            DataChannel::Atspi,
            &spec_atspi,
        )
        .expect_err("Atspi channel without pid fails with missing target, not unsupported stub");
        assert!(!err_atspi.to_string().contains("requires a named flow"));
    }

    #[test]
    fn elevated_step_actions_and_cdp_channel_are_blocked_under_read_only_gate() {
        let recipe: AppRecipe = serde_json::from_value(json!({
            "schema_version": 1,
            "app_id": "test-app",
            "app_version": "seeded",
            "version_source": "dpkg",
            "fingerprint_sha256": "seeded",
            "state_machine": { "initial_state": "ready", "states": [], "transitions": [] }
        }))
        .expect("recipe");

        for action in ["cdp_call", "atspi_click", "atspi_set_value", "interact_popup"] {
            assert_eq!(
                super::default_step_safety_level(action),
                SafetyLevel::AuthOnly,
                "{action} default safety level must be AuthOnly"
            );
            // Explicit read_only in JSON must NOT downgrade the action floor.
            let downgraded_step: RecipeStep = serde_json::from_value(json!({
                "action": action,
                "safety_level": "read_only",
                "args": {}
            }))
            .expect("step");
            assert_eq!(
                effective_step_safety_level(&downgraded_step),
                SafetyLevel::AuthOnly,
                "{action} must not downgrade below AuthOnly"
            );
            let blocked = check_safety_gate(
                &recipe,
                Some("test_flow"),
                std::slice::from_ref(&downgraded_step),
                SafetyLevel::ReadOnly,
                SafetyLevel::ReadOnly,
            )
            .expect_err("ReadOnly gate must block elevated action");
            assert_eq!(
                blocked.structured_content.as_ref().unwrap()["code"],
                "safety_gate_blocked"
            );
            assert!(
                check_safety_gate(
                    &recipe,
                    Some("test_flow"),
                    &[downgraded_step],
                    SafetyLevel::ReadOnly,
                    SafetyLevel::AuthOnly,
                )
                .is_ok(),
                "{action} must pass under AuthOnly gate"
            );
        }

        let cdp_spec: CapabilitySpec = serde_json::from_value(json!({
            "data_channel": "cdp",
            "safety_level": "read_only"
        }))
        .expect("cdp spec");
        assert_eq!(
            super::effective_capability_safety_level(&cdp_spec),
            SafetyLevel::AuthOnly
        );
    }

    #[tokio::test]
    async fn run_app_recipe_state_machine_enforces_safety_gate_on_transitions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recipe_path = dir.path().join("sm_cdp.json");
        let recipe = json!({
            "schema_version": 1,
            "app_id": "google-chrome",
            "app_version": "seeded",
            "version_source": "dpkg",
            "fingerprint_sha256": "seeded",
            "safety_policy": {
                "default_max_level": "read_only",
                "blocked_shortcuts": ["ctrl+q"],
                "blocked_flows": []
            },
            "state_machine": {
                "initial_state": "ready",
                "states": [{ "id": "ready" }, { "id": "done" }],
                "transitions": [{
                    "from_state": "ready",
                    "to_state": "done",
                    "action": "cdp_call",
                    "args": {
                        "ws_url": "ws://127.0.0.1:9222/devtools/browser/blocked",
                        "method": "Runtime.evaluate"
                    }
                }]
            }
        });
        std::fs::write(&recipe_path, recipe.to_string()).expect("write recipe");

        let res = RunAppRecipeTool
            .invoke(json!({
                "app_id": "google-chrome",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": "/opt/google/chrome/chrome",
                "allow_safety_level": "read_only"
            }))
            .await;
        assert_eq!(res.is_error, Some(true));
        assert_eq!(
            res.structured_content
                .as_ref()
                .and_then(|v| v.get("code"))
                .and_then(Value::as_str),
            Some("safety_gate_blocked"),
            "state machine transition must be gated: {res:?}"
        );

        let shortcut_recipe_path = dir.path().join("sm_shortcut.json");
        let shortcut_recipe = json!({
            "schema_version": 1,
            "app_id": "google-chrome",
            "app_version": "seeded",
            "version_source": "dpkg",
            "fingerprint_sha256": "seeded",
            "safety_policy": {
                "default_max_level": "read_only",
                "blocked_shortcuts": ["ctrl+q"],
                "blocked_flows": []
            },
            "state_machine": {
                "initial_state": "ready",
                "states": [{ "id": "ready" }, { "id": "done" }],
                "transitions": [{
                    "from_state": "ready",
                    "to_state": "done",
                    "action": "hotkey",
                    "args": { "keys": ["ctrl", "q"] }
                }]
            }
        });
        std::fs::write(&shortcut_recipe_path, shortcut_recipe.to_string()).expect("write recipe");
        let res_shortcut = RunAppRecipeTool
            .invoke(json!({
                "app_id": "google-chrome",
                "recipe_path": shortcut_recipe_path.display().to_string(),
                "app_path": "/opt/google/chrome/chrome",
                "allow_safety_level": "restricted"
            }))
            .await;
        assert_eq!(res_shortcut.is_error, Some(true));
        assert_eq!(
            res_shortcut
                .structured_content
                .as_ref()
                .and_then(|v| v.get("code"))
                .and_then(Value::as_str),
            Some("safety_gate_blocked")
        );
    }

    #[test]
    fn consumer_browser_cdp_policy_enforces_existing_profile_grant_and_method_restrictions() {
        for product in [
            super::BrowserProduct::GoogleChrome,
            super::BrowserProduct::Chromium,
            super::BrowserProduct::MicrosoftEdge,
            super::BrowserProduct::Brave,
            super::BrowserProduct::Vivaldi,
            super::BrowserProduct::Opera,
            super::BrowserProduct::Arc,
        ] {
            let err = super::evaluate_cdp_target_policy(
                4242,
                Some(7),
                product,
                false,
                super::PermissionMode::Standard,
                false,
                None,
            )
            .expect_err("consumer browser without --grant existing-profile must be refused");
            assert!(err.to_string().contains("--grant existing-profile"));

            let bounded_err = super::evaluate_cdp_target_policy(
                4242,
                Some(7),
                product,
                false,
                super::PermissionMode::Bounded,
                false,
                None,
            )
            .expect_err("consumer browser in bounded mode without manifest must be refused");
            assert!(bounded_err.to_string().contains("manifest"));

            let policy = super::evaluate_cdp_target_policy(
                4242,
                Some(7),
                product,
                false,
                super::PermissionMode::Standard,
                true,
                None,
            )
            .expect("consumer browser with --grant existing-profile must succeed");
            assert_eq!(policy, super::CdpMethodPolicy::ExistingProfile);

            let unres = super::evaluate_cdp_target_policy(
                4242,
                Some(7),
                product,
                false,
                super::PermissionMode::Unrestricted,
                false,
                None,
            )
            .expect("consumer browser in unrestricted mode still enforces ExistingProfile policy");
            assert_eq!(unres, super::CdpMethodPolicy::ExistingProfile);
        }

        // Embedded Electron/CEF/JxBrowser targets do not trigger existing_profile gate.
        assert_eq!(
            super::evaluate_cdp_target_policy(
                5555,
                None,
                super::BrowserProduct::Electron,
                true,
                super::PermissionMode::Standard,
                false,
                None,
            )
            .unwrap(),
            super::CdpMethodPolicy::Unrestricted
        );
        assert_eq!(
            super::evaluate_cdp_target_policy(
                5556,
                None,
                super::BrowserProduct::Other,
                false,
                super::PermissionMode::Standard,
                false,
                None,
            )
            .unwrap(),
            super::CdpMethodPolicy::Unrestricted
        );
        assert!(
            super::evaluate_cdp_target_policy(
                5557,
                None,
                super::BrowserProduct::Firefox,
                false,
                super::PermissionMode::Standard,
                true,
                None,
            )
            .is_err()
        );
    }

    fn sha1_digest(data: &[u8]) -> [u8; 20] {
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64) * 8;
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for (i, word) in chunk.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = h;
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                    _ => (b ^ c ^ d, 0xca62_c1d6u32),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        let mut out = [0u8; 20];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    async fn spawn_mock_cdp_ws_server() -> (u16, String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock cdp listener");
        let port = listener.local_addr().expect("local_addr").port();
        let ws_url = format!("ws://127.0.0.1:{port}/devtools/browser/secret-token-xyz");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    loop {
                        let Ok(n) = sock.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&buf);
                    let key = req
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| v.trim())
                        })
                        .unwrap_or("");
                    let accept_raw = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                    let accept = B64.encode(sha1_digest(accept_raw.as_bytes()));
                    let resp = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    loop {
                        let mut hdr = [0u8; 2];
                        if sock.read_exact(&mut hdr).await.is_err() {
                            return;
                        }
                        let opcode = hdr[0] & 0x0f;
                        let masked = (hdr[1] & 0x80) != 0;
                        let mut len = (hdr[1] & 0x7f) as usize;
                        if len == 126 {
                            let mut ext = [0u8; 2];
                            if sock.read_exact(&mut ext).await.is_err() {
                                return;
                            }
                            len = u16::from_be_bytes(ext) as usize;
                        }
                        let mut mask = [0u8; 4];
                        if masked && sock.read_exact(&mut mask).await.is_err() {
                            return;
                        }
                        let mut payload = vec![0u8; len];
                        if sock.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        if masked {
                            for (i, b) in payload.iter_mut().enumerate() {
                                *b ^= mask[i % 4];
                            }
                        }
                        if opcode == 0x8 {
                            return;
                        }
                        if opcode == 0x9 {
                            // Pong
                            let mut pong = vec![0x8a, payload.len() as u8];
                            pong.extend_from_slice(&payload);
                            let _ = sock.write_all(&pong).await;
                            continue;
                        }
                        let Ok(req_val) = serde_json::from_slice::<Value>(&payload) else {
                            continue;
                        };
                        let id = req_val.get("id").cloned().unwrap_or(json!(1));
                        let method = req_val.get("method").and_then(Value::as_str).unwrap_or("");
                        let result = match method {
                            "Target.getTargets" => json!({
                                "targetInfos": [{
                                    "targetId": "page-1",
                                    "type": "page",
                                    "url": "https://example.test",
                                    "title": "Example"
                                }]
                            }),
                            "Target.attachToTarget" => json!({ "sessionId": "sid-1" }),
                            "Runtime.evaluate" => json!({ "result": { "type": "string", "value": "ok" } }),
                            _ => json!({}),
                        };
                        let reply = json!({ "id": id, "result": result }).to_string();
                        let bytes = reply.as_bytes();
                        let mut frame = Vec::with_capacity(4 + bytes.len());
                        frame.push(0x81);
                        if bytes.len() < 126 {
                            frame.push(bytes.len() as u8);
                        } else {
                            frame.push(126);
                            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        }
                        frame.extend_from_slice(bytes);
                        if sock.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, ws_url, handle)
    }

    #[tokio::test]
    async fn cdp_call_and_channel_redact_ws_url_and_enforce_port_ownership() {
        let (port, ws_url, server_task) = spawn_mock_cdp_ws_server().await;

        let res = super::execute_cdp_call_async(
            None,
            None,
            &json!({
                "ws_url": ws_url,
                "method": "Runtime.evaluate",
                "params": { "expression": "'ok'" }
            }),
            None,
        )
        .await
        .expect("cdp_call against owned mock server");

        let serialized = res.to_string();
        assert!(!serialized.contains(&ws_url), "must not leak raw ws_url: {serialized}");
        assert!(
            !serialized.contains("secret-token-xyz"),
            "must not leak raw ws token: {serialized}"
        );
        assert!(!serialized.contains("ws://"), "must not leak ws:// URL: {serialized}");
        assert_eq!(
            res["endpoint"].as_str(),
            Some(format!("cdp-loopback://127.0.0.1:{port}/[redacted]").as_str())
        );
        let summary = format_artifacts_summary(&[res["artifact"].clone()]);
        assert!(!summary.contains("secret-token-xyz"));
        assert!(!summary.contains("ws://"));

        // execute_cdp_channel also redacts ws_url.
        let cdp_spec: CapabilitySpec = serde_json::from_value(json!({
            "data_channel": "cdp",
            "safety_level": "auth_only",
            "artifact_path": ws_url
        }))
        .expect("spec");
        let ch_res = tokio::task::spawn_blocking(move || {
            super::execute_cdp_channel(None, None, &cdp_spec, None)
        })
        .await
        .unwrap()
        .expect("execute_cdp_channel");
        let ch_serialized = ch_res.to_string();
        assert!(!ch_serialized.contains("secret-token-xyz"));
        assert!(!ch_serialized.contains("ws://"));
        assert_eq!(
            ch_res["endpoint"].as_str(),
            Some(format!("cdp-loopback://127.0.0.1:{port}/[redacted]").as_str())
        );

        // System PID 1 (init/systemd) must never be used to bypass process-tree ownership checks.
        let pid1_err = super::execute_cdp_call_async(
            Some(1),
            None,
            &json!({
                "ws_url": ws_url,
                "method": "Runtime.evaluate"
            }),
            None,
        )
        .await
        .expect_err("system pid 1 must be rejected");
        assert!(pid1_err.to_string().contains("system pid"));

        // Passing another unrelated PID that does not own the loopback port must be refused.
        let mut unrelated_child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn unrelated child");
        let mismatch_err = super::execute_cdp_call_async(
            Some(unrelated_child.id()),
            None,
            &json!({
                "ws_url": ws_url,
                "method": "Runtime.evaluate"
            }),
            None,
        )
        .await
        .expect_err("port owned by another process must be rejected");
        let _ = unrelated_child.kill();
        let _ = unrelated_child.wait();
        assert!(
            mismatch_err.to_string().contains("not owned"),
            "unexpected error: {mismatch_err}"
        );

        // Passing an unowned/non-listening port without PID must fail closed.
        let unowned_err = super::execute_cdp_call_async(
            None,
            None,
            &json!({
                "ws_url": "ws://127.0.0.1:1/devtools/browser/unowned-secret",
                "method": "Runtime.evaluate"
            }),
            None,
        )
        .await
        .expect_err("unowned loopback port must fail closed");
        assert!(unowned_err.to_string().contains("verify target process permission"));

        // @ userinfo spoofing is rejected.
        let spoof_err = super::execute_cdp_call_async(
            None,
            None,
            &json!({
                "ws_url": "ws://127.0.0.1:9222@evil.com/devtools/browser/1",
                "method": "Runtime.evaluate"
            }),
            None,
        )
        .await
        .expect_err("@ userinfo spoof must fail");
        assert!(spoof_err.to_string().contains("userinfo"));

        // probe_webview_targets step rejects path traversal config_path.
        let recipe: AppRecipe = serde_json::from_value(json!({
            "schema_version": 1,
            "app_id": "test-app",
            "app_version": "seeded",
            "version_source": "dpkg",
            "fingerprint_sha256": "seeded",
            "state_machine": { "initial_state": "ready", "states": [], "transitions": [] }
        }))
        .expect("recipe");
        let traversal_err = super::execute_recipe_step(
            None,
            &recipe,
            None,
            Some(std::process::id()),
            "probe_webview_targets",
            &json!({ "config_path": "../../etc/passwd" }),
        )
        .expect_err("config_path traversal in recipe step must fail");
        assert!(traversal_err.to_string().contains(".."));

        // Applying CdpMethodPolicy::ExistingProfile on a live connection blocks non-allowlisted methods.
        let restricted_conn = super::CdpConnection::connect(&ws_url).await.unwrap();
        restricted_conn.restrict_to_existing_profile();
        assert!(restricted_conn.call(None, "Target.getTargets", json!({})).await.is_ok());
        assert!(restricted_conn.call(None, "Network.enable", json!({})).await.is_err());
        assert!(restricted_conn.call(None, "Browser.close", json!({})).await.is_err());

        // redact_ws_url strips both full ws_url and secret token path from errors.
        let redacted = super::redacted_loopback_ws_endpoint(&ws_url);
        let sanitized = super::redact_ws_url(
            &format!("CDP connect to {ws_url} failed (/devtools/browser/secret-token-xyz)"),
            &ws_url,
            &redacted,
        );
        assert!(!sanitized.contains("secret-token-xyz"));
        assert!(!sanitized.contains("ws://"));

        server_task.abort();
    }

    #[tokio::test]
    async fn run_app_recipe_auto_upgrades_version_when_existing_flow_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app_bin = dir.path().join("dummy-upgraded-app");
        std::fs::write(&app_bin, b"dummy-binary-v2").expect("write dummy app");

        let inspection = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some(app_bin.display().to_string()),
            ..Default::default()
        })
        .expect("inspect dummy app");

        let old_version = "0.9.0";
        let old_sha = "00000000deadbeef";
        let recipe_path = dir.path().join("dummy_app_v0.9.0_00000000.json");
        let recipe = json!({
            "schema_version": 1,
            "app_id": "dummy_upgrade_ok",
            "app_version": old_version,
            "version_source": "unknown",
            "fingerprint_sha256": old_sha,
            "flows": {
                "ping": [{ "action": "wait_for_stable_frame", "args": { "ms": 1 } }]
            },
            "state_machine": {
                "initial_state": "ready",
                "states": [{ "id": "ready" }, { "id": "done" }],
                "transitions": [{
                    "from_state": "ready",
                    "to_state": "done",
                    "action": "wait_for_stable_frame",
                    "args": { "ms": 1 }
                }]
            }
        });
        std::fs::write(&recipe_path, serde_json::to_string_pretty(&recipe).unwrap())
            .expect("write recipe");

        global_recipe_cache().invalidate("dummy_upgrade_ok", old_version, old_sha);
        global_recipe_cache().invalidate(
            "dummy_upgrade_ok",
            &inspection.app_version,
            &inspection.fingerprint_sha256,
        );

        let res = RunAppRecipeTool
            .invoke(json!({
                "app_id": "dummy_upgrade_ok",
                "flow": "ping",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": app_bin.display().to_string(),
            }))
            .await;
        assert_ne!(res.is_error, Some(true), "expected success, got: {res:?}");
        let structured = res.structured_content.as_ref().expect("structured");
        assert_eq!(structured.get("version_upgraded").and_then(Value::as_bool), Some(true));
        assert_eq!(structured.get("previous_version").and_then(Value::as_str), Some(old_version));
        assert_eq!(
            structured.get("app_version").and_then(Value::as_str),
            Some(inspection.app_version.as_str())
        );
        assert_eq!(
            structured.get("fp8").and_then(Value::as_str),
            Some(inspection.fp8.as_str())
        );

        let text = serde_json::to_string(&res.content).unwrap();
        assert!(text.contains("Auto-upgraded recipe dummy_upgrade_ok"), "text: {text}");

        // Disk JSON must be atomically updated to the live version & fingerprint.
        let disk_recipe = load_recipe(&recipe_path).expect("reload upgraded recipe");
        assert_eq!(disk_recipe.app_version, inspection.app_version);
        assert_eq!(disk_recipe.fingerprint_sha256, inspection.fingerprint_sha256);

        // Hot cache must be refreshed: old key gone, new key present.
        assert!(global_recipe_cache()
            .get("dummy_upgrade_ok", old_version, old_sha)
            .is_none());
        assert!(global_recipe_cache()
            .get(
                "dummy_upgrade_ok",
                &inspection.app_version,
                &inspection.fingerprint_sha256
            )
            .is_some());

        // Subsequent state_machine invocation now matches VersionGate cleanly without upgrade.
        let res2 = RunAppRecipeTool
            .invoke(json!({
                "app_id": "dummy_upgrade_ok",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": app_bin.display().to_string(),
            }))
            .await;
        assert_ne!(res2.is_error, Some(true), "expected state_machine success: {res2:?}");
        let structured2 = res2.structured_content.as_ref().expect("structured2");
        assert!(structured2.get("version_upgraded").is_none());
    }

    #[tokio::test]
    async fn run_app_recipe_preserves_version_and_reports_mismatch_when_flow_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let app_bin = dir.path().join("dummy-failing-app");
        std::fs::write(&app_bin, b"dummy-binary-v2-broken").expect("write dummy app");

        let inspection = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some(app_bin.display().to_string()),
            ..Default::default()
        })
        .expect("inspect dummy app");

        let old_version = "1.2.3";
        let old_sha = "11223344aabbccdd";
        let recipe_path = dir.path().join("dummy_app_v1.2.3_11223344.json");
        let recipe = json!({
            "schema_version": 1,
            "app_id": "dummy_upgrade_fail",
            "app_version": old_version,
            "version_source": "unknown",
            "fingerprint_sha256": old_sha,
            "flows": {
                "broken": [{ "action": "unknown_ui_action", "args": {} }]
            },
            "state_machine": {
                "initial_state": "ready",
                "states": [{ "id": "ready" }, { "id": "done" }],
                "transitions": [{
                    "from_state": "ready",
                    "to_state": "done",
                    "action": "unknown_ui_action",
                    "args": {}
                }]
            }
        });
        std::fs::write(&recipe_path, serde_json::to_string_pretty(&recipe).unwrap())
            .expect("write recipe");

        // Case 1: Named flow fails under version mismatch.
        let res_flow = RunAppRecipeTool
            .invoke(json!({
                "app_id": "dummy_upgrade_fail",
                "flow": "broken",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": app_bin.display().to_string(),
            }))
            .await;
        assert_eq!(res_flow.is_error, Some(true));
        let flow_text = serde_json::to_string(&res_flow.content).unwrap();
        assert!(flow_text.contains(old_version), "missing old version: {flow_text}");
        assert!(
            flow_text.contains(&inspection.app_version),
            "missing live version: {flow_text}"
        );
        assert!(
            flow_text.contains("Recipe was NOT updated"),
            "missing non-update notice: {flow_text}"
        );
        assert_eq!(
            res_flow
                .structured_content
                .as_ref()
                .and_then(|v| v.get("version_upgraded"))
                .and_then(Value::as_bool),
            Some(false)
        );

        let disk_after_flow = load_recipe(&recipe_path).expect("reload recipe");
        assert_eq!(disk_after_flow.app_version, old_version);
        assert_eq!(disk_after_flow.fingerprint_sha256, old_sha);

        // Case 2: State machine fails under version mismatch.
        let res_sm = RunAppRecipeTool
            .invoke(json!({
                "app_id": "dummy_upgrade_fail",
                "recipe_path": recipe_path.display().to_string(),
                "app_path": app_bin.display().to_string(),
            }))
            .await;
        assert_eq!(res_sm.is_error, Some(true));
        let sm_text = serde_json::to_string(&res_sm.content).unwrap();
        assert!(sm_text.contains(old_version), "missing old version: {sm_text}");
        assert!(
            sm_text.contains("Recipe was NOT updated"),
            "missing non-update notice: {sm_text}"
        );
        assert_eq!(
            res_sm
                .structured_content
                .as_ref()
                .and_then(|v| v.get("version_upgraded"))
                .and_then(Value::as_bool),
            Some(false)
        );

        let disk_after_sm = load_recipe(&recipe_path).expect("reload recipe");
        assert_eq!(disk_after_sm.app_version, old_version);
        assert_eq!(disk_after_sm.fingerprint_sha256, old_sha);
    }
}
