// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tools for strong-versioned application flow inspection, recipe
//! generation, and deterministic state-machine execution:
//! - `inspect_app_flow`
//! - `generate_app_recipe`
//! - `run_app_recipe`

use std::path::PathBuf;
use std::process::Command;

use async_trait::async_trait;
use cua_driver_core::{
    app_recipe::{
        find_matching_recipe, global_recipe_cache, load_recipe, recipes_dir, save_recipe_to_dir,
        AppRecipe, AuthGate, RecipeState, RecipeTransition, StateMachine, VerifyResult, VersionGate,
    },
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app_inspector::{inspect_app_flow, InspectAppFlowRequest};
use crate::x11::context::{global_screen_pool, DisplayTarget};
use crate::x11::virtual_input::{xtest_click, xtest_hotkey, xtest_press_key, xtest_type_text};
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

            let recipe = AppRecipe {
                schema_version: 1,
                app_id,
                app_version: inspection.app_version,
                version_source: inspection.version_source,
                fingerprint_sha256: inspection.fingerprint_sha256,
                verified_shortcuts: inspection.verified_shortcuts,
                menu_topology: inspection.menu_topology,
                relative_anchors: Vec::new(),
                modal_handlers: Vec::new(),
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
        let recipe_path = args.opt_str("recipe_path").map(PathBuf::from);
        let display_id = resolve_display_id(&args);
        let req = InspectAppFlowRequest {
            pid: args.opt_u64("pid").map(|v| v as u32),
            window_id: args.opt_u64("window_id"),
            app_path: args.opt_str("app_path"),
            display_id: display_id.clone(),
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

            // Resolve recipe: explicit recipe_path -> hot cache -> recipes_dir().
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
                let found = find_matching_recipe(
                    &dir,
                    &app_id,
                    &inspection.app_version,
                    &inspection.fingerprint_sha256,
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

            // Mandatory VersionGate verification.
            let verify = VersionGate::verify(
                &recipe,
                &inspection.app_version,
                &inspection.fingerprint_sha256,
            );
            if let VerifyResult::VersionMismatch { ref reason, .. } = verify {
                return Ok(ToolResult::error(reason.clone())
                    .with_structured(serde_json::to_value(&verify)?));
            }

            let target = DisplayTarget::from_display_id(display_id.as_deref())?;
            let ctx = global_screen_pool().get_or_connect(&target).ok();

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
                    std::thread::sleep(std::time::Duration::from_millis(ms.min(2_000)));
                }
                if let Some(ref xctx) = ctx {
                    execute_recipe_action(xctx, &tx.action, &tx.args)?;
                }
                executed_steps.push(json!({
                    "from": tx.from_state,
                    "to": tx.to_state,
                    "action": tx.action,
                    "ok": true,
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

fn execute_recipe_action(
    ctx: &crate::x11::context::X11ScreenContext,
    action: &str,
    args: &Value,
) -> anyhow::Result<()> {
    match action {
        "press_key" => {
            if let Some(key) = args.get("key").and_then(Value::as_str) {
                xtest_press_key(ctx, key)?;
            }
        }
        "hotkey" => {
            if let Some(arr) = args.get("keys").and_then(Value::as_array) {
                let keys: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect();
                xtest_hotkey(ctx, &keys)?;
            }
        }
        "click" => {
            let x = args.get("x").and_then(Value::as_f64).unwrap_or(0.0).round() as i16;
            let y = args.get("y").and_then(Value::as_f64).unwrap_or(0.0).round() as i16;
            xtest_click(ctx, x, y, 1)?;
        }
        "type_text" => {
            if let Some(text) = args.get("text").and_then(Value::as_str) {
                xtest_type_text(ctx, text)?;
            }
        }
        _ => {}
    }
    Ok(())
}
