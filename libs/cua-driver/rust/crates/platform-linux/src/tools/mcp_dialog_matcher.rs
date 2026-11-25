// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tool `match_and_act_dialog` backed by `~/.config/cua-ycwang/dialog_rules.json`.

use std::sync::OnceLock;

use async_trait::async_trait;
use cua_driver_core::{
    delivery::FocusPolicy,
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
};
use serde_json::{json, Value};

use crate::dialog_matcher::{match_and_act, DialogRule, MatchAndActRequest};
use crate::x11::virtual_screen::global_virtual_screen_manager;

pub struct MatchAndActDialogTool;
static MATCH_DIALOG_DEF: OnceLock<ToolDef> = OnceLock::new();

#[async_trait]
impl Tool for MatchAndActDialogTool {
    fn def(&self) -> &ToolDef {
        MATCH_DIALOG_DEF.get_or_init(|| ToolDef {
            name: "match_and_act_dialog".into(),
            description: "Match a native desktop/browser dialog against ~/.config/cua-ycwang/dialog_rules.json (hot-reloaded) or an inline rule (WM_CLASS, root_roles, heading_regex, body_regex, button_name_regex, exclude_names, expected_button_count, target_button_index, focus_policy, env_key, verify_disappeared) and execute the configured action.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "pid": {
                        "type": "integer",
                        "description": "Optional target process ID. Omit to scan windows matching the dialog rule."
                    },
                    "window_id": {
                        "type": "integer",
                        "description": "Optional target window ID from list_windows."
                    },
                    "display_id": {
                        "type": "string",
                        "description": "Optional target X11 display id (e.g. ':1')."
                    },
                    "rule_id": {
                        "type": "string",
                        "description": "Optional rule id inside dialog_rules.json to restrict matching."
                    },
                    "rule": {
                        "type": "object",
                        "description": "Optional inline DialogRule object overriding dialog_rules.json."
                    },
                    "focus_policy": cua_driver_core::tool_schema::focus_policy_schema(),
                    "env_key": {
                        "type": "string",
                        "description": "Optional CUA_YCWANG_* secret env key to inject into the dialog's input before acting."
                    },
                    "env_file": {
                        "type": "string",
                        "description": "Optional .env file path for resolving env_key."
                    },
                    "verify_disappeared": {
                        "type": "boolean",
                        "description": "Override whether to verify the dialog closes after acting (default true)."
                    },
                    "wait_ms": {
                        "type": "integer",
                        "minimum": 100,
                        "maximum": 30_000,
                        "default": 5000,
                        "description": "Maximum wait/poll budget in milliseconds (default 5000, range 100..=30000)."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, match and report dialog/button details without clicking or typing."
                    }
                },
                "additionalProperties": false
            }),
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: true,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let pid = match args.get("pid") {
            None | Some(Value::Null) => None,
            Some(_) => match args.require_u32("pid") {
                Ok(v) => Some(v),
                Err(e) => return e,
            },
        };
        let window_id = args.opt_u64("window_id");
        let focus_policy = match args.get("focus_policy") {
            None | Some(Value::Null) => None,
            Some(_) => match FocusPolicy::from_args(&args) {
                Ok(fp) => Some(fp),
                Err(msg) => {
                    return ToolResult::error(msg)
                        .with_structured(json!({ "code": "invalid_arguments" }))
                }
            },
        };
        let inline_rule = match args.get("rule") {
            None | Some(Value::Null) => None,
            Some(val) => match serde_json::from_value::<DialogRule>(val.clone()) {
                Ok(rule) => Some(rule),
                Err(e) => {
                    return ToolResult::error(format!("invalid inline dialog rule: {e}"))
                        .with_structured(json!({ "code": "invalid_arguments" }))
                }
            },
        };
        let session = args.opt_str("session");
        let explicit_display = args.opt_str("display_id");
        let display_id = global_virtual_screen_manager()
            .resolve_display_for_session(session.as_deref(), explicit_display.as_deref());

        let req = MatchAndActRequest {
            pid,
            window_id,
            display_id,
            rule_id: args.opt_str("rule_id"),
            inline_rule,
            focus_policy,
            env_key: args.opt_str("env_key"),
            env_file: args.opt_str("env_file"),
            verify_disappeared: args.get("verify_disappeared").and_then(Value::as_bool),
            wait_ms: args.opt_u64("wait_ms"),
            dry_run: args.bool_or("dry_run", false),
        };

        match tokio::task::spawn_blocking(move || match_and_act(req)).await {
            Ok(Ok(outcome)) => {
                let text = if !outcome.matched {
                    format!(
                        "No dialog matched within {}ms (rule_id={:?}).",
                        outcome.elapsed_ms, outcome.rule_id
                    )
                } else if !outcome.acted {
                    format!(
                        "Matched dialog rule '{}' on pid={:?} window_id={:?} (dry_run=true, button={:?}).",
                        outcome.rule_id.as_deref().unwrap_or(""),
                        outcome.pid,
                        outcome.window_id,
                        outcome.target_button_name
                    )
                } else {
                    format!(
                        "Acted on dialog rule '{}' (pid={:?}, window_id={:?}, button={:?}, focus_policy={}, verified_disappeared={}).",
                        outcome.rule_id.as_deref().unwrap_or(""),
                        outcome.pid,
                        outcome.window_id,
                        outcome.target_button_name,
                        outcome.focus_policy,
                        outcome.verified_disappeared
                    )
                };
                ToolResult::text(text).with_structured(json!(outcome))
            }
            Ok(Err(e)) => ToolResult::error(format!("match_and_act_dialog failed: {e:#}")),
            Err(e) => ToolResult::error(format!("match_and_act_dialog panicked: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_driver_core::tool_schema::shared_schema_violations;

    #[test]
    fn match_and_act_dialog_passes_shared_schema_gate() {
        let def = MatchAndActDialogTool.def();
        let violations = shared_schema_violations(&def.name, &def.input_schema);
        assert!(violations.is_empty(), "{violations:?}");
    }
}
