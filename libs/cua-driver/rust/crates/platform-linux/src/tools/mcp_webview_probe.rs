// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! MCP tool `probe_webview_targets`: probes Electron, CEF, JxBrowser,
//! QtWebEngine, WebKitGTK, and `webview_probes.json` rules for live debug
//! targets (`/proc/<pid>/fd`, `/proc/net/tcp`, `/proc/net/unix`, `/json/version`).

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use cua_driver_core::protocol::ToolResult;
use cua_driver_core::tool::{Tool, ToolDef};
use serde_json::{json, Value};

static PROBE_WEBVIEW_DEF: OnceLock<ToolDef> = OnceLock::new();

fn resolve_canonical_or_ancestor(path: &Path) -> Result<PathBuf, String> {
    let mut existing = Some(path);
    let mut suffix = Vec::new();
    while let Some(cur) = existing {
        if cur.exists() {
            let canon = std::fs::canonicalize(cur)
                .map_err(|e| format!("failed to canonicalize {}: {e}", cur.display()))?;
            let mut out = canon;
            for part in suffix.into_iter().rev() {
                out.push(part);
            }
            return Ok(out);
        }
        if let Some(name) = cur.file_name() {
            suffix.push(name.to_os_string());
            existing = cur.parent();
        } else {
            break;
        }
    }
    Err(format!("cannot resolve path {}", path.display()))
}

pub(crate) fn validate_config_path_within(
    raw: &str,
    allowed_dir: &Path,
) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("config_path must not be empty".to_owned());
    }
    if trimmed.contains('\0') {
        return Err("config_path must not contain NUL bytes".to_owned());
    }
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "HOME is unavailable to expand '~/' in config_path".to_owned())?;
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(trimmed)
    };
    if expanded
        .components()
        .any(|comp| matches!(comp, Component::ParentDir))
    {
        return Err("config_path must not contain '..' path traversal".to_owned());
    }
    let candidate = if expanded.is_relative() {
        allowed_dir.join(&expanded)
    } else {
        expanded
    };
    let canonical_base = resolve_canonical_or_ancestor(allowed_dir)?;
    let canonical_target = resolve_canonical_or_ancestor(&candidate)?;
    if !canonical_target.starts_with(&canonical_base) || canonical_target == canonical_base {
        return Err(format!(
            "config_path must stay inside {}",
            allowed_dir.display()
        ));
    }
    Ok(canonical_target)
}

pub(crate) fn validate_config_path(raw: &str) -> Result<PathBuf, String> {
    let allowed_dir = cua_driver_core::ycwang_env::config_dir()
        .ok_or_else(|| "cannot resolve cua-ycwang config directory".to_owned())?;
    validate_config_path_within(raw, &allowed_dir)
}

pub struct ProbeWebviewTargetsTool;

#[async_trait::async_trait]
impl Tool for ProbeWebviewTargetsTool {
    fn def(&self) -> &ToolDef {
        PROBE_WEBVIEW_DEF.get_or_init(|| ToolDef {
            name: "probe_webview_targets".into(),
            description: "Probe a process (Electron, CEF, JxBrowser/TWS, QtWebEngine, WebKitGTK, or rules in ~/.config/cua-ycwang/webview_probes.json) for loopback CDP ports, Inspector Unix sockets, and /json/version targets.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "pid": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target application PID whose descendant process tree and open sockets should be probed."
                    },
                    "window_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional X11 window_id used to resolve _NET_WM_PID when pid is omitted."
                    },
                    "probe_http": {
                        "type": "boolean",
                        "default": true,
                        "description": "When true (default), probe discovered loopback TCP ports via HTTP /json/version and /json/list."
                    },
                    "config_path": {
                        "type": "string",
                        "description": "Optional override path to webview_probes.json (defaults to ~/.config/cua-ycwang/webview_probes.json)."
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
        let pid = args.get("pid").and_then(Value::as_u64).map(|v| v as u32);
        let window_id = args.get("window_id").and_then(Value::as_u64);
        if pid.is_none() && window_id.is_none() {
            return ToolResult::error(
                "probe_webview_targets: provide at least one of 'pid' or 'window_id'.",
            )
            .with_structured(json!({ "code": "invalid_arguments" }));
        }
        let probe_http = args
            .get("probe_http")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let config_path = match args.get("config_path").and_then(Value::as_str) {
            Some(raw) => match validate_config_path(raw) {
                Ok(validated) => Some(validated),
                Err(msg) => {
                    return ToolResult::error(format!("probe_webview_targets: {msg}"))
                        .with_structured(json!({ "code": "invalid_arguments" }));
                }
            },
            None => None,
        };

        match crate::webview_probe::probe_webview_targets(
            pid,
            window_id,
            probe_http,
            config_path.as_deref(),
        )
        .await
        {
            Ok(report) => {
                let engines: Vec<&str> = report
                    .matched_engines
                    .iter()
                    .map(|m| m.engine.as_str())
                    .collect();
                let verified_ports: Vec<u16> = report
                    .endpoints
                    .iter()
                    .filter(|e| e.cdp_verified)
                    .map(|e| e.port)
                    .collect();
                let summary = format!(
                    "Probed pid {} ({} process(es)): engines={:?}, listening_ports={:?}, verified_cdp_ports={:?}, unix_sockets={}.",
                    report.pid,
                    report.process_count,
                    engines,
                    report.listening_ports,
                    verified_ports,
                    report.unix_sockets.len(),
                );
                let structured = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
                ToolResult::text(summary).with_structured(structured)
            }
            Err(err) => ToolResult::error(format!("probe_webview_targets failed: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeWebviewTargetsTool;
    use cua_driver_core::tool::Tool;

    #[tokio::test]
    async fn schema_and_missing_target_validation() {
        let tool = ProbeWebviewTargetsTool;
        let def = tool.def();
        assert_eq!(def.name, "probe_webview_targets");
        assert!(def.read_only);
        let props = def
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("properties");
        for k in ["session", "pid", "window_id", "probe_http", "config_path"] {
            assert!(props.contains_key(k), "missing property {k}");
        }

        let err = tool.invoke(serde_json::json!({})).await;
        assert_eq!(err.is_error, Some(true));
        assert_eq!(
            err.structured_content
                .as_ref()
                .and_then(|s| s.get("code"))
                .and_then(|v| v.as_str()),
            Some("invalid_arguments")
        );

        for bad_path in ["../etc/passwd", "/etc/passwd", "/tmp/../etc/passwd", ""] {
            let bad = tool
                .invoke(serde_json::json!({
                    "pid": std::process::id(),
                    "config_path": bad_path
                }))
                .await;
            assert_eq!(bad.is_error, Some(true), "expected rejection for {bad_path:?}");
            assert_eq!(
                bad.structured_content
                    .as_ref()
                    .and_then(|s| s.get("code"))
                    .and_then(|v| v.as_str()),
                Some("invalid_arguments"),
                "for {bad_path:?}"
            );
        }
    }

    #[test]
    fn validate_config_path_within_blocks_traversal_outside_and_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let allowed = root.path().join("cfg");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("secret.json");
        std::fs::write(&outside_file, "{}").unwrap();
        let inside_file = allowed.join("webview_probes.json");
        std::fs::write(&inside_file, "{}").unwrap();

        let ok_abs = super::validate_config_path_within(
            inside_file.to_str().unwrap(),
            &allowed,
        )
        .expect("inside absolute path must succeed");
        assert_eq!(ok_abs, std::fs::canonicalize(&inside_file).unwrap());

        let ok_rel = super::validate_config_path_within("webview_probes.json", &allowed)
            .expect("relative filename inside allowed dir must succeed");
        assert_eq!(ok_rel, std::fs::canonicalize(&inside_file).unwrap());

        let ok_new = super::validate_config_path_within("sub/new_probes.json", &allowed)
            .expect("non-existent path inside allowed dir must succeed");
        assert!(ok_new.starts_with(std::fs::canonicalize(&allowed).unwrap()));

        for bad in [
            "",
            "   ",
            "../outside/secret.json",
            "sub/../../outside/secret.json",
            outside_file.to_str().unwrap(),
            "/etc/passwd",
            allowed.to_str().unwrap(),
        ] {
            assert!(
                super::validate_config_path_within(bad, &allowed).is_err(),
                "must reject {bad:?}"
            );
        }

        #[cfg(unix)]
        {
            let link = allowed.join("escape.json");
            std::os::unix::fs::symlink(&outside_file, &link).unwrap();
            assert!(
                super::validate_config_path_within(link.to_str().unwrap(), &allowed).is_err(),
                "must reject symlink escaping allowed config dir"
            );
        }
    }
}
