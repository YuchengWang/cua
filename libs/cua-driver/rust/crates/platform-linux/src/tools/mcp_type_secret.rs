// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Out-of-band secret & TOTP typing MCP tools:
//! - `type_secret_from_env`
//! - `type_totp_from_env`
//!
//! Resolves `CUA_YCWANG_*` credentials and TOTP seeds/URIs from `.env` files
//! or process environment and types them into a target X11 display without ever
//! returning or logging plaintext secrets or generated OTP codes.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use cua_driver_core::{
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::ArgsExt,
    totp::{TotpConfig, TotpGenerationOutcome, DEFAULT_MIN_REMAINING_SECS},
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};
use crate::x11::virtual_input::{xtest_press_key, xtest_type_text};
use crate::x11::virtual_screen::global_virtual_screen_manager;

pub(crate) const ENV_KEY_PREFIX: &str = "CUA_YCWANG_";

/// Validate that `env_key` strictly starts with `CUA_YCWANG_` and has a non-empty suffix.
pub(crate) fn validate_env_key(env_key: &str) -> anyhow::Result<&str> {
    let trimmed = env_key.trim();
    if trimmed != env_key
        || !trimmed.starts_with(ENV_KEY_PREFIX)
        || trimmed.len() <= ENV_KEY_PREFIX.len()
        || trimmed.contains(char::is_whitespace)
        || trimmed.contains('=')
    {
        anyhow::bail!(
            "env_key must start with '{ENV_KEY_PREFIX}' with a non-empty suffix (got '{env_key}')"
        );
    }
    Ok(trimmed)
}

/// Parse `.env` content and look up `target_key`.
///
/// Rules:
/// - Ignore blank lines and `#` comments.
/// - Strip optional leading `export `.
/// - Split on the first `=` only (`split_once('=')`).
/// - Trim key and strip matching outer single or double quotes from value.
pub(crate) fn parse_env_content_for_key(
    content: &str,
    target_key: &str,
) -> Option<Zeroizing<String>> {
    let mut found: Option<Zeroizing<String>> = None;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((raw_k, raw_v)) = line.split_once('=') else {
            continue;
        };
        if raw_k.trim() != target_key {
            continue;
        }
        let val = raw_v.trim();
        let unquoted = if val.len() >= 2
            && ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
        {
            &val[1..val.len() - 1]
        } else {
            val
        };
        found = Some(Zeroizing::new(unquoted.to_owned()));
    }
    found
}

fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn read_key_from_env_file(path: &Path, key: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
    let content = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read env file {}: {e}", path.display()))?,
    );
    Ok(parse_env_content_for_key(&content, key))
}

/// Resolve `env_key` from explicit `env_file` or the default lookup chain:
/// 1) `CUA_YCWANG_ENV_FILE` if set and exists
/// 2) `./.env` if exists
/// 3) `~/.config/cua-ycwang/.env` if exists
/// 4) `std::env::var(key)` fallback
pub(crate) fn resolve_secret_from_env(
    env_key: &str,
    env_file: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    let key = validate_env_key(env_key)?;

    if let Some(explicit) = env_file.map(str::trim).filter(|s| !s.is_empty()) {
        let path = expand_tilde(explicit);
        if !path.is_file() {
            anyhow::bail!("env_file does not exist: {}", path.display());
        }
        let val = read_key_from_env_file(&path, key)?
            .ok_or_else(|| anyhow::anyhow!("key '{key}' not found in {}", path.display()))?;
        if val.is_empty() {
            anyhow::bail!("key '{key}' is empty in {}", path.display());
        }
        return Ok(val);
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(from_var) = std::env::var("CUA_YCWANG_ENV_FILE") {
        let trimmed = from_var.trim();
        if !trimmed.is_empty() {
            candidates.push(expand_tilde(trimmed));
        }
    }
    candidates.push(PathBuf::from(".env"));
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            candidates.push(PathBuf::from(home).join(".config/cua-ycwang/.env"));
        }
    }

    for path in &candidates {
        if path.is_file() {
            if let Some(val) = read_key_from_env_file(path, key)? {
                if val.is_empty() {
                    anyhow::bail!("key '{key}' is empty in {}", path.display());
                }
                return Ok(val);
            }
        }
    }

    if let Ok(val) = std::env::var(key) {
        let secret = Zeroizing::new(val);
        if secret.is_empty() {
            anyhow::bail!("process env key '{key}' is empty");
        }
        return Ok(secret);
    }

    anyhow::bail!("key '{key}' not found in .env candidates or process environment")
}

/// Type a resolved secret into `ctx` without ever exposing plaintext in errors or logs.
pub(crate) fn type_secret_into_context(
    ctx: &X11ScreenContext,
    env_key: &str,
    secret: &str,
    press_enter: bool,
) -> anyhow::Result<usize> {
    let char_len = secret.chars().count();
    xtest_type_text(ctx, secret).map_err(|_| {
        anyhow::anyhow!(
            "failed to type env secret (key={env_key}, len={char_len}) on {}: X11 key synthesis failed",
            ctx.display_id
        )
    })?;
    if press_enter {
        xtest_press_key(ctx, "Return").map_err(|_| {
            anyhow::anyhow!(
                "typed env secret (key={env_key}, len={char_len}) on {}, but failed to press Return",
                ctx.display_id
            )
        })?;
    }
    Ok(char_len)
}

pub(crate) fn format_typed_secret_summary(
    env_key: &str,
    char_len: usize,
    display_id: &str,
) -> String {
    format!("Typed env secret (key={env_key}, len={char_len}) on {display_id}")
}

/// Resolve a TOTP seed or `otpauth://totp/...` URI from env and generate a code
/// with boundary-wait protection, zeroizing the raw secret immediately after parsing.
pub(crate) fn resolve_totp_outcome_from_env(
    env_key: &str,
    env_file: Option<&str>,
    min_remaining_secs: u64,
) -> anyhow::Result<TotpGenerationOutcome> {
    let raw_secret = resolve_secret_from_env(env_key, env_file)?;
    let config = TotpConfig::from_secret_or_uri(&raw_secret)?;
    drop(raw_secret);
    config.generate_now_with_guard(min_remaining_secs)
}

pub(crate) fn format_typed_totp_summary(
    env_key: &str,
    digits: u32,
    waited_boundary: bool,
    display_id: &str,
) -> String {
    format!(
        "Typed TOTP code (key={env_key}, digits={digits}, waited_boundary={waited_boundary}) on {display_id}"
    )
}

fn resolve_target_display(args: &Value) -> Result<DisplayTarget, ToolResult> {
    if let Some(explicit) = args.opt_str("display_id").filter(|s| !s.trim().is_empty()) {
        return DisplayTarget::from_display_id(Some(&explicit))
            .map_err(|e| ToolResult::error(format!("invalid display_id: {e:#}")));
    }
    let session = args.opt_str("session");
    if let Some(id) = global_virtual_screen_manager().resolve_display_for_session(session.as_deref(), None) {
        return DisplayTarget::from_display_id(Some(&id))
            .map_err(|e| ToolResult::error(format!("invalid display_id: {e:#}")));
    }
    Ok(DisplayTarget::Primary)
}

pub struct TypeSecretFromEnvTool;
static TYPE_SECRET_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for TypeSecretFromEnvTool {
    fn def(&self) -> &ToolDef {
        TYPE_SECRET_DEF.get_or_init(|| ToolDef {
            name: "type_secret_from_env".into(),
            description: "Resolve a CUA_YCWANG_* secret from .env or process env and type it into the target X11 display without exposing plaintext to logs or tool output.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["env_key"],
                "properties": {
                    "env_key": {
                        "type": "string",
                        "description": "Environment variable name (must start with CUA_YCWANG_)."
                    },
                    "env_file": {
                        "type": "string",
                        "description": "Optional path to .env file."
                    },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "press_enter": {
                        "type": "boolean",
                        "description": "Whether to press Return after typing the secret (default false)."
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
        let Some(env_key) = args.opt_str("env_key") else {
            return ToolResult::error("env_key is required");
        };
        if let Err(e) = validate_env_key(&env_key) {
            return ToolResult::error(format!("{e:#}"));
        }
        let env_file = args.opt_str("env_file");
        let press_enter = args.bool_or("press_enter", false);
        let target = match resolve_target_display(&args) {
            Ok(t) => t,
            Err(r) => return r,
        };

        match tokio::task::spawn_blocking(move || -> anyhow::Result<(String, usize)> {
            let secret = resolve_secret_from_env(&env_key, env_file.as_deref())?;
            let ctx = global_screen_pool().get_or_connect(&target)?;
            let _ime_guard = crate::ime::ImeGuard::acquire_for_target(&ctx.target);
            let char_len = type_secret_into_context(&ctx, &env_key, &secret, press_enter)?;
            drop(secret);
            Ok((ctx.display_id.clone(), char_len))
        })
        .await
        {
            Ok(Ok((display_id, char_len))) => {
                let key = args.opt_str("env_key").unwrap_or_default();
                let msg = format_typed_secret_summary(&key, char_len, &display_id);
                ToolResult::text(msg).with_structured(json!({
                    "ok": true,
                    "env_key": key,
                    "length": char_len,
                    "display_id": display_id,
                    "press_enter": press_enter,
                }))
            }
            Ok(Err(e)) => ToolResult::error(format!("type_secret_from_env failed: {e:#}")),
            Err(e) => ToolResult::error(format!("type_secret_from_env panicked: {e}")),
        }
    }
}

pub struct TypeTotpFromEnvTool;
static TYPE_TOTP_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for TypeTotpFromEnvTool {
    fn def(&self) -> &ToolDef {
        TYPE_TOTP_DEF.get_or_init(|| ToolDef {
            name: "type_totp_from_env".into(),
            description: "Resolve a CUA_YCWANG_* TOTP seed or otpauth://totp URI from .env or process env, generate a current RFC 6238 code with boundary-wait protection, and type it into the target X11 display without exposing plaintext secrets or codes.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["env_key"],
                "properties": {
                    "env_key": {
                        "type": "string",
                        "description": "Environment variable name holding Base32 seed or otpauth://totp URI (must start with CUA_YCWANG_)."
                    },
                    "env_file": {
                        "type": "string",
                        "description": "Optional path to .env file."
                    },
                    "display_id": { "type": "string" },
                    "session": cua_driver_core::tool_schema::session_schema(),
                    "press_enter": {
                        "type": "boolean",
                        "description": "Whether to press Return after typing the TOTP code (default false)."
                    },
                    "min_remaining_secs": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Minimum remaining seconds in the current TOTP window before waiting for the next window (default 4)."
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
        let Some(env_key) = args.opt_str("env_key") else {
            return ToolResult::error("env_key is required");
        };
        if let Err(e) = validate_env_key(&env_key) {
            return ToolResult::error(format!("{e:#}"));
        }
        let env_file = args.opt_str("env_file");
        let press_enter = args.bool_or("press_enter", false);
        let min_remaining_secs = args
            .opt_u64("min_remaining_secs")
            .unwrap_or(DEFAULT_MIN_REMAINING_SECS);
        let target = match resolve_target_display(&args) {
            Ok(t) => t,
            Err(r) => return r,
        };

        match tokio::task::spawn_blocking(move || -> anyhow::Result<(String, usize, u32, u64, bool, u64, u64)> {
            let outcome = resolve_totp_outcome_from_env(
                &env_key,
                env_file.as_deref(),
                min_remaining_secs,
            )?;
            let ctx = global_screen_pool().get_or_connect(&target)?;
            let _ime_guard = crate::ime::ImeGuard::acquire_for_target(&ctx.target);
            let char_len = type_secret_into_context(&ctx, &env_key, &outcome.code, press_enter)?;
            let digits = outcome.digits;
            let period = outcome.period;
            let waited_boundary = outcome.waited_boundary;
            let waited_ms = outcome.waited_ms;
            let remaining_secs = outcome.remaining_secs;
            drop(outcome);
            Ok((
                ctx.display_id.clone(),
                char_len,
                digits,
                period,
                waited_boundary,
                waited_ms,
                remaining_secs,
            ))
        })
        .await
        {
            Ok(Ok((display_id, char_len, digits, period, waited_boundary, waited_ms, remaining_secs))) => {
                let key = args.opt_str("env_key").unwrap_or_default();
                let msg = format_typed_totp_summary(&key, digits, waited_boundary, &display_id);
                ToolResult::text(msg).with_structured(json!({
                    "ok": true,
                    "env_key": key,
                    "length": char_len,
                    "digits": digits,
                    "period": period,
                    "waited_boundary": waited_boundary,
                    "waited_ms": waited_ms,
                    "remaining_secs": remaining_secs,
                    "display_id": display_id,
                    "press_enter": press_enter,
                }))
            }
            Ok(Err(e)) => ToolResult::error(format!("type_totp_from_env failed: {e:#}")),
            Err(e) => ToolResult::error(format!("type_totp_from_env panicked: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_guard_rejects_non_cua_ycwang_keys() {
        assert!(validate_env_key("CUA_YCWANG_TOS_LIVE_PASSWORD").is_ok());
        assert!(validate_env_key("CUA_YCWANG_TWS_PAPER_USERNAME").is_ok());

        for bad in [
            "HOME",
            "PATH",
            "AWS_SECRET_ACCESS_KEY",
            "CUA_YCWANG_",
            "cua_ycwang_test",
            " CUA_YCWANG_TEST",
            "CUA_YCWANG_BAD=1",
        ] {
            let err = validate_env_key(bad).unwrap_err();
            assert!(
                err.to_string().contains("CUA_YCWANG_"),
                "expected clear prefix error for '{bad}', got: {err}"
            );
        }
    }

    #[test]
    fn env_parsing_handles_quotes_equals_comments_and_export() {
        let content = r#"
# Comment line
   # Indented comment

export CUA_YCWANG_TOS_LIVE_USERNAME = "alice_trader"
CUA_YCWANG_TOS_LIVE_PASSWORD='p@ss=word#123'
CUA_YCWANG_TWS_PAPER_USERNAME=bob_paper
export CUA_YCWANG_TWS_PAPER_PASSWORD="quoted=with=equals"
CUA_YCWANG_MISMATCH="abc'
"#;

        assert_eq!(
            parse_env_content_for_key(content, "CUA_YCWANG_TOS_LIVE_USERNAME")
                .as_deref()
                .map(String::as_str),
            Some("alice_trader")
        );
        assert_eq!(
            parse_env_content_for_key(content, "CUA_YCWANG_TOS_LIVE_PASSWORD")
                .as_deref()
                .map(String::as_str),
            Some("p@ss=word#123")
        );
        assert_eq!(
            parse_env_content_for_key(content, "CUA_YCWANG_TWS_PAPER_USERNAME")
                .as_deref()
                .map(String::as_str),
            Some("bob_paper")
        );
        assert_eq!(
            parse_env_content_for_key(content, "CUA_YCWANG_TWS_PAPER_PASSWORD")
                .as_deref()
                .map(String::as_str),
            Some("quoted=with=equals")
        );
        // Mismatched quotes are not stripped
        assert_eq!(
            parse_env_content_for_key(content, "CUA_YCWANG_MISMATCH")
                .as_deref()
                .map(String::as_str),
            Some("\"abc'")
        );
        assert!(parse_env_content_for_key(content, "CUA_YCWANG_MISSING").is_none());
    }

    #[test]
    fn resolve_secret_from_explicit_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env.test");
        let secret_val = "Super$ecret=Pass!99";
        std::fs::write(
            &env_path,
            format!("CUA_YCWANG_TWS_LIVE_PASSWORD=\"{secret_val}\"\n"),
        )
        .unwrap();

        let resolved = resolve_secret_from_env(
            "CUA_YCWANG_TWS_LIVE_PASSWORD",
            Some(&env_path.display().to_string()),
        )
        .unwrap();
        assert_eq!(resolved.as_str(), secret_val);
    }

    #[test]
    fn zero_secret_leak_summary_formatting() {
        let secret = "MyUltraSecretPassword123!";
        let summary = format_typed_secret_summary(
            "CUA_YCWANG_TOS_LIVE_PASSWORD",
            secret.chars().count(),
            ":132",
        );
        assert_eq!(
            summary,
            "Typed env secret (key=CUA_YCWANG_TOS_LIVE_PASSWORD, len=25) on :132"
        );
        assert!(!summary.contains(secret));
    }

    #[test]
    fn resolve_totp_from_env_file_and_summary_never_leak_secret_or_code() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env.totp");
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        std::fs::write(&env_path, format!("CUA_YCWANG_TWS_PAPER_TOTP_SECRET={seed}\n")).unwrap();

        let outcome = resolve_totp_outcome_from_env(
            "CUA_YCWANG_TWS_PAPER_TOTP_SECRET",
            Some(&env_path.display().to_string()),
            0,
        )
        .unwrap();
        assert_eq!(outcome.digits, 6);
        assert_eq!(outcome.period, 30);
        assert_eq!(outcome.code.len(), 6);
        assert!(!outcome.waited_boundary);

        let summary = format_typed_totp_summary(
            "CUA_YCWANG_TWS_PAPER_TOTP_SECRET",
            outcome.digits,
            outcome.waited_boundary,
            ":132",
        );
        assert!(!summary.contains(seed));
        assert!(!summary.contains(outcome.code.as_str()));
    }
}
