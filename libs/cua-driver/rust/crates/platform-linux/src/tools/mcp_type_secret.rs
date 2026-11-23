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

/// Build the ordered `.env` candidate list from environment values.
pub(crate) fn default_env_file_candidates_from(
    explicit_env_file_var: Option<&str>,
    config_dir_var: Option<&str>,
    home_var: Option<&str>,
) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(from_var) = explicit_env_file_var.map(str::trim).filter(|s| !s.is_empty()) {
        candidates.push(expand_tilde(from_var));
    }
    candidates.push(PathBuf::from(".env"));
    if let Some(config_dir) = config_dir_var.map(str::trim).filter(|s| !s.is_empty()) {
        let base = expand_tilde(config_dir);
        candidates.push(base.join("env/secrets.env"));
        candidates.push(base.join(".env"));
    }
    if let Some(home) = home_var.map(str::trim).filter(|s| !s.is_empty()) {
        let base = PathBuf::from(home).join(".config/cua-ycwang");
        let secrets = base.join("env/secrets.env");
        if !candidates.contains(&secrets) {
            candidates.push(secrets);
        }
        let dotenv = base.join(".env");
        if !candidates.contains(&dotenv) {
            candidates.push(dotenv);
        }
    }
    candidates
}

/// Resolve `env_key` from explicit `env_file` or the default lookup chain:
/// 1) `CUA_YCWANG_ENV_FILE` if set and exists
/// 2) `./.env` if exists
/// 3) `$CUA_YCWANG_CONFIG_DIR/env/secrets.env` and `$CUA_YCWANG_CONFIG_DIR/.env` if set and exist
/// 4) `~/.config/cua-ycwang/env/secrets.env` and `~/.config/cua-ycwang/.env` if exist
/// 5) `std::env::var(key)` fallback
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

    let explicit_env_file_var = std::env::var("CUA_YCWANG_ENV_FILE").ok();
    let config_dir_var = std::env::var("CUA_YCWANG_CONFIG_DIR").ok();
    let home_var = std::env::var("HOME").ok();
    let candidates = default_env_file_candidates_from(
        explicit_env_file_var.as_deref(),
        config_dir_var.as_deref(),
        home_var.as_deref(),
    );

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
            description: "Resolve a CUA_YCWANG_* secret (e.g. CUA_YCWANG_SUDO_PASS for sudo prompts) from .env, $CUA_YCWANG_CONFIG_DIR/env/secrets.env, ~/.config/cua-ycwang/env/secrets.env, or process env and type it into the target X11 display without exposing plaintext to logs or tool output.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["env_key"],
                "properties": {
                    "env_key": {
                        "type": "string",
                        "description": "Environment variable name (must start with CUA_YCWANG_, e.g. CUA_YCWANG_SUDO_PASS)."
                    },
                    "env_file": {
                        "type": "string",
                        "description": "Optional path to .env file. When omitted, automatically searches CUA_YCWANG_ENV_FILE, ./.env, $CUA_YCWANG_CONFIG_DIR/env/secrets.env, and ~/.config/cua-ycwang/env/secrets.env."
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

pub(crate) const DEFAULT_SUDO_ENV_KEY: &str = "CUA_YCWANG_SUDO_PASS";

/// Strip a leading `sudo ` prefix if the caller already included it.
pub(crate) fn normalize_sudo_command(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    let cmd = trimmed
        .strip_prefix("sudo")
        .filter(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        .map(str::trim_start)
        .unwrap_or(trimmed);
    if cmd.is_empty() {
        anyhow::bail!("command must not be empty");
    }
    if cmd.contains('\0') {
        anyhow::bail!("command must not contain NUL bytes");
    }
    Ok(cmd.to_owned())
}

fn shell_single_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

fn truncate_chars(raw: &str, max_chars: usize) -> String {
    let mut chars = raw.chars();
    let collected: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{collected}...")
    } else {
        collected
    }
}

/// Build a self-cleaning bash script that transparently displays the exact `sudo`
/// command, prompts with `sudo -p` showing the command, and optionally keeps the
/// terminal open so the user can inspect the command output.
pub(crate) fn build_sudo_terminal_script(
    command: &str,
    self_script_path: &Path,
    keep_open: bool,
) -> String {
    let q_self = shell_single_quote(&self_script_path.display().to_string());
    let q_cmd = shell_single_quote(command);
    let short_cmd = truncate_chars(&command.replace(['\r', '\n'], " "), 60).replace('%', "%%");
    let prompt_text = format!("[sudo] 即将执行: {short_cmd} | 请输入 %u 的密码: ");
    let q_prompt = shell_single_quote(&prompt_text);

    let mut script = format!(
        "#!/usr/bin/env bash\n\
         rm -f -- {q_self}\n\
         clear\n\
         printf '========================================\\n'\n\
         printf '[cua-ycwang] 即将以 sudo 执行命令:\\n'\n\
         printf '  sudo %s\\n' {q_cmd}\n\
         printf '========================================\\n\\n'\n\
         sudo -k -p {q_prompt} -- bash -c {q_cmd}\n\
         rc=$?\n\
         printf '\\n----------------------------------------\\n'\n\
         printf '[cua-ycwang] 命令执行完成 (exit code: %d)\\n' \"$rc\"\n"
    );
    if keep_open {
        script.push_str(
            "printf '按 Enter 关闭此终端窗口...\\n'\n\
             read -r _\n",
        );
    }
    script
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SudoRiskAssessment {
    pub needs_confirmation: bool,
    pub risk_level: &'static str,
    pub reasons: Vec<&'static str>,
}

fn push_unique_reason(reasons: &mut Vec<&'static str>, reason: &'static str) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn split_shell_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            cur.push(ch);
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            cur.push(ch);
            continue;
        }
        if !in_single && !in_double {
            if ch == ';' || ch == '\n' {
                if !cur.trim().is_empty() {
                    segments.push(cur.trim().to_owned());
                }
                cur.clear();
                continue;
            }
            if ch == '&' {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    if !cur.trim().is_empty() {
                        segments.push(cur.trim().to_owned());
                    }
                    cur.clear();
                    continue;
                }
            }
            if ch == '|' {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                if !cur.trim().is_empty() {
                    segments.push(cur.trim().to_owned());
                }
                cur.clear();
                continue;
            }
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        segments.push(cur.trim().to_owned());
    }
    segments
}

fn command_basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

fn is_readonly_segment(tokens: &[&str]) -> bool {
    let Some(first) = tokens.first() else {
        return true;
    };
    let bin = command_basename(first);
    match bin {
        "id" | "whoami" | "uname" | "hostname" | "pwd" | "date" | "uptime" | "free" | "df"
        | "du" | "ls" | "ll" | "stat" | "file" | "cat" | "head" | "tail" | "wc" | "grep"
        | "egrep" | "fgrep" | "rg" | "ps" | "pgrep" | "ss" | "ip" | "ifconfig" | "lsblk"
        | "blkid" | "lscpu" | "lsusb" | "lspci" | "wpctl" | "pactl" | "amixer" | "journalctl"
        | "dmesg" => true,
        "systemctl" => matches!(
            tokens.get(1).copied(),
            Some("status" | "is-active" | "is-enabled" | "list-units" | "list-unit-files")
        ),
        "dpkg" => matches!(tokens.get(1).copied(), Some("-l" | "-L" | "-s" | "--list")),
        "apt" | "apt-cache" => matches!(
            tokens.get(1).copied(),
            Some("list" | "show" | "policy" | "search" | "depends")
        ),
        _ => false,
    }
}

/// Classify a `sudo` command into `safe` (read-only allowlist), `destructive`,
/// or `needs_review` (fail-closed default for unknown/compound commands).
pub(crate) fn assess_sudo_command_risk(command: &str) -> SudoRiskAssessment {
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut all_segments_readonly = true;

    if command.contains('>') || command.contains("$(") || command.contains('`') {
        push_unique_reason(&mut reasons, "包含输出重定向或命令替换");
        all_segments_readonly = false;
    }

    let segments = split_shell_segments(command);
    if segments.is_empty() {
        return SudoRiskAssessment {
            needs_confirmation: true,
            risk_level: "needs_review",
            reasons: vec!["空命令或无法解析"],
        };
    }

    for seg in &segments {
        let tokens: Vec<&str> = seg.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let mut idx = 0;
        while idx < tokens.len() && tokens[idx] == "sudo" {
            idx += 1;
        }
        let cmd_tokens = &tokens[idx..];
        let Some(first) = cmd_tokens.first() else {
            all_segments_readonly = false;
            continue;
        };
        let bin = command_basename(first);
        let rest = &cmd_tokens[1..];

        let mut seg_destructive = false;
        if matches!(bin, "rm" | "rmdir" | "shred" | "unlink" | "truncate" | "mv" | "dd" | "tee") {
            push_unique_reason(&mut reasons, "文件删除、移动或覆写");
            seg_destructive = true;
        } else if bin == "cp" && rest.iter().any(|a| *a == "-f" || *a == "--force") {
            push_unique_reason(&mut reasons, "强制覆盖复制文件");
            seg_destructive = true;
        } else if bin == "rsync" && rest.iter().any(|a| a.starts_with("--delete")) {
            push_unique_reason(&mut reasons, "rsync 同步删除目标文件");
            seg_destructive = true;
        } else if bin == "find"
            && rest
                .iter()
                .any(|a| matches!(*a, "-delete" | "-exec" | "-execdir" | "-ok"))
        {
            push_unique_reason(&mut reasons, "find 批量删除或执行动作");
            seg_destructive = true;
        } else if bin == "sed" && rest.iter().any(|a| *a == "-i" || a.starts_with("-i")) {
            push_unique_reason(&mut reasons, "sed 原地修改文件内容");
            seg_destructive = true;
        } else if matches!(bin, "apt" | "apt-get" | "aptitude")
            && rest.iter().any(|a| {
                matches!(
                    *a,
                    "remove" | "purge" | "autoremove" | "install" | "upgrade" | "dist-upgrade" | "full-upgrade"
                )
            })
        {
            push_unique_reason(&mut reasons, "软件包安装/卸载/升级");
            seg_destructive = true;
        } else if bin == "dpkg"
            && rest.iter().any(|a| {
                matches!(
                    *a,
                    "-r" | "--remove" | "-P" | "--purge" | "-i" | "--install"
                )
            })
        {
            push_unique_reason(&mut reasons, "dpkg 软件包安装或卸载");
            seg_destructive = true;
        } else if matches!(bin, "snap" | "flatpak")
            && rest
                .iter()
                .any(|a| matches!(*a, "remove" | "uninstall" | "install"))
        {
            push_unique_reason(&mut reasons, "软件包安装或卸载");
            seg_destructive = true;
        } else if matches!(bin, "systemctl" | "service")
            && rest
                .iter()
                .any(|a| matches!(*a, "stop" | "disable" | "mask" | "restart" | "reload" | "enable"))
        {
            push_unique_reason(&mut reasons, "系统服务启停或配置变更");
            seg_destructive = true;
        } else if matches!(bin, "reboot" | "shutdown" | "poweroff" | "halt") {
            push_unique_reason(&mut reasons, "系统关机或重启");
            seg_destructive = true;
        } else if matches!(bin, "chmod" | "chown" | "chgrp" | "chattr") {
            push_unique_reason(&mut reasons, "文件权限或所有权修改");
            seg_destructive = true;
        } else if bin.starts_with("mkfs")
            || matches!(
                bin,
                "fdisk" | "parted" | "gdisk" | "sfdisk" | "wipefs" | "mount" | "umount" | "lvremove"
                    | "vgremove" | "pvremove"
            )
        {
            push_unique_reason(&mut reasons, "磁盘、分区或挂载变更");
            seg_destructive = true;
        } else if matches!(
            bin,
            "userdel" | "usermod" | "useradd" | "passwd" | "visudo" | "ufw" | "iptables" | "nft"
                | "kill" | "killall" | "pkill"
        ) {
            push_unique_reason(&mut reasons, "账户、防火墙或进程强杀");
            seg_destructive = true;
        } else if matches!(bin, "bash" | "sh" | "zsh" | "python" | "python3") {
            push_unique_reason(&mut reasons, "嵌套 Shell 或脚本执行");
            seg_destructive = true;
        }

        if seg_destructive || !is_readonly_segment(cmd_tokens) {
            all_segments_readonly = false;
        }
    }

    if !reasons.is_empty() {
        SudoRiskAssessment {
            needs_confirmation: true,
            risk_level: "destructive",
            reasons,
        }
    } else if all_segments_readonly {
        SudoRiskAssessment {
            needs_confirmation: false,
            risk_level: "safe",
            reasons: Vec::new(),
        }
    } else {
        SudoRiskAssessment {
            needs_confirmation: true,
            risk_level: "needs_review",
            reasons: vec!["非只读白名单命令（保守审核）"],
        }
    }
}

fn confirm_destructive_sudo_via_zenity(
    display_id: &str,
    command: &str,
    assessment: &SudoRiskAssessment,
) -> anyhow::Result<bool> {
    let reason_line = if assessment.reasons.is_empty() {
        "高风险/非只读操作".to_owned()
    } else {
        assessment.reasons.join("、")
    };
    let text = format!(
        "检测到需要人工审核的 sudo 命令：\n\n\
         风险等级：{}\n\
         风险原因：{}\n\n\
         待执行命令：\n  sudo {}\n\n\
         请核对命令内容后再决定是否继续执行。",
        assessment.risk_level, reason_line, command
    );
    let status = std::process::Command::new("zenity")
        .env("DISPLAY", display_id)
        .arg("--question")
        .arg("--title=高危 sudo 命令审核 (cua-ycwang)")
        .arg("--ok-label=确认执行")
        .arg("--cancel-label=取消")
        .arg("--default-cancel")
        .arg("--width=540")
        .arg("--no-markup")
        .arg("--text")
        .arg(&text)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to launch zenity confirmation dialog (fail-closed): {e}"
            )
        })?;
    Ok(status.success())
}

pub struct SudoInTerminalTool;
static SUDO_IN_TERMINAL_DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

#[async_trait]
impl Tool for SudoInTerminalTool {
    fn def(&self) -> &ToolDef {
        SUDO_IN_TERMINAL_DEF.get_or_init(|| ToolDef {
            name: "sudo_in_terminal".into(),
            description: "Run a sudo command transparently in a visible terminal. Destructive or non-read-only commands (e.g. rm, mv, apt purge/remove, systemctl stop, chmod, redirects) automatically pop up a zenity confirmation dialog showing the full command BEFORE reading or typing CUA_YCWANG_SUDO_PASS; read-only commands proceed directly and keep output visible.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run with sudo (leading 'sudo ' is optional)."
                    },
                    "env_key": {
                        "type": "string",
                        "description": "Optional CUA_YCWANG_* secret key name (default: CUA_YCWANG_SUDO_PASS)."
                    },
                    "env_file": {
                        "type": "string",
                        "description": "Optional path to .env file. Defaults to $CUA_YCWANG_CONFIG_DIR/env/secrets.env and ~/.config/cua-ycwang/env/secrets.env."
                    },
                    "keep_open": {
                        "type": "boolean",
                        "description": "Keep the terminal window open after execution so the user can view output (default true)."
                    },
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
        let Some(raw_cmd) = args.opt_str("command") else {
            return ToolResult::error("command is required");
        };
        let command = match normalize_sudo_command(&raw_cmd) {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("invalid command: {e:#}")),
        };
        let env_key = args
            .opt_str("env_key")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_SUDO_ENV_KEY.to_owned());
        if let Err(e) = validate_env_key(&env_key) {
            return ToolResult::error(format!("{e:#}"));
        }
        let env_file = args.opt_str("env_file");
        let keep_open = args.bool_or("keep_open", true);
        let target = match resolve_target_display(&args) {
            Ok(t) => t,
            Err(r) => return r,
        };

        let command_for_result = command.clone();
        let env_key_for_result = env_key.clone();
        let assessment = assess_sudo_command_risk(&command);
        let risk_level = assessment.risk_level;
        let confirmation_required = assessment.needs_confirmation;

        match tokio::task::spawn_blocking(
            move || -> anyhow::Result<(bool, String, Option<u32>, Option<u64>)> {
                let ctx = global_screen_pool().get_or_connect(&target)?;
                if assessment.needs_confirmation {
                    let approved = confirm_destructive_sudo_via_zenity(
                        &ctx.display_id,
                        &command,
                        &assessment,
                    )?;
                    if !approved {
                        return Ok((false, ctx.display_id.clone(), None, None));
                    }
                }

                let secret = resolve_secret_from_env(&env_key, env_file.as_deref())?;

            let script_path = std::env::temp_dir().join(format!(
                "cua-sudo-{}-{}.sh",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let script_body = build_sudo_terminal_script(&command, &script_path, keep_open);
            std::fs::write(&script_path, script_body)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &script_path,
                    std::fs::Permissions::from_mode(0o700),
                );
            }

            let title = format!(
                "sudo: {}",
                truncate_chars(&command.replace(['\r', '\n'], " "), 48)
            );
            let exec_cmd = format!("bash {}", shell_single_quote(&script_path.display().to_string()));
            let child = std::process::Command::new("xfce4-terminal")
                .env("DISPLAY", &ctx.display_id)
                .arg("--disable-server")
                .arg("-T")
                .arg(&title)
                .arg("-e")
                .arg(&exec_cmd)
                .spawn()
                .map_err(|e| {
                    let _ = std::fs::remove_file(&script_path);
                    anyhow::anyhow!("failed to launch xfce4-terminal: {e}")
                })?;
            let pid = child.id();

            let mut found_xid = None;
            for _ in 0..50 {
                let windows = crate::x11::list_windows(Some(pid));
                if let Some(w) = windows.first() {
                    found_xid = Some(w.xid);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let xid = found_xid.ok_or_else(|| {
                anyhow::anyhow!("timed out waiting for xfce4-terminal window (pid {pid})")
            })?;

            crate::input::x11_activate_window_persistent(xid)
                .map_err(|e| anyhow::anyhow!("failed to activate terminal window {xid}: {e}"))?;
            std::thread::sleep(std::time::Duration::from_millis(450));

            let _ime_guard = crate::ime::ImeGuard::acquire_for_target(&ctx.target);
            type_secret_into_context(&ctx, &env_key, &secret, true)?;
            drop(secret);

            Ok((true, ctx.display_id.clone(), Some(pid), Some(xid)))
        })
        .await
        {
            Ok(Ok((false, display_id, _, _))) => {
                let msg = format!(
                    "Cancelled by user in confirmation dialog: 'sudo {command_for_result}' was NOT executed on {display_id}."
                );
                ToolResult::text(msg).with_structured(json!({
                    "ok": false,
                    "cancelled": true,
                    "command": command_for_result,
                    "risk_level": risk_level,
                    "confirmation_required": confirmation_required,
                    "display_id": display_id,
                }))
            }
            Ok(Ok((true, display_id, Some(pid), Some(window_id)))) => {
                let msg = format!(
                    "Started transparent sudo command 'sudo {command_for_result}' in terminal (pid={pid}, window_id={window_id}) on {display_id} and typed {env_key_for_result}."
                );
                ToolResult::text(msg).with_structured(json!({
                    "ok": true,
                    "cancelled": false,
                    "command": command_for_result,
                    "env_key": env_key_for_result,
                    "risk_level": risk_level,
                    "confirmation_required": confirmation_required,
                    "pid": pid,
                    "window_id": window_id,
                    "display_id": display_id,
                    "keep_open": keep_open,
                }))
            }
            Ok(Ok((true, _, _, _))) => {
                ToolResult::error("sudo_in_terminal failed: missing terminal pid/window_id")
            }
            Ok(Err(e)) => ToolResult::error(format!("sudo_in_terminal failed: {e:#}")),
            Err(e) => ToolResult::error(format!("sudo_in_terminal panicked: {e}")),
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

    #[test]
    fn default_candidates_include_config_dir_and_secrets_env() {
        let candidates = default_env_file_candidates_from(
            None,
            Some("/tmp/custom-cua-config"),
            Some("/tmp/custom-home"),
        );
        assert_eq!(
            candidates,
            vec![
                PathBuf::from(".env"),
                PathBuf::from("/tmp/custom-cua-config/env/secrets.env"),
                PathBuf::from("/tmp/custom-cua-config/.env"),
                PathBuf::from("/tmp/custom-home/.config/cua-ycwang/env/secrets.env"),
                PathBuf::from("/tmp/custom-home/.config/cua-ycwang/.env"),
            ]
        );
    }

    #[test]
    fn normalize_sudo_command_strips_prefix_and_rejects_empty() {
        assert_eq!(
            normalize_sudo_command("sudo apt purge -y wemeet").unwrap(),
            "apt purge -y wemeet"
        );
        assert_eq!(normalize_sudo_command("  id  ").unwrap(), "id");
        assert!(normalize_sudo_command("sudo   ").is_err());
        assert!(normalize_sudo_command("").is_err());
    }

    #[test]
    fn build_sudo_terminal_script_shows_command_and_keep_open() {
        let script = build_sudo_terminal_script(
            "apt update && echo '100%'",
            Path::new("/tmp/test-sudo.sh"),
            true,
        );
        assert!(script.contains("即将以 sudo 执行命令"));
        assert!(script.contains("sudo -k -p"));
        assert!(script.contains("100%%"));
        assert!(script.contains("read -r _"));
    }

    #[test]
    fn assess_sudo_command_risk_separates_readonly_destructive_and_unknown() {
        let safe_id = assess_sudo_command_risk("id");
        assert!(!safe_id.needs_confirmation);
        assert_eq!(safe_id.risk_level, "safe");

        let safe_status = assess_sudo_command_risk("systemctl status pipewire");
        assert!(!safe_status.needs_confirmation);
        assert_eq!(safe_status.risk_level, "safe");

        for cmd in [
            "rm -rf /tmp/foo",
            "mv /tmp/a /tmp/b",
            "apt purge -y wemeet",
            "systemctl stop nginx",
            "chmod -R 777 /opt/app",
            "id > /tmp/out.txt",
            "ls | rm -f foo",
        ] {
            let res = assess_sudo_command_risk(cmd);
            assert!(res.needs_confirmation, "expected confirmation for '{cmd}'");
            assert_eq!(res.risk_level, "destructive", "for '{cmd}'");
        }

        let unknown = assess_sudo_command_risk("some_custom_tool --apply");
        assert!(unknown.needs_confirmation);
        assert_eq!(unknown.risk_level, "needs_review");
    }
}
