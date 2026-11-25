// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Sanitized site authentication metadata resolver (`resolve_auth_site`).
//!
//! Reads `auth_sites.json`, `totp_sites.json`, `auth_templates.json`,
//! `google_voice.json`, and `env/secrets.env` key names (NEVER values) from
//! `$CUA_YCWANG_CONFIG_DIR` (default `~/.config/cua-ycwang`), and resolves
//! matching non-secret metadata (`site`, `totp_env_key`, `username_env_key`,
//! `password_env_key`, `env_file`, `second_factor_type`, `auth_flow`,
//! `app_recipe`, `sms_config`, and `candidates`) for a URL/domain, username,
//! or keyword query.
//!
//! Security boundary:
//! - `.env` parsing discards everything after `=` immediately and only retains
//!   variable names starting with `CUA_YCWANG_`.
//! - JSON registries deserialize through strict metadata-only structs so
//!   unexpected secret fields are ignored at the type boundary.
//! - Output and error messages never expose secrets, passwords, TOTP seeds,
//!   `otpauth://` URIs, or URL query/userinfo credentials.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::protocol::ToolResult;
use crate::tool::{Tool, ToolDef};
use crate::tool_args::parse_typed_input;

/// Required prefix for all credential and TOTP environment variable names.
pub const ENV_KEY_PREFIX: &str = "CUA_YCWANG_";

const AUTH_SITES_FILENAME: &str = "auth_sites.json";
const TOTP_SITES_FILENAME: &str = "totp_sites.json";
const AUTH_TEMPLATES_FILENAME: &str = "auth_templates.json";
const GOOGLE_VOICE_FILENAME: &str = "google_voice.json";

const COMPOUND_PUBLIC_SECOND_LEVELS: &[&str] = &[
    "com", "co", "net", "org", "edu", "gov", "ac", "ne", "or", "go",
];

// ── Public Wire Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResolveAuthSiteInput {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRecipeRef {
    pub app_id: String,
    pub flow: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmsAuthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_number: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_numbers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthTemplateSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_plaintext_policy: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommended_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnvKeyPresence {
    pub totp: bool,
    pub username: bool,
    pub password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSiteCandidate {
    pub site: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tws_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_recipe: Option<AppRecipeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_recipe: Option<AppRecipeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_remaining_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub press_enter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sms_config: Option<SmsAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_template: Option<AuthTemplateSummary>,
    pub env_keys_present: EnvKeyPresence,
    #[serde(skip)]
    aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveAuthSiteResponse {
    pub matched: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tws_env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_recipe: Option<AppRecipeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_recipe: Option<AppRecipeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_remaining_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub press_enter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sms_config: Option<SmsAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_template: Option<AuthTemplateSummary>,
    pub candidates: Vec<AuthSiteCandidate>,
}

// ── Strict Metadata-Only File Schemas ────────────────────────────────────────
//
// Any unknown keys (such as an accidentally added `secret`, `password`, or
// `seed`) are silently discarded by Serde during deserialization.

#[derive(Debug, Deserialize, Default)]
struct AuthSitesFile {
    #[serde(default)]
    defaults: Option<AuthSitesDefaults>,
    #[serde(default)]
    sites: Vec<AuthSiteRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct AuthSitesDefaults {
    #[serde(default)]
    totp: Option<TotpDefaults>,
    #[serde(default)]
    sms_google_voice: Option<SmsDefaults>,
}

#[derive(Debug, Deserialize, Default)]
struct TotpDefaults {
    #[serde(default)]
    env_file: Option<String>,
    #[serde(default)]
    min_remaining_secs: Option<u64>,
    #[serde(default)]
    press_enter: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct SmsDefaults {
    #[serde(default)]
    voice_url: Option<String>,
    #[serde(default)]
    primary_number: Option<String>,
    #[serde(default)]
    fallback_numbers: Vec<String>,
    #[serde(default)]
    sender_hints: Vec<String>,
    #[serde(default)]
    code_regex: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct GoogleVoiceNumberRecord {
    #[serde(default)]
    e164: Option<String>,
    #[serde(default)]
    formatted: Option<String>,
}

/// Strict metadata-only deserialization target for `google_voice.json`.
/// Any secret/credential/token fields are silently discarded by Serde.
#[derive(Debug, Deserialize, Default)]
struct GoogleVoiceFile {
    #[serde(default)]
    site_id: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    voice_url: Option<String>,
    #[serde(default)]
    primary_number: Option<String>,
    #[serde(default)]
    fallback_numbers: Vec<String>,
    #[serde(default)]
    numbers: Vec<GoogleVoiceNumberRecord>,
    #[serde(default)]
    sender_hints: Vec<String>,
    #[serde(default)]
    code_regex: Option<String>,
    #[serde(default)]
    auth_flow: Option<String>,
    #[serde(default)]
    chrome_flow: Option<String>,
    #[serde(default)]
    app_recipe: Option<AppRecipeOrString>,
    #[serde(default)]
    desktop_recipe: Option<AppRecipeRef>,
}

#[derive(Debug, Deserialize, Default)]
struct TotpSitesFile {
    #[serde(default)]
    default_env_file: Option<String>,
    #[serde(default)]
    default_min_remaining_secs: Option<u64>,
    #[serde(default)]
    sites: Vec<AuthSiteRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AppRecipeOrString {
    Structured(AppRecipeRef),
    Compact(String),
}

impl AppRecipeOrString {
    fn into_ref(self) -> Option<AppRecipeRef> {
        match self {
            Self::Structured(r) => {
                let app_id = sanitize_non_secret(&r.app_id)?;
                let flow = sanitize_non_secret(&r.flow)?;
                Some(AppRecipeRef { app_id, flow })
            }
            Self::Compact(raw) => {
                let clean = sanitize_non_secret(&raw)?;
                if let Some((app_id, flow)) = clean.split_once(':') {
                    let app_id = sanitize_non_secret(app_id)?;
                    let flow = sanitize_non_secret(flow)?;
                    Some(AppRecipeRef { app_id, flow })
                } else {
                    Some(AppRecipeRef {
                        app_id: clean,
                        flow: String::new(),
                    })
                }
            }
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct AuthSiteRecord {
    site_id: String,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    auth_method: Option<String>,
    #[serde(default)]
    second_factor_type: Option<String>,
    #[serde(default)]
    env_key: Option<String>,
    #[serde(default)]
    totp_env_key: Option<String>,
    #[serde(default)]
    username_env_key: Option<String>,
    #[serde(default)]
    password_env_key: Option<String>,
    #[serde(default)]
    tws_env_key: Option<String>,
    #[serde(default)]
    env_file: Option<String>,
    #[serde(default)]
    auth_flow: Option<String>,
    #[serde(default)]
    chrome_flow: Option<String>,
    #[serde(default)]
    desktop_recipe: Option<AppRecipeRef>,
    #[serde(default)]
    app_recipe: Option<AppRecipeOrString>,
    #[serde(default)]
    min_remaining_secs: Option<u64>,
    #[serde(default)]
    press_enter: Option<bool>,
    #[serde(default)]
    voice_url: Option<String>,
    #[serde(default)]
    primary_number: Option<String>,
    #[serde(default)]
    fallback_numbers: Vec<String>,
    #[serde(default)]
    sender_hints: Vec<String>,
    #[serde(default)]
    code_regex: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AuthTemplatesFile {
    #[serde(default)]
    templates: BTreeMap<String, AuthTemplateRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct AuthTemplateRecord {
    #[serde(default)]
    auth_method: Option<String>,
    #[serde(default)]
    safety_level: Option<String>,
    #[serde(default)]
    zero_plaintext_policy: Option<bool>,
    #[serde(default)]
    execution_order: Vec<AuthTemplateStepRecord>,
    #[serde(default)]
    steps: Vec<AuthTemplateStepRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct AuthTemplateStepRecord {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    tools: Vec<String>,
}

// ── Sanitization & Validation Helpers ────────────────────────────────────────

/// Validate an environment variable name: must strictly start with
/// `CUA_YCWANG_`, contain a non-empty suffix, and use only `[A-Za-z0-9_]`.
pub fn validate_env_key(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed != raw
        || !trimmed.starts_with(ENV_KEY_PREFIX)
        || trimmed.len() <= ENV_KEY_PREFIX.len()
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some(trimmed)
}

fn sanitize_env_key(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| {
        let trimmed = s.trim().to_owned();
        validate_env_key(&trimmed).map(|valid| valid.to_owned())
    })
}

fn sanitize_non_secret(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("otpauth://") {
        return None;
    }
    Some(trimmed.to_owned())
}

fn sanitize_opt_str(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| sanitize_non_secret(&s))
}

fn sanitize_url_opt(raw: Option<String>) -> Option<String> {
    let clean = sanitize_opt_str(raw)?;
    if let Ok(mut parsed) = Url::parse(&clean) {
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            return Some(parsed.into());
        }
    }
    Some(clean)
}

fn is_google_voice_sms_type(val: Option<&str>) -> bool {
    matches!(
        val.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("sms_google_voice" | "google_voice_sms")
    )
}

fn opt_trimmed(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn expand_tilde_str(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home).join(rest);
            }
        }
    }
    PathBuf::from(raw)
}

/// Read ONLY `CUA_YCWANG_*` key names from an `.env` file.
///
/// The value portion after the first `=` is immediately discarded without
/// allocation, logging, or inspection.
pub fn collect_env_key_names_from_file(path: &Path, out: &mut BTreeSet<String>) -> anyhow::Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read env key names from {}: {e}", path.display()))?;
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
        let Some((raw_key, _discarded_value)) = line.split_once('=') else {
            continue;
        };
        if let Some(valid_key) = validate_env_key(raw_key.trim()) {
            out.insert(valid_key.to_owned());
        }
    }
    Ok(())
}

fn read_json_sanitized<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<Option<T>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str::<T>(&raw).map(Some).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse {}: line {}, column {}",
            path.display(),
            e.line(),
            e.column()
        )
    })
}

// ── Domain / Host Extraction & Matching ──────────────────────────────────────

/// Extract the lowercase hostname from a URL or bare host/domain string.
/// Strips scheme, credentials (`user:pass@`), port, path, query, and fragment.
pub fn extract_url_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&candidate).ok()?;
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// Split a hostname into `(non_suffix_stem, registrable_primary_label, is_bare_registrable)`.
///
/// Examples:
/// - `"www.interactivebrokers.com.au"` -> `("www.interactivebrokers", "interactivebrokers", false)`
/// - `"interactivebrokers.com"`        -> `("interactivebrokers", "interactivebrokers", true)`
/// - `"accounts.google.com"`           -> `("accounts.google", "google", false)`
/// - `"console.aws.amazon.co.jp"`      -> `("console.aws.amazon", "amazon", false)`
fn decompose_domain(host: &str) -> Option<(String, String, bool)> {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let last = labels[labels.len() - 1];
    let second_last = labels[labels.len() - 2];
    let suffix_len = if labels.len() >= 3
        && last.len() == 2
        && COMPOUND_PUBLIC_SECOND_LEVELS.contains(&second_last)
    {
        2
    } else {
        1
    };
    let stem_labels = &labels[..labels.len() - suffix_len];
    if stem_labels.is_empty() {
        return None;
    }
    let primary = stem_labels[stem_labels.len() - 1].to_owned();
    let stem = stem_labels.join(".");
    let bare_registrable = stem_labels.len() == 1 || (stem_labels.len() == 2 && stem_labels[0] == "www");
    Some((stem, primary, bare_registrable))
}

fn score_host_against_domain(host: &str, domain: &str) -> u32 {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || d.is_empty() {
        return 0;
    }
    if h == d {
        return 100;
    }
    let h_no_www = strip_www(&h);
    let d_no_www = strip_www(&d);
    if h_no_www == d_no_www {
        return 95;
    }
    if h.ends_with(&format!(".{d_no_www}")) {
        return 90;
    }

    if let (Some((h_stem, h_primary, _)), Some((d_stem, d_primary, d_bare))) =
        (decompose_domain(&h), decompose_domain(&d))
    {
        let h_stem_no_www = strip_www(&h_stem);
        let d_stem_no_www = strip_www(&d_stem);
        if h_stem_no_www == d_stem_no_www {
            return 85;
        }
        if h_stem_no_www.ends_with(&format!(".{d_stem_no_www}")) {
            return 82;
        }
        // Cross-ccTLD / alternate-TLD matching for bare registrable domains
        // (e.g. `www.interactivebrokers.com.au` <-> `interactivebrokers.com`),
        // gated to labels >= 3 chars so short 2-char brands like `id.me` do not
        // collide across unrelated TLDs.
        if d_bare && d_primary.len() >= 3 && h_primary == d_primary {
            return 80;
        }
    }
    0
}

// ── Registry Loading & Merging ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct MergedSite {
    site_id: String,
    issuer: Option<String>,
    account: Option<String>,
    domains: Vec<String>,
    aliases: Vec<String>,
    second_factor_type: Option<String>,
    totp_env_key: Option<String>,
    username_env_key: Option<String>,
    password_env_key: Option<String>,
    tws_env_key: Option<String>,
    env_file: Option<String>,
    auth_flow: Option<String>,
    chrome_flow: Option<String>,
    desktop_recipe: Option<AppRecipeRef>,
    app_recipe: Option<AppRecipeRef>,
    min_remaining_secs: Option<u64>,
    press_enter: Option<bool>,
    voice_url: Option<String>,
    primary_number: Option<String>,
    fallback_numbers: Vec<String>,
    sender_hints: Vec<String>,
    code_regex: Option<String>,
}

fn push_unique_ci(target: &mut Vec<String>, items: Vec<String>) {
    for raw in items {
        let Some(clean) = sanitize_non_secret(&raw) else {
            continue;
        };
        if !target.iter().any(|existing| existing.eq_ignore_ascii_case(&clean)) {
            target.push(clean);
        }
    }
}

fn merge_site_record(
    sites: &mut Vec<MergedSite>,
    index: &mut HashMap<String, usize>,
    rec: AuthSiteRecord,
    default_second_factor: Option<&str>,
) {
    let Some(site_id) = sanitize_non_secret(&rec.site_id) else {
        return;
    };
    let explicit_totp = sanitize_env_key(rec.totp_env_key);
    let fallback_env_key = sanitize_env_key(rec.env_key);
    let second_factor = sanitize_opt_str(rec.second_factor_type)
        .or_else(|| sanitize_opt_str(rec.auth_method))
        .or_else(|| default_second_factor.map(str::to_owned));

    let totp_env_key = explicit_totp.or_else(|| {
        fallback_env_key.filter(|k| {
            second_factor.as_deref() == Some("totp")
                || k.ends_with("_TOTP_SECRET")
                || k.ends_with("_TOTP")
        })
    });
    let username_env_key = sanitize_env_key(rec.username_env_key);
    let password_env_key = sanitize_env_key(rec.password_env_key);
    let tws_env_key = sanitize_env_key(rec.tws_env_key);
    let app_recipe = rec.app_recipe.and_then(AppRecipeOrString::into_ref);
    let desktop_recipe = rec.desktop_recipe.and_then(|r| {
        Some(AppRecipeRef {
            app_id: sanitize_non_secret(&r.app_id)?,
            flow: sanitize_non_secret(&r.flow)?,
        })
    });

    if let Some(&idx) = index.get(&site_id) {
        let existing = &mut sites[idx];
        if existing.issuer.is_none() {
            existing.issuer = sanitize_opt_str(rec.issuer);
        }
        if existing.account.is_none() {
            existing.account = sanitize_opt_str(rec.account);
        }
        push_unique_ci(&mut existing.domains, rec.domains);
        push_unique_ci(&mut existing.aliases, rec.aliases);
        if existing.second_factor_type.is_none() {
            existing.second_factor_type = second_factor;
        }
        if existing.totp_env_key.is_none() {
            existing.totp_env_key = totp_env_key;
        }
        if existing.username_env_key.is_none() {
            existing.username_env_key = username_env_key;
        }
        if existing.password_env_key.is_none() {
            existing.password_env_key = password_env_key;
        }
        if existing.tws_env_key.is_none() {
            existing.tws_env_key = tws_env_key;
        }
        if existing.env_file.is_none() {
            existing.env_file = sanitize_opt_str(rec.env_file);
        }
        if existing.auth_flow.is_none() {
            existing.auth_flow = sanitize_opt_str(rec.auth_flow);
        }
        if existing.chrome_flow.is_none() {
            existing.chrome_flow = sanitize_opt_str(rec.chrome_flow);
        }
        if existing.desktop_recipe.is_none() {
            existing.desktop_recipe = desktop_recipe;
        }
        if existing.app_recipe.is_none() {
            existing.app_recipe = app_recipe;
        }
        if existing.min_remaining_secs.is_none() {
            existing.min_remaining_secs = rec.min_remaining_secs;
        }
        if existing.press_enter.is_none() {
            existing.press_enter = rec.press_enter;
        }
        if existing.voice_url.is_none() {
            existing.voice_url = sanitize_url_opt(rec.voice_url);
        }
        if existing.primary_number.is_none() {
            existing.primary_number = sanitize_opt_str(rec.primary_number);
        }
        push_unique_ci(&mut existing.fallback_numbers, rec.fallback_numbers);
        push_unique_ci(&mut existing.sender_hints, rec.sender_hints);
        if existing.code_regex.is_none() {
            existing.code_regex = sanitize_opt_str(rec.code_regex);
        }
    } else {
        let mut domains = Vec::new();
        push_unique_ci(&mut domains, rec.domains);
        let mut aliases = Vec::new();
        push_unique_ci(&mut aliases, rec.aliases);
        let mut fallback_numbers = Vec::new();
        push_unique_ci(&mut fallback_numbers, rec.fallback_numbers);
        let mut sender_hints = Vec::new();
        push_unique_ci(&mut sender_hints, rec.sender_hints);

        let idx = sites.len();
        index.insert(site_id.clone(), idx);
        sites.push(MergedSite {
            site_id,
            issuer: sanitize_opt_str(rec.issuer),
            account: sanitize_opt_str(rec.account),
            domains,
            aliases,
            second_factor_type: second_factor,
            totp_env_key,
            username_env_key,
            password_env_key,
            tws_env_key,
            env_file: sanitize_opt_str(rec.env_file),
            auth_flow: sanitize_opt_str(rec.auth_flow),
            chrome_flow: sanitize_opt_str(rec.chrome_flow),
            desktop_recipe,
            app_recipe,
            min_remaining_secs: rec.min_remaining_secs,
            press_enter: rec.press_enter,
            voice_url: sanitize_url_opt(rec.voice_url),
            primary_number: sanitize_opt_str(rec.primary_number),
            fallback_numbers,
            sender_hints,
            code_regex: sanitize_opt_str(rec.code_regex),
        });
    }
}

fn normalize_stem(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

fn derive_env_stems(site_id: &str, totp_env_key: Option<&str>) -> Vec<String> {
    let mut stems = Vec::new();
    if let Some(key) = totp_env_key {
        let stripped = key
            .strip_suffix("_TOTP_SECRET")
            .or_else(|| key.strip_suffix("_TOTP"))
            .unwrap_or(key);
        if stripped.starts_with(ENV_KEY_PREFIX) && stripped.len() > ENV_KEY_PREFIX.len() {
            stems.push(stripped.to_owned());
        }
    }
    let site_stem = format!("{ENV_KEY_PREFIX}{}", normalize_stem(site_id));
    if !stems.contains(&site_stem) {
        stems.push(site_stem);
    }
    stems
}

fn find_key_for_stems(
    stems: &[String],
    suffixes: &[&str],
    env_keys: &BTreeSet<String>,
) -> Option<String> {
    for stem in stems {
        for suffix in suffixes {
            let candidate = format!("{stem}{suffix}");
            if env_keys.contains(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn build_template_summaries(templates: AuthTemplatesFile) -> BTreeMap<String, AuthTemplateSummary> {
    let mut out = BTreeMap::new();
    for (name, rec) in templates.templates {
        let mut tools = Vec::new();
        for step in rec.execution_order.into_iter().chain(rec.steps.into_iter()) {
            if let Some(t) = sanitize_opt_str(step.tool) {
                if !tools.contains(&t) {
                    tools.push(t);
                }
            }
            for t in step.tools {
                if let Some(clean) = sanitize_non_secret(&t) {
                    if !tools.contains(&clean) {
                        tools.push(clean);
                    }
                }
            }
        }
        out.insert(
            name,
            AuthTemplateSummary {
                auth_method: sanitize_opt_str(rec.auth_method),
                safety_level: sanitize_opt_str(rec.safety_level),
                zero_plaintext_policy: rec.zero_plaintext_policy,
                recommended_tools: tools,
            },
        );
    }
    out
}

#[derive(Debug, Clone, Default)]
struct SanitizedGoogleVoice {
    site_id: String,
    issuer: Option<String>,
    account: Option<String>,
    domains: Vec<String>,
    aliases: Vec<String>,
    voice_url: Option<String>,
    primary_number: Option<String>,
    fallback_numbers: Vec<String>,
    sender_hints: Vec<String>,
    code_regex: Option<String>,
    auth_flow: Option<String>,
    chrome_flow: Option<String>,
    app_recipe: Option<AppRecipeRef>,
    desktop_recipe: Option<AppRecipeRef>,
}

fn sanitize_google_voice_file(gv: GoogleVoiceFile) -> SanitizedGoogleVoice {
    let site_id = sanitize_opt_str(gv.site_id).unwrap_or_else(|| "google_voice".to_owned());
    let issuer = sanitize_opt_str(gv.issuer).or_else(|| Some("Google Voice".to_owned()));
    let account = sanitize_opt_str(gv.account);
    let voice_url = sanitize_url_opt(gv.voice_url);

    let mut domains = Vec::new();
    push_unique_ci(&mut domains, gv.domains);
    if let Some(ref vurl) = voice_url {
        if let Some(host) = extract_url_host(vurl) {
            push_unique_ci(&mut domains, vec![host]);
        }
    }

    let mut aliases = Vec::new();
    push_unique_ci(&mut aliases, gv.aliases);
    if site_id.eq_ignore_ascii_case("google_voice") {
        push_unique_ci(
            &mut aliases,
            vec!["google voice".to_owned(), "google-voice".to_owned()],
        );
    }

    let mut num_entries = Vec::new();
    for rec in gv.numbers {
        if let Some(num) = sanitize_opt_str(rec.e164).or_else(|| sanitize_opt_str(rec.formatted)) {
            if !num_entries
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&num))
            {
                num_entries.push(num);
            }
        }
    }

    let primary_number =
        sanitize_opt_str(gv.primary_number).or_else(|| num_entries.first().cloned());
    let mut fallback_numbers = Vec::new();
    push_unique_ci(&mut fallback_numbers, gv.fallback_numbers);
    push_unique_ci(&mut fallback_numbers, num_entries);
    if let Some(ref primary) = primary_number {
        fallback_numbers.retain(|n| !n.eq_ignore_ascii_case(primary));
    }

    let mut sender_hints = Vec::new();
    push_unique_ci(&mut sender_hints, gv.sender_hints);

    let app_recipe = gv.app_recipe.and_then(AppRecipeOrString::into_ref);
    let desktop_recipe = gv.desktop_recipe.and_then(|r| {
        Some(AppRecipeRef {
            app_id: sanitize_non_secret(&r.app_id)?,
            flow: sanitize_non_secret(&r.flow)?,
        })
    });

    SanitizedGoogleVoice {
        site_id,
        issuer,
        account,
        domains,
        aliases,
        voice_url,
        primary_number,
        fallback_numbers,
        sender_hints,
        code_regex: sanitize_opt_str(gv.code_regex),
        auth_flow: sanitize_opt_str(gv.auth_flow),
        chrome_flow: sanitize_opt_str(gv.chrome_flow),
        app_recipe,
        desktop_recipe,
    }
}

fn google_voice_as_site_record(gv: &SanitizedGoogleVoice) -> AuthSiteRecord {
    AuthSiteRecord {
        site_id: gv.site_id.clone(),
        issuer: gv.issuer.clone(),
        account: gv.account.clone(),
        domains: gv.domains.clone(),
        aliases: gv.aliases.clone(),
        auth_method: Some("sms_google_voice".to_owned()),
        second_factor_type: Some("sms_google_voice".to_owned()),
        auth_flow: gv.auth_flow.clone(),
        chrome_flow: gv.chrome_flow.clone(),
        desktop_recipe: gv.desktop_recipe.clone(),
        app_recipe: gv.app_recipe.clone().map(AppRecipeOrString::Structured),
        voice_url: gv.voice_url.clone(),
        primary_number: gv.primary_number.clone(),
        fallback_numbers: gv.fallback_numbers.clone(),
        sender_hints: gv.sender_hints.clone(),
        code_regex: gv.code_regex.clone(),
        ..Default::default()
    }
}

fn load_candidates(config_dir: &Path) -> anyhow::Result<Vec<AuthSiteCandidate>> {
    let auth_sites: Option<AuthSitesFile> =
        read_json_sanitized(&config_dir.join(AUTH_SITES_FILENAME))?;
    let totp_sites: Option<TotpSitesFile> =
        read_json_sanitized(&config_dir.join(TOTP_SITES_FILENAME))?;
    let auth_templates: Option<AuthTemplatesFile> =
        read_json_sanitized(&config_dir.join(AUTH_TEMPLATES_FILENAME))?;
    let google_voice_file: Option<GoogleVoiceFile> =
        read_json_sanitized(&config_dir.join(GOOGLE_VOICE_FILENAME))?;
    let gv_config = google_voice_file.map(sanitize_google_voice_file);

    let mut default_totp_env_file: Option<String> = None;
    let mut default_min_remaining_secs: Option<u64> = None;
    let mut default_press_enter: Option<bool> = None;
    let mut default_sms_voice_url: Option<String> = None;
    let mut default_sms_primary: Option<String> = None;
    let mut default_sms_fallbacks: Vec<String> = Vec::new();
    let mut default_sms_sender_hints: Vec<String> = Vec::new();
    let mut default_sms_code_regex: Option<String> = None;

    let mut merged: Vec<MergedSite> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    if let Some(auth) = auth_sites {
        if let Some(defaults) = auth.defaults {
            if let Some(totp) = defaults.totp {
                default_totp_env_file = sanitize_opt_str(totp.env_file);
                default_min_remaining_secs = totp.min_remaining_secs;
                default_press_enter = totp.press_enter;
            }
            if let Some(sms) = defaults.sms_google_voice {
                default_sms_voice_url = sanitize_url_opt(sms.voice_url);
                default_sms_primary = sanitize_opt_str(sms.primary_number);
                push_unique_ci(&mut default_sms_fallbacks, sms.fallback_numbers);
                push_unique_ci(&mut default_sms_sender_hints, sms.sender_hints);
                default_sms_code_regex = sanitize_opt_str(sms.code_regex);
            }
        }
        for rec in auth.sites {
            merge_site_record(&mut merged, &mut index, rec, None);
        }
    }

    if let Some(totp) = totp_sites {
        if default_totp_env_file.is_none() {
            default_totp_env_file = sanitize_opt_str(totp.default_env_file);
        }
        if default_min_remaining_secs.is_none() {
            default_min_remaining_secs = totp.default_min_remaining_secs;
        }
        for rec in totp.sites {
            merge_site_record(&mut merged, &mut index, rec, Some("totp"));
        }
    }

    if let Some(ref gv) = gv_config {
        merge_site_record(
            &mut merged,
            &mut index,
            google_voice_as_site_record(gv),
            Some("sms_google_voice"),
        );
    }

    // Collect ONLY `CUA_YCWANG_*` key names from local secrets.env files.
    let mut env_keys: BTreeSet<String> = BTreeSet::new();
    let local_env_secrets = config_dir.join("env").join("secrets.env");
    let local_root_secrets = config_dir.join("secrets.env");
    collect_env_key_names_from_file(&local_env_secrets, &mut env_keys)?;
    collect_env_key_names_from_file(&local_root_secrets, &mut env_keys)?;
    if let Some(ref p) = default_totp_env_file {
        collect_env_key_names_from_file(&expand_tilde_str(p), &mut env_keys)?;
    }
    for site in &merged {
        if let Some(ref p) = site.env_file {
            collect_env_key_names_from_file(&expand_tilde_str(p), &mut env_keys)?;
        }
    }

    let templates = auth_templates
        .map(build_template_summaries)
        .unwrap_or_default();

    let default_local_env_path = if local_env_secrets.is_file() {
        Some(local_env_secrets.display().to_string())
    } else if local_root_secrets.is_file() {
        Some(local_root_secrets.display().to_string())
    } else {
        None
    };

    let mut claimed_primary_keys: BTreeSet<String> = BTreeSet::new();
    for site in &merged {
        for k in [
            site.totp_env_key.as_deref(),
            site.username_env_key.as_deref(),
            site.password_env_key.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            claimed_primary_keys.insert(k.to_owned());
        }
    }

    let mut out = Vec::with_capacity(merged.len());
    for site in merged {
        let stems = derive_env_stems(&site.site_id, site.totp_env_key.as_deref());
        let totp_env_key = site
            .totp_env_key
            .or_else(|| find_key_for_stems(&stems, &["_TOTP_SECRET", "_TOTP"], &env_keys));
        let username_env_key = site
            .username_env_key
            .or_else(|| find_key_for_stems(&stems, &["_USERNAME", "_USER"], &env_keys));
        let password_env_key = site
            .password_env_key
            .or_else(|| find_key_for_stems(&stems, &["_PASSWORD", "_PASS"], &env_keys));

        let second_factor_type = site.second_factor_type.or_else(|| {
            if totp_env_key.is_some() {
                Some("totp".to_owned())
            } else {
                None
            }
        });

        let uses_env_secrets = totp_env_key.is_some()
            || username_env_key.is_some()
            || password_env_key.is_some()
            || site.tws_env_key.is_some()
            || second_factor_type.as_deref() == Some("totp");

        let env_file = site.env_file.or_else(|| {
            if uses_env_secrets {
                default_totp_env_file
                    .clone()
                    .or_else(|| default_local_env_path.clone())
            } else {
                None
            }
        });

        let mut related_env_keys = Vec::new();
        if let Some(ref tws_key) = site.tws_env_key {
            related_env_keys.push(tws_key.clone());
        }
        let site_prefix = format!("{ENV_KEY_PREFIX}{}_", normalize_stem(&site.site_id));
        for key in &env_keys {
            if key.starts_with(&site_prefix)
                && totp_env_key.as_deref() != Some(key.as_str())
                && username_env_key.as_deref() != Some(key.as_str())
                && password_env_key.as_deref() != Some(key.as_str())
                && !claimed_primary_keys.contains(key)
                && !related_env_keys.contains(key)
            {
                related_env_keys.push(key.clone());
            }
        }

        let is_gv_sms = is_google_voice_sms_type(second_factor_type.as_deref());
        let auth_flow = site.auth_flow.or_else(|| site.chrome_flow.clone()).or_else(|| {
            if is_gv_sms {
                Some("sms_google_voice".to_owned())
            } else {
                None
            }
        });

        let app_recipe = site
            .app_recipe
            .or_else(|| {
                site.chrome_flow.clone().map(|flow| AppRecipeRef {
                    app_id: "google-chrome".to_owned(),
                    flow,
                })
            })
            .or_else(|| site.desktop_recipe.clone());

        let sms_config = if is_gv_sms
            || site.voice_url.is_some()
            || site.primary_number.is_some()
            || !site.sender_hints.is_empty()
            || site.code_regex.is_some()
        {
            let gv_ref = gv_config.as_ref();
            let voice_url = site
                .voice_url
                .or_else(|| gv_ref.and_then(|g| g.voice_url.clone()))
                .or_else(|| default_sms_voice_url.clone());
            let primary_number = site
                .primary_number
                .or_else(|| gv_ref.and_then(|g| g.primary_number.clone()))
                .or_else(|| default_sms_primary.clone());

            let mut fallback_numbers = site.fallback_numbers;
            if let Some(gv) = gv_ref {
                if let Some(ref gv_primary) = gv.primary_number {
                    push_unique_ci(&mut fallback_numbers, vec![gv_primary.clone()]);
                }
                push_unique_ci(&mut fallback_numbers, gv.fallback_numbers.clone());
            }
            if fallback_numbers.is_empty() {
                push_unique_ci(&mut fallback_numbers, default_sms_fallbacks.clone());
            }
            if let Some(ref primary) = primary_number {
                fallback_numbers.retain(|n| !n.eq_ignore_ascii_case(primary));
            }

            let mut sender_hints = site.sender_hints;
            if let Some(gv) = gv_ref {
                push_unique_ci(&mut sender_hints, gv.sender_hints.clone());
            }
            push_unique_ci(&mut sender_hints, default_sms_sender_hints.clone());

            let code_regex = site
                .code_regex
                .or_else(|| gv_ref.and_then(|g| g.code_regex.clone()))
                .or_else(|| default_sms_code_regex.clone());

            let account = gv_ref.and_then(|g| g.account.clone());

            Some(SmsAuthConfig {
                voice_url,
                account,
                primary_number,
                fallback_numbers,
                sender_hints,
                code_regex,
            })
        } else {
            None
        };

        let auth_template = second_factor_type
            .as_deref()
            .and_then(|kind| {
                templates.get(kind).or_else(|| {
                    if is_google_voice_sms_type(Some(kind)) {
                        templates
                            .get("sms_google_voice")
                            .or_else(|| templates.get("google_voice_sms"))
                    } else {
                        None
                    }
                })
            })
            .cloned();

        let env_keys_present = EnvKeyPresence {
            totp: totp_env_key
                .as_deref()
                .is_some_and(|k| env_keys.contains(k)),
            username: username_env_key
                .as_deref()
                .is_some_and(|k| env_keys.contains(k)),
            password: password_env_key
                .as_deref()
                .is_some_and(|k| env_keys.contains(k)),
        };

        let is_totp = second_factor_type.as_deref() == Some("totp");
        out.push(AuthSiteCandidate {
            site: site.site_id,
            issuer: site.issuer,
            account: site.account,
            domains: site.domains,
            totp_env_key,
            username_env_key,
            password_env_key,
            tws_env_key: site.tws_env_key,
            related_env_keys,
            env_file,
            second_factor_type,
            auth_flow,
            app_recipe,
            desktop_recipe: site.desktop_recipe,
            min_remaining_secs: if is_totp {
                site.min_remaining_secs.or(default_min_remaining_secs)
            } else {
                site.min_remaining_secs
            },
            press_enter: if is_totp {
                site.press_enter.or(default_press_enter)
            } else {
                site.press_enter
            },
            sms_config,
            auth_template,
            env_keys_present,
            aliases: site.aliases,
        });
    }
    Ok(out)
}

// ── Matching & Disambiguation ────────────────────────────────────────────────

fn score_url_candidate(candidate: &AuthSiteCandidate, host: &str) -> u32 {
    let mut best = candidate
        .domains
        .iter()
        .map(|dom| score_host_against_domain(host, dom))
        .max()
        .unwrap_or(0);

    if best > 0 {
        return best;
    }

    // Fallback: match primary label or bare hostname against `site_id` / prefix
    // (e.g. `ibkr.com.au` -> `ibkr` matching `ibkr_yucheng123`).
    let host_no_www = strip_www(host);
    if !host_no_www.contains('.') {
        if candidate.site.eq_ignore_ascii_case(host_no_www) {
            return 75;
        }
        if candidate
            .site
            .to_ascii_lowercase()
            .starts_with(&format!("{host_no_www}_"))
        {
            return 70;
        }
        if candidate
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer.eq_ignore_ascii_case(host_no_www))
        {
            return 65;
        }
    } else if let Some((_, primary, _)) = decompose_domain(host) {
        if primary.len() >= 3 {
            let site_lower = candidate.site.to_ascii_lowercase();
            if site_lower == primary || site_lower.starts_with(&format!("{primary}_")) {
                best = best.max(70);
            }
        }
    }

    best
}

fn score_query_candidate(candidate: &AuthSiteCandidate, query: &str) -> u32 {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return 0;
    }
    let terms: Vec<&str> = q.split_whitespace().collect();
    if terms.is_empty() {
        return 0;
    }

    let mut haystack_parts: Vec<String> = vec![candidate.site.to_ascii_lowercase()];
    if let Some(ref issuer) = candidate.issuer {
        haystack_parts.push(issuer.to_ascii_lowercase());
    }
    if let Some(ref account) = candidate.account {
        haystack_parts.push(account.to_ascii_lowercase());
    }
    for dom in &candidate.domains {
        haystack_parts.push(dom.to_ascii_lowercase());
    }
    for alias in &candidate.aliases {
        haystack_parts.push(alias.to_ascii_lowercase());
    }
    for key in [
        candidate.totp_env_key.as_deref(),
        candidate.username_env_key.as_deref(),
        candidate.password_env_key.as_deref(),
        candidate.tws_env_key.as_deref(),
        candidate.second_factor_type.as_deref(),
        candidate.auth_flow.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        haystack_parts.push(key.to_ascii_lowercase());
    }
    for key in &candidate.related_env_keys {
        haystack_parts.push(key.to_ascii_lowercase());
    }

    if !terms
        .iter()
        .all(|term| haystack_parts.iter().any(|part| part.contains(term)))
    {
        return 0;
    }

    if candidate.site.eq_ignore_ascii_case(&q)
        || candidate
            .account
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&q))
        || candidate
            .aliases
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&q))
        || (terms.len() == 1
            && candidate
                .domains
                .iter()
                .any(|d| strip_www(&d.to_ascii_lowercase()) == strip_www(terms[0])))
    {
        return 100;
    }

    if terms.len() == 1 {
        let t = terms[0];
        if candidate.site.to_ascii_lowercase().starts_with(t)
            || candidate
                .issuer
                .as_deref()
                .is_some_and(|i| i.to_ascii_lowercase().starts_with(t))
            || candidate
                .domains
                .iter()
                .any(|d| score_host_against_domain(t, d) >= 80)
        {
            return 85;
        }
    }
    70
}

fn score_username_candidate(candidate: &AuthSiteCandidate, username: &str) -> u32 {
    let want = username.trim().to_ascii_lowercase();
    if want.is_empty() {
        return 0;
    }

    if let Some(ref account_raw) = candidate.account {
        let acct = account_raw.trim().to_ascii_lowercase();
        if acct == want {
            return 100;
        }
        // Whitespace / punctuation token match (keeps `-`, `_`, `.`, `@` intact so
        // `yucheng123` never spuriously matches `yucheng123-sub`).
        let token_exact = acct
            .split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | ':'))
            .filter(|tok| !tok.is_empty())
            .any(|tok| tok == want);
        if token_exact {
            return 85;
        }
        // Email local-part match when caller passes local username without domain.
        if !want.contains('@')
            && acct
                .split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';'))
                .filter_map(|tok| tok.split_once('@').map(|(local, _)| local))
                .any(|local| local == want)
        {
            return 75;
        }
        if acct.contains(&want) {
            return 60;
        }
    }

    let site_lower = candidate.site.to_ascii_lowercase();
    if site_lower == want {
        return 70;
    }
    if site_lower.contains(&want) {
        return 50;
    }
    0
}

fn build_matched_response(
    query_host: Option<String>,
    candidate: AuthSiteCandidate,
    reason: &str,
) -> ResolveAuthSiteResponse {
    ResolveAuthSiteResponse {
        matched: true,
        reason: reason.to_owned(),
        query_host,
        site: Some(candidate.site.clone()),
        issuer: candidate.issuer.clone(),
        account: candidate.account.clone(),
        domains: candidate.domains.clone(),
        totp_env_key: candidate.totp_env_key.clone(),
        username_env_key: candidate.username_env_key.clone(),
        password_env_key: candidate.password_env_key.clone(),
        tws_env_key: candidate.tws_env_key.clone(),
        related_env_keys: candidate.related_env_keys.clone(),
        env_file: candidate.env_file.clone(),
        second_factor_type: candidate.second_factor_type.clone(),
        auth_flow: candidate.auth_flow.clone(),
        app_recipe: candidate.app_recipe.clone(),
        desktop_recipe: candidate.desktop_recipe.clone(),
        min_remaining_secs: candidate.min_remaining_secs,
        press_enter: candidate.press_enter,
        sms_config: candidate.sms_config.clone(),
        auth_template: candidate.auth_template.clone(),
        candidates: vec![candidate],
    }
}

fn build_unmatched_response(
    reason: &str,
    query_host: Option<String>,
    candidates: Vec<AuthSiteCandidate>,
) -> ResolveAuthSiteResponse {
    ResolveAuthSiteResponse {
        matched: false,
        reason: reason.to_owned(),
        query_host,
        site: None,
        issuer: None,
        account: None,
        domains: Vec::new(),
        totp_env_key: None,
        username_env_key: None,
        password_env_key: None,
        tws_env_key: None,
        related_env_keys: Vec::new(),
        env_file: None,
        second_factor_type: None,
        auth_flow: None,
        app_recipe: None,
        desktop_recipe: None,
        min_remaining_secs: None,
        press_enter: None,
        sms_config: None,
        auth_template: None,
        candidates,
    }
}

/// Resolve sanitized site authentication metadata from `config_dir`.
pub fn resolve_auth_site_in_dir(
    config_dir: &Path,
    input: &ResolveAuthSiteInput,
) -> anyhow::Result<ResolveAuthSiteResponse> {
    let all_sites = load_candidates(config_dir)?;
    let url_arg = opt_trimmed(input.url.as_deref());
    let username_arg = opt_trimmed(input.username.as_deref());
    let query_arg = opt_trimmed(input.query.as_deref());

    let query_host = url_arg.as_deref().and_then(extract_url_host);

    if all_sites.is_empty() {
        return Ok(build_unmatched_response(
            "no_sites_configured",
            query_host,
            Vec::new(),
        ));
    }

    if url_arg.is_none() && username_arg.is_none() && query_arg.is_none() {
        return Ok(build_unmatched_response(
            "listed_all_sites",
            None,
            all_sites,
        ));
    }

    let mut pool: Vec<(u32, AuthSiteCandidate)> = all_sites
        .into_iter()
        .map(|c| (0_u32, c))
        .collect();

    if let Some(ref raw_url) = url_arg {
        let Some(ref host) = query_host else {
            return Ok(build_unmatched_response("invalid_url", None, Vec::new()));
        };
        let mut url_scored: Vec<(u32, AuthSiteCandidate)> = pool
            .into_iter()
            .filter_map(|(_, cand)| {
                let s = score_url_candidate(&cand, host);
                (s > 0).then_some((s, cand))
            })
            .collect();
        if url_scored.is_empty() {
            // Keep `raw_url` unused in response so query params/userinfo are never echoed.
            let _ = raw_url;
            return Ok(build_unmatched_response("no_match", query_host, Vec::new()));
        }
        let max_score = url_scored.iter().map(|(s, _)| *s).max().unwrap_or(0);
        // Keep exact/subdomain matches isolated from weaker cross-TLD fallbacks.
        let min_keep = if max_score >= 90 { 90 } else { max_score };
        url_scored.retain(|(s, _)| *s >= min_keep);
        url_scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.site.cmp(&b.1.site)));
        pool = url_scored;
    }

    if let Some(ref query) = query_arg {
        let mut query_scored: Vec<(u32, u32, AuthSiteCandidate)> = pool
            .into_iter()
            .filter_map(|(prev, cand)| {
                let qs = score_query_candidate(&cand, query);
                (qs > 0).then_some((qs, prev + qs, cand))
            })
            .collect();
        if query_scored.is_empty() {
            return Ok(build_unmatched_response("no_match", query_host, Vec::new()));
        }
        let max_qs = query_scored.iter().map(|(qs, _, _)| *qs).max().unwrap_or(0);
        if max_qs >= 100 {
            query_scored.retain(|(qs, _, _)| *qs >= 100);
        }
        query_scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.site.cmp(&b.2.site)));
        pool = query_scored
            .into_iter()
            .map(|(_, total, cand)| (total, cand))
            .collect();
    }

    if let Some(ref username) = username_arg {
        let user_scored: Vec<(u32, AuthSiteCandidate)> = pool
            .iter()
            .map(|(_, cand)| (score_username_candidate(cand, username), cand.clone()))
            .collect();
        let max_user = user_scored.iter().map(|(s, _)| *s).max().unwrap_or(0);
        if max_user == 0 {
            let domain_candidates = if url_arg.is_some() {
                pool.into_iter().map(|(_, c)| c).collect()
            } else {
                Vec::new()
            };
            return Ok(build_unmatched_response(
                "username_not_matched",
                query_host,
                domain_candidates,
            ));
        }
        pool = user_scored
            .into_iter()
            .filter(|(s, _)| *s == max_user)
            .collect();
    }

    let candidates: Vec<AuthSiteCandidate> = pool.into_iter().map(|(_, c)| c).collect();
    match candidates.len() {
        0 => Ok(build_unmatched_response("no_match", query_host, Vec::new())),
        1 => {
            let single = candidates.into_iter().next().expect("len == 1");
            Ok(build_matched_response(query_host, single, "matched"))
        }
        _ => Ok(build_unmatched_response(
            "multiple_candidates",
            query_host,
            candidates,
        )),
    }
}

fn format_summary_text(resp: &ResolveAuthSiteResponse) -> String {
    if resp.matched {
        let site = resp.site.as_deref().unwrap_or("unknown");
        let mut details = Vec::new();
        if let Some(ref account) = resp.account {
            details.push(format!("account={account}"));
        }
        if let Some(ref factor) = resp.second_factor_type {
            details.push(format!("2fa={factor}"));
        }
        if let Some(ref key) = resp.totp_env_key {
            details.push(format!("totp_env_key={key}"));
        }
        if let Some(ref key) = resp.username_env_key {
            details.push(format!("username_env_key={key}"));
        }
        if let Some(ref key) = resp.password_env_key {
            details.push(format!("password_env_key={key}"));
        }
        if let Some(ref flow) = resp.auth_flow {
            details.push(format!("auth_flow={flow}"));
        }
        if let Some(ref recipe) = resp.app_recipe {
            details.push(format!("app_recipe={}:{}", recipe.app_id, recipe.flow));
        }
        if let Some(ref sms) = resp.sms_config {
            if let Some(ref voice_url) = sms.voice_url {
                details.push(format!("voice_url={voice_url}"));
            }
        }
        if let Some(ref env_file) = resp.env_file {
            details.push(format!("env_file={env_file}"));
        }
        format!("Matched auth site '{site}' ({})", details.join(", "))
    } else if resp.candidates.is_empty() {
        format!(
            "No matching auth site found (reason={}{})",
            resp.reason,
            resp.query_host
                .as_deref()
                .map(|h| format!(", host={h}"))
                .unwrap_or_default()
        )
    } else {
        let preview: Vec<String> = resp
            .candidates
            .iter()
            .take(10)
            .map(|c| {
                let acct = c.account.as_deref().unwrap_or("-");
                let key = c
                    .totp_env_key
                    .as_deref()
                    .or(c.username_env_key.as_deref())
                    .or(c.second_factor_type.as_deref())
                    .unwrap_or("-");
                format!("{} (account={}, key={})", c.site, acct, key)
            })
            .collect();
        let more = if resp.candidates.len() > 10 {
            format!(" (+{} more)", resp.candidates.len() - 10)
        } else {
            String::new()
        };
        format!(
            "Found {} auth site candidate(s) (reason={}): {}{}",
            resp.candidates.len(),
            resp.reason,
            preview.join("; "),
            more
        )
    }
}

// ── MCP Tool Definition ──────────────────────────────────────────────────────

pub struct ResolveAuthSiteTool;

static RESOLVE_AUTH_SITE_DEF: OnceLock<ToolDef> = OnceLock::new();

impl ResolveAuthSiteTool {
    fn tool_def() -> &'static ToolDef {
        RESOLVE_AUTH_SITE_DEF.get_or_init(|| ToolDef {
            name: "resolve_auth_site".into(),
            description: "Resolve sanitized site authentication and 2FA metadata (CUA_YCWANG_* \
                env key names, env_file path, second_factor_type, auth_flow, app_recipe, \
                sms_config, and account candidates) from local cua-ycwang auth registries \
                (including google_voice.json) by URL/domain, username, or query. Read-only; \
                never reads or exposes secret values, passwords, TOTP seeds, otpauth URIs, \
                or codes."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Current page URL or domain/hostname to match against registered auth sites (e.g. 'https://www.interactivebrokers.com.au/sso/Login')."
                    },
                    "username": {
                        "type": "string",
                        "description": "Optional username or account label visible on the page (e.g. 'yucheng123') to disambiguate sites with multiple accounts."
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional keyword filter (site_id, issuer, domain, account, or env_key name) to search or list matching site metadata when url is omitted."
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
}

#[async_trait]
impl Tool for ResolveAuthSiteTool {
    fn def(&self) -> &ToolDef {
        Self::tool_def()
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let input = match parse_typed_input::<ResolveAuthSiteInput>("resolve_auth_site", args) {
            Ok(input) => input,
            Err(result) => return result,
        };
        let Some(config_dir) = crate::ycwang_env::config_dir() else {
            return ToolResult::error(
                "resolve_auth_site failed: could not resolve cua-ycwang config directory",
            );
        };
        match tokio::task::spawn_blocking(move || resolve_auth_site_in_dir(&config_dir, &input))
            .await
        {
            Ok(Ok(response)) => {
                let text = format_summary_text(&response);
                match serde_json::to_value(&response) {
                    Ok(structured) => ToolResult::text(text).with_structured(structured),
                    Err(e) => {
                        ToolResult::error(format!("resolve_auth_site serialization failed: {e}"))
                    }
                }
            }
            Ok(Err(e)) => ToolResult::error(format!("resolve_auth_site failed: {e:#}")),
            Err(e) => ToolResult::error(format!("resolve_auth_site panicked: {e}")),
        }
    }
}

// ── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Content;
    use crate::tool::ToolRegistry;

    const FAKE_TOTP_SEED_A: &str = "JBSWY3DPEHPK3PXPFAKE";
    const FAKE_TOTP_SEED_B: &str = "GEZDGNBVGY3TQOJQFAKE";
    const FAKE_PASSWORD_VAL: &str = "Ultra$ecretFakePass_98765!";
    const FAKE_USERNAME_VAL: &str = "SecretFakeLoginUser_42";
    const FAKE_OTPAUTH_URI: &str = "otpauth://totp/Example:fake?secret=JBSWY3DPEHPK3PXPFAKE&issuer=Example";

    fn write_fixture_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let env_dir = dir.path().join("env");
        std::fs::create_dir_all(&env_dir).unwrap();

        std::fs::write(
            env_dir.join("secrets.env"),
            format!(
                "# Synthetic test secrets — must NEVER appear in tool output\n\
                 export CUA_YCWANG_IBKR_YUCHENG123_TOTP_SECRET=\"{FAKE_TOTP_SEED_A}\"\n\
                 CUA_YCWANG_IBKR_YUCHENG123_SUB_TOTP_SECRET='{FAKE_TOTP_SEED_B}'\n\
                 CUA_YCWANG_TWS_PAPER_TOTP_SECRET={FAKE_OTPAUTH_URI}\n\
                 CUA_YCWANG_GITHUB_TOTP_SECRET={FAKE_TOTP_SEED_A}\n\
                 CUA_YCWANG_GITHUB_USERNAME={FAKE_USERNAME_VAL}\n\
                 CUA_YCWANG_GITHUB_PASSWORD='{FAKE_PASSWORD_VAL}'\n\
                 NON_PREFIXED_SECRET=SHOULD_BE_IGNORED_TOTALLY\n"
            ),
        )
        .unwrap();

        std::fs::write(
            dir.path().join(AUTH_SITES_FILENAME),
            serde_json::to_string_pretty(&json!({
                "schema_version": 1,
                "defaults": {
                    "totp": {
                        "min_remaining_secs": 4,
                        "press_enter": true
                    },
                    "sms_google_voice": {
                        "voice_url": "https://voice.google.com/u/0/messages",
                        "primary_number": "+13022527984",
                        "fallback_numbers": ["+13026350785"]
                    }
                },
                "sites": [
                    {
                        "site_id": "github",
                        "issuer": "GitHub",
                        "account": "YuchengWang",
                        "domains": ["github.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_GITHUB_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_github",
                        "secret": FAKE_TOTP_SEED_A,
                        "password": FAKE_PASSWORD_VAL
                    },
                    {
                        "site_id": "ibkr_yucheng123",
                        "issuer": "Interactive Brokers",
                        "account": "yucheng123",
                        "domains": ["interactivebrokers.com", "ibkr.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_IBKR_YUCHENG123_TOTP_SECRET",
                        "tws_env_key": "CUA_YCWANG_TWS_PAPER_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_ibkr_yucheng123",
                        "desktop_recipe": {
                            "app_id": "tws",
                            "flow": "login_2fa_totp"
                        }
                    },
                    {
                        "site_id": "ibkr_yucheng123_sub",
                        "issuer": "Interactive Brokers",
                        "account": "yucheng123-sub",
                        "domains": ["interactivebrokers.com", "ibkr.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_IBKR_YUCHENG123_SUB_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_ibkr_yucheng123_sub"
                    },
                    {
                        "site_id": "aws",
                        "issuer": "Amazon Web Services",
                        "account": "GoogleAuthenticator@419644307354",
                        "domains": ["signin.aws.amazon.com", "console.aws.amazon.com", "aws.amazon.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_AWS_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_aws"
                    },
                    {
                        "site_id": "idme",
                        "issuer": "ID.me",
                        "account": "wfing123@gmail.com",
                        "domains": ["api.id.me", "id.me"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_IDME_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_idme"
                    },
                    {
                        "site_id": "wise_1",
                        "issuer": "Wise",
                        "account": "wfing123@gmail.com (1)",
                        "domains": ["wise.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_WISE_1_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_wise_1"
                    },
                    {
                        "site_id": "wise_2",
                        "issuer": "Wise",
                        "account": "wfing123@gmail.com (2)",
                        "domains": ["wise.com"],
                        "auth_method": "totp",
                        "env_key": "CUA_YCWANG_WISE_2_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_wise_2"
                    },
                    {
                        "site_id": "bankofamerica",
                        "issuer": "Bank of America",
                        "domains": ["bankofamerica.com", "secure.bankofamerica.com"],
                        "auth_method": "sms_google_voice",
                        "sender_hints": ["73981", "BofA"]
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        std::fs::write(
            dir.path().join(TOTP_SITES_FILENAME),
            serde_json::to_string_pretty(&json!({
                "schema_version": 1,
                "sites": [
                    {
                        "site_id": "legacy_only_site",
                        "issuer": "Legacy Site",
                        "account": "legacy_user",
                        "domains": ["legacy.example.org"],
                        "env_key": "CUA_YCWANG_LEGACY_TOTP_SECRET",
                        "chrome_flow": "2fa_totp_legacy"
                    },
                    {
                        "site_id": "bad_prefix_site",
                        "issuer": "Bad Prefix",
                        "account": "bad",
                        "domains": ["badprefix.example.com"],
                        "env_key": "UNSAFE_RAW_KEY_NAME"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        std::fs::write(
            dir.path().join(AUTH_TEMPLATES_FILENAME),
            serde_json::to_string_pretty(&json!({
                "schema_version": 1,
                "templates": {
                    "totp": {
                        "auth_method": "totp",
                        "safety_level": "auth_only",
                        "zero_plaintext_policy": true,
                        "execution_order": [
                            { "priority": 1, "tool": "cua-ycwang.run_app_recipe" },
                            { "priority": 2, "tool": "cua-ycwang.type_totp_from_env" }
                        ]
                    },
                    "sms_google_voice": {
                        "auth_method": "sms_google_voice",
                        "safety_level": "auth_only",
                        "steps": [
                            { "step": 2, "tools": ["chrome_devtools.select_page"] },
                            { "step": 3, "tool": "chrome_devtools.evaluate_script" }
                        ]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        dir
    }

    fn assert_no_secrets_leaked(payload: &str) {
        for forbidden in [
            FAKE_TOTP_SEED_A,
            FAKE_TOTP_SEED_B,
            FAKE_PASSWORD_VAL,
            FAKE_USERNAME_VAL,
            FAKE_OTPAUTH_URI,
            "otpauth://",
            "SHOULD_BE_IGNORED_TOTALLY",
            "NON_PREFIXED_SECRET",
        ] {
            assert!(
                !payload.contains(forbidden),
                "secret material '{forbidden}' leaked into output: {payload}"
            );
        }
    }

    #[test]
    fn url_cctld_matching_and_username_disambiguation() {
        let dir = write_fixture_dir();

        // 1) ccTLD URL without username -> returns both IBKR accounts as candidates
        let ambiguous = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://www.interactivebrokers.com.au/sso/Login?action=1&token=SECRET_URL_TOK".into()),
                username: None,
                query: None,
            },
        )
        .unwrap();
        assert!(!ambiguous.matched);
        assert_eq!(ambiguous.reason, "multiple_candidates");
        assert_eq!(
            ambiguous.query_host.as_deref(),
            Some("www.interactivebrokers.com.au")
        );
        let site_ids: Vec<&str> = ambiguous.candidates.iter().map(|c| c.site.as_str()).collect();
        assert_eq!(site_ids, vec!["ibkr_yucheng123", "ibkr_yucheng123_sub"]);
        let json_str = serde_json::to_string(&ambiguous).unwrap();
        assert!(!json_str.contains("SECRET_URL_TOK"));
        assert_no_secrets_leaked(&json_str);

        // 2) Exact username disambiguates `yucheng123` away from `yucheng123-sub`
        let primary = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://www.interactivebrokers.com.au/sso/Login".into()),
                username: Some("yucheng123".into()),
                query: None,
            },
        )
        .unwrap();
        assert!(primary.matched);
        assert_eq!(primary.site.as_deref(), Some("ibkr_yucheng123"));
        assert_eq!(
            primary.totp_env_key.as_deref(),
            Some("CUA_YCWANG_IBKR_YUCHENG123_TOTP_SECRET")
        );
        assert_eq!(
            primary.tws_env_key.as_deref(),
            Some("CUA_YCWANG_TWS_PAPER_TOTP_SECRET")
        );
        assert_eq!(
            primary.related_env_keys,
            vec!["CUA_YCWANG_TWS_PAPER_TOTP_SECRET".to_owned()]
        );
        assert_eq!(primary.second_factor_type.as_deref(), Some("totp"));
        assert_eq!(primary.auth_flow.as_deref(), Some("2fa_totp_ibkr_yucheng123"));
        assert_eq!(
            primary.app_recipe,
            Some(AppRecipeRef {
                app_id: "google-chrome".into(),
                flow: "2fa_totp_ibkr_yucheng123".into()
            })
        );
        assert_eq!(
            primary.desktop_recipe,
            Some(AppRecipeRef {
                app_id: "tws".into(),
                flow: "login_2fa_totp".into()
            })
        );
        assert!(primary
            .env_file
            .as_deref()
            .is_some_and(|p| p.ends_with("env/secrets.env")));
        assert_no_secrets_leaked(&serde_json::to_string(&primary).unwrap());

        // 3) Sub-account username resolves cleanly to `ibkr_yucheng123_sub`
        let sub = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://portal.ibkr.co.uk/Account".into()),
                username: Some("yucheng123-sub".into()),
                query: None,
            },
        )
        .unwrap();
        assert!(sub.matched);
        assert_eq!(sub.site.as_deref(), Some("ibkr_yucheng123_sub"));
        assert_eq!(
            sub.totp_env_key.as_deref(),
            Some("CUA_YCWANG_IBKR_YUCHENG123_SUB_TOTP_SECRET")
        );
    }

    #[test]
    fn prevents_false_domain_collisions_and_preserves_subdomain_scoping() {
        let dir = write_fixture_dir();

        // Retail Amazon must NOT match `aws.amazon.com`
        let retail_amazon = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://www.amazon.com/ap/signin".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!retail_amazon.matched);
        assert!(retail_amazon.candidates.is_empty());

        // Regional AWS console matches `aws.amazon.com`
        let aws_console = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://ap-southeast-2.console.aws.amazon.com/".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(aws_console.matched);
        assert_eq!(aws_console.site.as_deref(), Some("aws"));

        // `id.kraken.com` or `id.example.com` must NOT falsely match short `id.me`
        let id_collision = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://id.example.com/login".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!id_collision.matched);
        assert!(id_collision.candidates.is_empty());
    }

    #[test]
    fn infers_username_and_password_env_keys_from_secrets_env_keys_only() {
        let dir = write_fixture_dir();
        let res = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://github.com/sessions/two-factor/app".into()),
                ..Default::default()
            },
        )
        .unwrap();

        assert!(res.matched);
        assert_eq!(res.site.as_deref(), Some("github"));
        assert_eq!(
            res.totp_env_key.as_deref(),
            Some("CUA_YCWANG_GITHUB_TOTP_SECRET")
        );
        assert_eq!(
            res.username_env_key.as_deref(),
            Some("CUA_YCWANG_GITHUB_USERNAME")
        );
        assert_eq!(
            res.password_env_key.as_deref(),
            Some("CUA_YCWANG_GITHUB_PASSWORD")
        );
        assert!(res.candidates[0].env_keys_present.totp);
        assert!(res.candidates[0].env_keys_present.username);
        assert!(res.candidates[0].env_keys_present.password);

        let serialized = serde_json::to_string(&res).unwrap();
        let summary = format_summary_text(&res);
        assert_no_secrets_leaked(&serialized);
        assert_no_secrets_leaked(&summary);
    }

    #[test]
    fn fuzzy_query_and_listing_and_sms_google_voice_work() {
        let dir = write_fixture_dir();

        // Fuzzy query without url
        let wise = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                query: Some("wise".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!wise.matched);
        assert_eq!(wise.candidates.len(), 2);

        // Query + username narrows Wise
        let wise2 = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                query: Some("wise".into()),
                username: Some("wfing123@gmail.com (2)".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(wise2.matched);
        assert_eq!(wise2.site.as_deref(), Some("wise_2"));

        // Legacy totp_sites.json-only entry is included
        let legacy = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("legacy.example.org".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(legacy.matched);
        assert_eq!(legacy.site.as_deref(), Some("legacy_only_site"));
        assert_eq!(
            legacy.totp_env_key.as_deref(),
            Some("CUA_YCWANG_LEGACY_TOTP_SECRET")
        );

        // Non-CUA_YCWANG_ env_key in JSON is stripped/rejected
        let bad_prefix = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("badprefix.example.com".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(bad_prefix.matched);
        assert_eq!(bad_prefix.totp_env_key, None);

        // SMS Google Voice metadata + defaults
        let bofa = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://secure.bankofamerica.com/login/sign-in".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(bofa.matched);
        assert_eq!(bofa.site.as_deref(), Some("bankofamerica"));
        assert_eq!(bofa.second_factor_type.as_deref(), Some("sms_google_voice"));
        assert_eq!(bofa.env_file, None);
        assert_eq!(
            bofa.sms_config.as_ref().and_then(|s| s.primary_number.as_deref()),
            Some("+13022527984")
        );
        assert_eq!(
            bofa.auth_template
                .as_ref()
                .map(|t| t.recommended_tools.as_slice()),
            Some(
                &[
                    "chrome_devtools.select_page".to_owned(),
                    "chrome_devtools.evaluate_script".to_owned()
                ][..]
            )
        );

        // Empty args lists all sites
        let all = resolve_auth_site_in_dir(dir.path(), &ResolveAuthSiteInput::default()).unwrap();
        assert!(!all.matched);
        assert_eq!(all.reason, "listed_all_sites");
        assert!(all.candidates.len() >= 9);
        assert_no_secrets_leaked(&serde_json::to_string(&all).unwrap());
    }

    #[test]
    fn malformed_json_error_does_not_leak_file_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let secret_marker = "SECRET_THAT_MUST_NEVER_BE_IN_ERROR";
        std::fs::write(
            dir.path().join(AUTH_SITES_FILENAME),
            format!("{{ \"broken\": \"{secret_marker}\", "),
        )
        .unwrap();
        let err = resolve_auth_site_in_dir(dir.path(), &ResolveAuthSiteInput::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to parse"), "{err}");
        assert!(!err.contains(secret_marker), "{err}");

        // Malformed google_voice.json must also redact file contents in errors.
        let gv_dir = tempfile::tempdir().unwrap();
        let gv_secret = "GV_BROKEN_SECRET_TOKEN_999";
        std::fs::write(
            gv_dir.path().join(GOOGLE_VOICE_FILENAME),
            format!("{{ \"voice_url\": \"https://voice.google.com/u/0/messages\", \"secret\": \"{gv_secret}\", "),
        )
        .unwrap();
        let gv_err = resolve_auth_site_in_dir(gv_dir.path(), &ResolveAuthSiteInput::default())
            .unwrap_err()
            .to_string();
        assert!(gv_err.contains("failed to parse"), "{gv_err}");
        assert!(gv_err.contains(GOOGLE_VOICE_FILENAME), "{gv_err}");
        assert!(!gv_err.contains(gv_secret), "{gv_err}");
    }

    #[test]
    fn google_voice_json_merges_sms_config_supports_query_and_drops_secrets() {
        let dir = write_fixture_dir();
        let gv_secret = "GV_TOP_SECRET_COOKIE_XYZ";
        let gv_token = "GV_QUERY_TOKEN_SECRET_123";
        let gv_pass = "GV_PASS_SECRET_456";

        // Override auth_sites.json without sms_google_voice defaults so we prove
        // voice_url / primary_number / fallback_numbers / sender_hints / code_regex
        // merge directly from google_voice.json for both `sms_google_voice` and
        // `google_voice_sms` sites.
        std::fs::write(
            dir.path().join(AUTH_SITES_FILENAME),
            serde_json::to_string_pretty(&json!({
                "schema_version": 1,
                "sites": [
                    {
                        "site_id": "bankofamerica",
                        "issuer": "Bank of America",
                        "domains": ["bankofamerica.com", "secure.bankofamerica.com"],
                        "auth_method": "sms_google_voice",
                        "sender_hints": ["73981", "BofA"],
                        "code_regex": "\\b(\\d{6})\\b"
                    },
                    {
                        "site_id": "custom_sms_portal",
                        "issuer": "Custom Portal",
                        "domains": ["portal.example.net"],
                        "second_factor_type": "google_voice_sms",
                        "sender_hints": ["CustomPortal"]
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        std::fs::write(
            dir.path().join(GOOGLE_VOICE_FILENAME),
            serde_json::to_string_pretty(&json!({
                "voice_url": format!("https://user:{gv_pass}@voice.google.com/u/0/messages?token={gv_token}#frag"),
                "account": "gv-routing-profile",
                "numbers": [
                    { "e164": "+15550100100", "formatted": "(555) 010-0100" },
                    { "e164": "+15550100200", "formatted": "(555) 010-0200" },
                    { "formatted": "(555) 010-0300" }
                ],
                "sender_hints": ["GoogleVoice"],
                "code_regex": "\\b(\\d{4,8})\\b",
                "secret": gv_secret,
                "password": gv_pass,
                "cookies": ["SID=SHOULD_NOT_APPEAR"],
                "otpauth_uri": FAKE_OTPAUTH_URI
            }))
            .unwrap(),
        )
        .unwrap();

        let assert_gv_clean = |payload: &str| {
            assert_no_secrets_leaked(payload);
            for forbidden in [gv_secret, gv_token, gv_pass, "SID=SHOULD_NOT_APPEAR"] {
                assert!(
                    !payload.contains(forbidden),
                    "google_voice secret '{forbidden}' leaked into output: {payload}"
                );
            }
        };

        // 1) `query="google_voice"` resolves directly to Google Voice routing metadata
        // even when `sms_google_voice` sites exist in auth_sites.json.
        let gv = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                query: Some("google_voice".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gv.matched, "expected google_voice query to match: {gv:?}");
        assert_eq!(gv.site.as_deref(), Some("google_voice"));
        assert_eq!(gv.account.as_deref(), Some("gv-routing-profile"));
        assert_eq!(gv.second_factor_type.as_deref(), Some("sms_google_voice"));
        assert_eq!(gv.auth_flow.as_deref(), Some("sms_google_voice"));
        assert_eq!(gv.domains, vec!["voice.google.com".to_owned()]);
        let gv_sms = gv.sms_config.as_ref().expect("sms_config must be present");
        assert_eq!(
            gv_sms.voice_url.as_deref(),
            Some("https://voice.google.com/u/0/messages")
        );
        assert_eq!(gv_sms.account.as_deref(), Some("gv-routing-profile"));
        assert_eq!(gv_sms.primary_number.as_deref(), Some("+15550100100"));
        assert_eq!(
            gv_sms.fallback_numbers,
            vec!["+15550100200".to_owned(), "(555) 010-0300".to_owned()]
        );
        assert_eq!(gv_sms.sender_hints, vec!["GoogleVoice".to_owned()]);
        assert_eq!(gv_sms.code_regex.as_deref(), Some("\\b(\\d{4,8})\\b"));
        assert!(gv.auth_template.is_some());
        assert_gv_clean(&serde_json::to_string(&gv).unwrap());
        assert_gv_clean(&format_summary_text(&gv));

        // 2) URL resolution against `voice.google.com` also matches `google_voice`
        let gv_by_url = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://voice.google.com/u/0/messages".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gv_by_url.matched);
        assert_eq!(gv_by_url.site.as_deref(), Some("google_voice"));

        // 3) `bankofamerica` (`sms_google_voice`) merges google_voice.json routing
        // while keeping its site-specific sender_hints and code_regex override.
        let bofa = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://secure.bankofamerica.com/login/sign-in".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(bofa.matched);
        assert_eq!(bofa.site.as_deref(), Some("bankofamerica"));
        let bofa_sms = bofa.sms_config.as_ref().expect("bofa sms_config");
        assert_eq!(
            bofa_sms.voice_url.as_deref(),
            Some("https://voice.google.com/u/0/messages")
        );
        assert_eq!(bofa_sms.account.as_deref(), Some("gv-routing-profile"));
        assert_eq!(bofa_sms.primary_number.as_deref(), Some("+15550100100"));
        assert_eq!(
            bofa_sms.fallback_numbers,
            vec!["+15550100200".to_owned(), "(555) 010-0300".to_owned()]
        );
        assert_eq!(
            bofa_sms.sender_hints,
            vec![
                "73981".to_owned(),
                "BofA".to_owned(),
                "GoogleVoice".to_owned()
            ]
        );
        assert_eq!(bofa_sms.code_regex.as_deref(), Some("\\b(\\d{6})\\b"));
        assert_gv_clean(&serde_json::to_string(&bofa).unwrap());

        // 4) `google_voice_sms` variant also receives merged sms_config, fallback code_regex,
        // and the `sms_google_voice` auth_template.
        let portal = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some("https://portal.example.net/verify".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(portal.matched);
        assert_eq!(portal.site.as_deref(), Some("custom_sms_portal"));
        assert_eq!(portal.auth_flow.as_deref(), Some("sms_google_voice"));
        assert!(portal.auth_template.is_some());
        let portal_sms = portal.sms_config.as_ref().expect("portal sms_config");
        assert_eq!(
            portal_sms.voice_url.as_deref(),
            Some("https://voice.google.com/u/0/messages")
        );
        assert_eq!(portal_sms.primary_number.as_deref(), Some("+15550100100"));
        assert_eq!(portal_sms.code_regex.as_deref(), Some("\\b(\\d{4,8})\\b"));
        assert_gv_clean(&serde_json::to_string(&portal).unwrap());
    }

    #[tokio::test]
    async fn tool_registry_exposes_and_invokes_resolve_auth_site() {
        let mut registry = ToolRegistry::new();
        registry.register_session_tools();
        let list = registry.tools_list();
        let entry = list["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "resolve_auth_site")
            .expect("resolve_auth_site must be registered");

        assert_eq!(entry["annotations"]["readOnlyHint"], true);
        assert_eq!(entry["annotations"]["destructiveHint"], false);
        assert_eq!(entry["annotations"]["idempotentHint"], true);
        assert_eq!(entry["annotations"]["openWorldHint"], false);
        assert_eq!(entry["capabilities"], json!(["auth.site.resolve"]));
        assert_eq!(entry["risk"]["class"], json!("r2"));

        // Unknown arguments are refused at the canonical dispatch boundary.
        let refused = registry
            .invoke("resolve_auth_site", json!({"unknown_param": "x"}))
            .await;
        assert_eq!(refused.is_error, Some(true));

        // Direct tool invocation with URL containing query/userinfo secrets strips them.
        let dir = write_fixture_dir();
        let resp = resolve_auth_site_in_dir(
            dir.path(),
            &ResolveAuthSiteInput {
                url: Some(format!(
                    "https://user:{FAKE_PASSWORD_VAL}@github.com/login?token={FAKE_TOTP_SEED_A}"
                )),
                ..Default::default()
            },
        )
        .unwrap();
        let text = format_summary_text(&resp);
        assert_no_secrets_leaked(&text);
        assert_no_secrets_leaked(&serde_json::to_string(&resp).unwrap());

        // Check Content enum import stays exercised.
        let result = ToolResult::text(text);
        assert!(matches!(result.content.first(), Some(Content::Text { .. })));
    }
}
