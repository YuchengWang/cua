// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Strong-versioned `AppRecipe` foundation, `VersionGate`, and in-memory hot cache.
//!
//! Recipes are stored under `$CUA_YCWANG_CONFIG_DIR/app_recipes/` using the
//! canonical filename `<app_id>_v<version>_<fp8>.json`, where `<fp8>` is the
//! first 8 hex characters of `fingerprint_sha256`. Old recipes are never
//! overwritten across versions, and `VersionGate::verify()` blocks execution
//! with `version_mismatch` if either `app_version` or `fp8` drifts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where the application's version was detected from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionSource {
    Dpkg,
    Install4j,
    PackageJson,
    DotnetDeps,
    PeOrElf,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedShortcut {
    pub id: String,
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuEntry {
    pub path: Vec<String>,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortcut: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelativeAnchor {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_pattern: Option<String>,
    pub rel_x: f64,
    pub rel_y: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModalHandler {
    pub pattern: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Out-of-band authentication gate (never stores or returns plaintext secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthGate {
    pub kind: String,
    pub prompt_title: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub press_enter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_remaining_secs: Option<u64>,
    #[serde(default = "default_true")]
    pub zeroize_after_use: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeState {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_regex: Option<String>,
    #[serde(default)]
    pub expected_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_gate: Option<AuthGate>,
    #[serde(default)]
    pub captcha_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeTransition {
    pub from_state: String,
    pub to_state: String,
    pub action: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_for_stable_frame_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,
}

/// Primary or fallback data acquisition channel for a recipe capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DataChannel {
    Atspi,
    Cdp,
    Clipboard,
    FileExport,
    Log,
    #[default]
    WindowMeta,
    ScreenshotRoi,
    ScreenshotFull,
}

/// Execution safety tier for a capability, flow, or step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyLevel {
    #[default]
    ReadOnly,
    AuthOnly,
    Restricted,
}

impl SafetyLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::AuthOnly => "auth_only",
            Self::Restricted => "restricted",
        }
    }
}

/// Expected structured output shape for an acquired capability artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OutputSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roi_norm: Option<[f64; 4]>,
}

/// Declarative capability routing entry in [`AppRecipe::capabilities`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    pub data_channel: DataChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default)]
    pub safety_level: SafetyLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms_est: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_method: Option<DataChannel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<OutputSchema>,
}

/// Runtime safety policy enforced by `run_app_recipe` and `acquire_app_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SafetyPolicy {
    #[serde(default)]
    pub default_max_level: SafetyLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_shortcuts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_flows: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Single step in a named [`AppRecipe::flows`] sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeStep {
    pub action: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_for_stable_frame_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_level: Option<SafetyLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms_est: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateMachine {
    pub initial_state: String,
    #[serde(default)]
    pub states: Vec<RecipeState>,
    #[serde(default)]
    pub transitions: Vec<RecipeTransition>,
}

/// Strong-versioned deterministic application recipe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppRecipe {
    pub schema_version: u32,
    pub app_id: String,
    pub app_version: String,
    pub version_source: VersionSource,
    pub fingerprint_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tech_stack: Option<String>,
    #[serde(default)]
    pub atspi_blind: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_interaction: Option<String>,
    #[serde(default)]
    pub launch_isolation_hints: Vec<String>,
    #[serde(default)]
    pub verified_shortcuts: Vec<VerifiedShortcut>,
    #[serde(default)]
    pub menu_topology: Vec<MenuEntry>,
    #[serde(default)]
    pub relative_anchors: Vec<RelativeAnchor>,
    #[serde(default)]
    pub modal_handlers: Vec<ModalHandler>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub flows: HashMap<String, Vec<RecipeStep>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub capabilities: HashMap<String, CapabilitySpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_policy: Option<SafetyPolicy>,
    pub state_machine: StateMachine,
}

impl AppRecipe {
    /// First 8 hex characters of `fingerprint_sha256`.
    pub fn fp8(&self) -> &str {
        fp8_of(&self.fingerprint_sha256)
    }

    /// Canonical filename `<app_id>_v<version>_<fp8>.json`.
    pub fn canonical_filename(&self) -> String {
        canonical_recipe_filename(&self.app_id, &self.app_version, &self.fingerprint_sha256)
    }
}

/// Extract the 8-char fingerprint prefix.
pub fn fp8_of(sha256_hex: &str) -> &str {
    let len = sha256_hex.len().min(8);
    &sha256_hex[..len]
}

fn sanitize_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Build `<app_id>_v<version>_<fp8>.json` with sanitized filename components.
pub fn canonical_recipe_filename(app_id: &str, app_version: &str, sha256_hex: &str) -> String {
    let id = sanitize_component(app_id);
    let ver = sanitize_component(app_version);
    let fp = sanitize_component(fp8_of(sha256_hex));
    format!("{id}_v{ver}_{fp}.json")
}

/// Resolve `$CUA_YCWANG_CONFIG_DIR/app_recipes` (default `~/.config/cua-ycwang/app_recipes`).
pub fn recipes_dir() -> Option<PathBuf> {
    crate::ycwang_env::resolve_ycwang_config_dir().map(|d| d.join("app_recipes"))
}

/// Persist `recipe` to `<dir>/<app_id>_v<version>_<fp8>.json`.
pub fn save_recipe_to_dir(dir: &Path, recipe: &AppRecipe) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
    let path = dir.join(recipe.canonical_filename());
    let body = serde_json::to_string_pretty(recipe).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(path)
}

/// Load and deserialize an [`AppRecipe`] from disk.
pub fn load_recipe(path: &Path) -> Result<AppRecipe, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid recipe {}: {e}", path.display()))
}

/// Resolve normalized [`RelativeAnchor`] coordinates `(rel_x, rel_y)` against
/// a target window geometry `(win_x, win_y, win_w, win_h)`.
pub fn resolve_relative_anchor_xy(
    anchor: &RelativeAnchor,
    win_x: i32,
    win_y: i32,
    win_w: u32,
    win_h: u32,
) -> (i16, i16) {
    let rx = anchor.rel_x.clamp(0.0, 1.0);
    let ry = anchor.rel_y.clamp(0.0, 1.0);
    let x = (f64::from(win_x) + rx * f64::from(win_w.max(1))).round() as i16;
    let y = (f64::from(win_y) + ry * f64::from(win_h.max(1))).round() as i16;
    (x, y)
}

/// Merge a curated `<app_id>.json` overlay onto a version-pinned base recipe,
/// preserving the base's `app_version`, `version_source`, `fingerprint_sha256`,
/// and `tech_stack`.
pub fn merge_curated_overlay(base: &mut AppRecipe, overlay: &AppRecipe) {
    for (name, steps) in &overlay.flows {
        base.flows.insert(name.clone(), steps.clone());
    }
    for (name, spec) in &overlay.capabilities {
        base.capabilities.insert(name.clone(), spec.clone());
    }
    for anchor in &overlay.relative_anchors {
        if let Some(existing) = base
            .relative_anchors
            .iter_mut()
            .find(|a| a.name == anchor.name)
        {
            *existing = anchor.clone();
        } else {
            base.relative_anchors.push(anchor.clone());
        }
    }
    for handler in &overlay.modal_handlers {
        if let Some(existing) = base
            .modal_handlers
            .iter_mut()
            .find(|h| h.pattern == handler.pattern)
        {
            *existing = handler.clone();
        } else {
            base.modal_handlers.push(handler.clone());
        }
    }
    for shortcut in &overlay.verified_shortcuts {
        if let Some(existing) = base
            .verified_shortcuts
            .iter_mut()
            .find(|s| s.id == shortcut.id)
        {
            *existing = shortcut.clone();
        } else {
            base.verified_shortcuts.push(shortcut.clone());
        }
    }
    if let Some(ref ov_policy) = overlay.safety_policy {
        match base.safety_policy {
            Some(ref mut base_policy) => {
                base_policy.default_max_level = ov_policy.default_max_level;
                for s in &ov_policy.blocked_shortcuts {
                    if !base_policy.blocked_shortcuts.contains(s) {
                        base_policy.blocked_shortcuts.push(s.clone());
                    }
                }
                for f in &ov_policy.blocked_flows {
                    if !base_policy.blocked_flows.contains(f) {
                        base_policy.blocked_flows.push(f.clone());
                    }
                }
                if ov_policy.notes.is_some() {
                    base_policy.notes = ov_policy.notes.clone();
                }
            }
            None => {
                base.safety_policy = Some(ov_policy.clone());
            }
        }
    }
}

fn apply_curated_overlay_if_present(dir: &Path, base_path: &Path, recipe: &mut AppRecipe) {
    let overlay_filename = format!("{}.json", sanitize_component(&recipe.app_id));
    let overlay_path = dir.join(overlay_filename);
    if overlay_path == base_path || !overlay_path.is_file() {
        return;
    }
    if let Ok(overlay) = load_recipe(&overlay_path) {
        if overlay.app_id.eq_ignore_ascii_case(&recipe.app_id) {
            merge_curated_overlay(recipe, &overlay);
        }
    }
}

/// Find a recipe in `dir` matching `(app_id, app_version, fp8)`.
pub fn find_matching_recipe(
    dir: &Path,
    app_id: &str,
    app_version: &str,
    sha256_hex: &str,
) -> Option<AppRecipe> {
    let exact = dir.join(canonical_recipe_filename(app_id, app_version, sha256_hex));
    if exact.is_file() {
        if let Ok(mut recipe) = load_recipe(&exact) {
            apply_curated_overlay_if_present(dir, &exact, &mut recipe);
            return Some(recipe);
        }
    }
    None
}

/// Find the highest-fidelity recipe for `app_id` in `dir`, preferring exact
/// `(app_version, fp8)` matches and ranking `java_install4j` / `electron` /
/// `dotnet_avalonia` recipes above lower-fidelity `native_elf` / `vunknown`
/// fallbacks. When a version-pinned base recipe (`<app_id>_v<ver>_<fp8>.json`)
/// is matched, any curated `<app_id>.json` overlay in the same directory is
/// merged onto it.
pub fn find_best_recipe_for_app(
    dir: &Path,
    app_id: &str,
    preferred_version: Option<&str>,
    preferred_sha256: Option<&str>,
) -> Option<AppRecipe> {
    find_best_recipe_with_path(dir, app_id, preferred_version, preferred_sha256)
        .map(|(recipe, _)| recipe)
}

/// Variant of [`find_best_recipe_for_app`] that also returns the base recipe's
/// disk path for cache mtime/len tracking.
pub fn find_best_recipe_with_path(
    dir: &Path,
    app_id: &str,
    preferred_version: Option<&str>,
    preferred_sha256: Option<&str>,
) -> Option<(AppRecipe, PathBuf)> {
    if let (Some(ver), Some(sha)) = (preferred_version, preferred_sha256) {
        if ver != "unknown" {
            let exact_path = dir.join(canonical_recipe_filename(app_id, ver, sha));
            if let Some(exact) = find_matching_recipe(dir, app_id, ver, sha) {
                return Some((exact, exact_path));
            }
        }
    }

    let preferred_fp8 = preferred_sha256.map(fp8_of);
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<(i32, PathBuf, AppRecipe)> = None;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(recipe) = load_recipe(&path) else {
            continue;
        };
        if !recipe.app_id.eq_ignore_ascii_case(app_id) {
            continue;
        }
        let mut score = 0i32;
        if let Some(ver) = preferred_version.filter(|v| *v != "unknown") {
            if recipe.app_version == ver {
                score += 100;
            }
        }
        if let Some(fp8) = preferred_fp8 {
            if recipe.fp8() == fp8 {
                score += 50;
            }
        }
        match recipe.tech_stack.as_deref() {
            Some("java_install4j" | "electron" | "dotnet_avalonia") => score += 20,
            Some("native_elf") => {}
            Some(_) => score += 10,
            None => {}
        }
        if recipe.app_version != "unknown" && recipe.app_version != "seeded" {
            score += 10;
        }
        if !recipe.relative_anchors.is_empty() || !recipe.flows.is_empty() {
            score += 5;
        }
        // Prefer version-pinned base files (<app_id>_v...) over unpinned <app_id>.json
        // so the curated overlay can be cleanly merged onto the versioned base.
        let is_version_pinned = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("_v"));
        if is_version_pinned {
            score += 5;
        }

        if best
            .as_ref()
            .is_none_or(|(best_score, _, _)| score > *best_score)
        {
            best = Some((score, path, recipe));
        }
    }

    best.map(|(_, base_path, mut recipe)| {
        apply_curated_overlay_if_present(dir, &base_path, &mut recipe);
        (recipe, base_path)
    })
}

/// Machine-readable result from [`VersionGate::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerifyResult {
    Matched {
        app_id: String,
        app_version: String,
        fp8: String,
    },
    VersionMismatch {
        code: String,
        app_id: String,
        expected_version: String,
        actual_version: String,
        expected_fp8: String,
        actual_fp8: String,
        reason: String,
    },
}

impl VerifyResult {
    pub fn is_matched(&self) -> bool {
        matches!(self, Self::Matched { .. })
    }
}

/// Real-time version + binary fingerprint gate.
pub struct VersionGate;

impl VersionGate {
    /// Verify `recipe` against the live `actual_version` and `actual_sha256`.
    /// Blocks execution with `version_mismatch` if either `app_version` or `fp8` differs.
    pub fn verify(recipe: &AppRecipe, actual_version: &str, actual_sha256: &str) -> VerifyResult {
        let expected_fp8 = recipe.fp8();
        let actual_fp8 = fp8_of(actual_sha256);

        if recipe.app_version != actual_version || expected_fp8 != actual_fp8 {
            return VerifyResult::VersionMismatch {
                code: "version_mismatch".to_owned(),
                app_id: recipe.app_id.clone(),
                expected_version: recipe.app_version.clone(),
                actual_version: actual_version.to_owned(),
                expected_fp8: expected_fp8.to_owned(),
                actual_fp8: actual_fp8.to_owned(),
                reason: format!(
                    "recipe {} requires v{} ({}), but live target is v{} ({})",
                    recipe.app_id,
                    recipe.app_version,
                    expected_fp8,
                    actual_version,
                    actual_fp8
                ),
            };
        }

        VerifyResult::Matched {
            app_id: recipe.app_id.clone(),
            app_version: recipe.app_version.clone(),
            fp8: expected_fp8.to_owned(),
        }
    }
}

fn file_stamp(path: &Path) -> (Option<u128>, Option<u64>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return (None, None);
    };
    let modified_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());
    (modified_ns, Some(meta.len()))
}

fn overlay_path_for(base_path: &Path, app_id: &str) -> Option<PathBuf> {
    let dir = base_path.parent()?;
    let candidate = dir.join(format!("{}.json", sanitize_component(app_id)));
    if candidate != base_path && candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

#[derive(Clone)]
struct CachedRecipeEntry {
    recipe: Arc<AppRecipe>,
    source_path: Option<PathBuf>,
    modified_ns: Option<u128>,
    file_len: Option<u64>,
    overlay_path: Option<PathBuf>,
    overlay_modified_ns: Option<u128>,
    overlay_file_len: Option<u64>,
}

/// In-memory hot cache for verified [`AppRecipe`] instances, with automatic
/// disk `mtime` / `len` invalidation and reload.
#[derive(Default)]
pub struct AppRecipeCache {
    entries: RwLock<HashMap<String, CachedRecipeEntry>>,
}

impl AppRecipeCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(app_id: &str, app_version: &str, fp8: &str) -> String {
        format!("{app_id}:{app_version}:{fp8}")
    }

    pub fn get(&self, app_id: &str, app_version: &str, sha256_hex: &str) -> Option<Arc<AppRecipe>> {
        let key = Self::key(app_id, app_version, fp8_of(sha256_hex));
        let entry = {
            let guard = self.entries.read().ok()?;
            guard.get(&key)?.clone()
        };

        if let Some(ref src) = entry.source_path {
            let (cur_mtime, cur_len) = file_stamp(src);
            let current_overlay = overlay_path_for(src, &entry.recipe.app_id);
            let overlay_changed = match (&entry.overlay_path, &current_overlay) {
                (Some(prev), Some(cur)) if prev == cur => {
                    let (om, ol) = file_stamp(cur);
                    om != entry.overlay_modified_ns || ol != entry.overlay_file_len
                }
                (None, None) => false,
                _ => true,
            };

            if cur_mtime != entry.modified_ns || cur_len != entry.file_len || overlay_changed {
                if let Ok(mut reloaded) = load_recipe(src) {
                    if let Some(dir) = src.parent() {
                        apply_curated_overlay_if_present(dir, src, &mut reloaded);
                    }
                    let arc = self.insert_with_path(reloaded, Some(src.clone()));
                    return Some(arc);
                }
                if let Ok(mut guard) = self.entries.write() {
                    guard.remove(&key);
                }
                return None;
            }
        }

        Some(entry.recipe)
    }

    pub fn insert(&self, recipe: AppRecipe) -> Arc<AppRecipe> {
        self.insert_with_path(recipe, None)
    }

    pub fn insert_with_path(
        &self,
        recipe: AppRecipe,
        source_path: Option<PathBuf>,
    ) -> Arc<AppRecipe> {
        let key = Self::key(&recipe.app_id, &recipe.app_version, recipe.fp8());
        let (modified_ns, file_len) = source_path
            .as_deref()
            .map(file_stamp)
            .unwrap_or((None, None));
        let overlay_path = source_path
            .as_deref()
            .and_then(|p| overlay_path_for(p, &recipe.app_id));
        let (overlay_modified_ns, overlay_file_len) = overlay_path
            .as_deref()
            .map(file_stamp)
            .unwrap_or((None, None));
        let arc = Arc::new(recipe);
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(
                key,
                CachedRecipeEntry {
                    recipe: Arc::clone(&arc),
                    source_path,
                    modified_ns,
                    file_len,
                    overlay_path,
                    overlay_modified_ns,
                    overlay_file_len,
                },
            );
        }
        arc
    }

    pub fn invalidate(&self, app_id: &str, app_version: &str, sha256_hex: &str) {
        let key = Self::key(app_id, app_version, fp8_of(sha256_hex));
        if let Ok(mut guard) = self.entries.write() {
            guard.remove(&key);
        }
    }
}

/// Process-wide shared [`AppRecipeCache`].
pub fn global_recipe_cache() -> &'static AppRecipeCache {
    static CACHE: OnceLock<AppRecipeCache> = OnceLock::new();
    CACHE.get_or_init(AppRecipeCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_recipe(version: &str, sha: &str) -> AppRecipe {
        AppRecipe {
            schema_version: 1,
            app_id: "tws".to_owned(),
            app_version: version.to_owned(),
            version_source: VersionSource::Install4j,
            fingerprint_sha256: sha.to_owned(),
            tech_stack: Some("java_install4j".to_owned()),
            atspi_blind: false,
            recommended_interaction: Some("visual_grounding_plus_hotkeys".to_owned()),
            launch_isolation_hints: Vec::new(),
            verified_shortcuts: vec![VerifiedShortcut {
                id: "order_ticket".to_owned(),
                keys: vec!["ctrl".to_owned(), "o".to_owned()],
                description: Some("Open order ticket".to_owned()),
                source: "manifest".to_owned(),
            }],
            menu_topology: vec![MenuEntry {
                path: vec!["File".to_owned(), "Exit".to_owned()],
                label: "Exit".to_owned(),
                shortcut: Some("Ctrl+Q".to_owned()),
                role: Some("menu item".to_owned()),
            }],
            relative_anchors: Vec::new(),
            modal_handlers: vec![ModalHandler {
                pattern: ".*Tip of the Day.*".to_owned(),
                action: "press_key".to_owned(),
                key: Some("Escape".to_owned()),
            }],
            flows: HashMap::new(),
            capabilities: HashMap::new(),
            safety_policy: None,
            state_machine: StateMachine {
                initial_state: "login".to_owned(),
                states: vec![RecipeState {
                    id: "login".to_owned(),
                    description: Some("Login window".to_owned()),
                    title_regex: Some(".*Login.*".to_owned()),
                    expected_roles: vec!["text".to_owned(), "password text".to_owned()],
                    auth_gate: None,
                    captcha_patterns: vec!["Verify you are human".to_owned()],
                }],
                transitions: Vec::new(),
            },
        }
    }

    #[test]
    fn canonical_filename_and_versioned_storage_never_overwrite_old_versions() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = sample_recipe("10.52.1d", "abcdef1234567890");
        let r2 = sample_recipe("10.53.0a", "fedcba9876543210");

        let p1 = save_recipe_to_dir(dir.path(), &r1).unwrap();
        let p2 = save_recipe_to_dir(dir.path(), &r2).unwrap();

        assert_eq!(
            p1.file_name().unwrap().to_str().unwrap(),
            "tws_v10.52.1d_abcdef12.json"
        );
        assert_eq!(
            p2.file_name().unwrap().to_str().unwrap(),
            "tws_v10.53.0a_fedcba98.json"
        );
        assert!(p1.exists() && p2.exists());
        assert_eq!(load_recipe(&p1).unwrap(), r1);
        assert_eq!(
            find_matching_recipe(dir.path(), "tws", "10.52.1d", "abcdef1299999999"),
            Some(r1)
        );
    }

    #[test]
    fn version_gate_blocks_version_or_fingerprint_mismatch() {
        let recipe = sample_recipe("10.52.1d", "abcdef1234567890");

        assert!(VersionGate::verify(&recipe, "10.52.1d", "abcdef12ffffffff").is_matched());

        let ver_err = VersionGate::verify(&recipe, "10.53.0a", "abcdef1234567890");
        assert!(!ver_err.is_matched());
        let val = serde_json::to_value(&ver_err).unwrap();
        assert_eq!(val["status"], "version_mismatch");
        assert_eq!(val["code"], "version_mismatch");

        let fp_err = VersionGate::verify(&recipe, "10.52.1d", "0000000034567890");
        assert!(!fp_err.is_matched());
    }

    #[test]
    fn hot_cache_stores_and_invalidates_by_version_and_fp8() {
        let cache = AppRecipeCache::new();
        let recipe = sample_recipe("7.25.1", "1122334455667788");
        cache.insert(recipe.clone());

        assert_eq!(
            cache
                .get("tws", "7.25.1", "1122334400000000")
                .as_deref(),
            Some(&recipe)
        );
        assert!(cache.get("tws", "7.25.2", "1122334400000000").is_none());

        cache.invalidate("tws", "7.25.1", "11223344");
        assert!(cache.get("tws", "7.25.1", "11223344").is_none());
    }

    #[test]
    fn find_best_recipe_prefers_java_install4j_over_native_elf_vunknown() {
        let dir = tempfile::tempdir().unwrap();
        let mut native = sample_recipe("unknown", "26b5c011727a1194");
        native.app_id = "thinkorswim".to_owned();
        native.version_source = VersionSource::PeOrElf;
        native.tech_stack = Some("native_elf".to_owned());
        save_recipe_to_dir(dir.path(), &native).unwrap();

        let mut java = sample_recipe("1994.1.16", "deadbeef12345678");
        java.app_id = "thinkorswim".to_owned();
        java.version_source = VersionSource::Install4j;
        java.tech_stack = Some("java_install4j".to_owned());
        save_recipe_to_dir(dir.path(), &java).unwrap();

        let picked = find_best_recipe_for_app(dir.path(), "thinkorswim", Some("unknown"), None)
            .expect("should find a recipe");
        assert_eq!(picked.tech_stack.as_deref(), Some("java_install4j"));
        assert_eq!(picked.app_version, "1994.1.16");
    }

    #[test]
    fn resolve_relative_anchor_xy_maps_normalized_coords_to_window_geometry() {
        let anchor = RelativeAnchor {
            name: "charts_tab".to_owned(),
            role: Some("tab".to_owned()),
            title_pattern: None,
            rel_x: 0.25,
            rel_y: 0.5,
        };
        assert_eq!(resolve_relative_anchor_xy(&anchor, 100, 50, 1000, 800), (350, 450));
    }

    #[test]
    fn cache_invalidates_and_reloads_when_mtime_or_len_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut r1 = sample_recipe("1994.1.16", "6f8008dc00000000");
        r1.app_id = "thinkorswim".to_owned();
        let path = save_recipe_to_dir(dir.path(), &r1).unwrap();

        let cache = AppRecipeCache::new();
        cache.insert_with_path(r1.clone(), Some(path.clone()));
        assert_eq!(
            cache.get("thinkorswim", "1994.1.16", "6f8008dc").unwrap().flows.len(),
            0
        );

        // Modify file on disk (length & mtime change)
        std::thread::sleep(std::time::Duration::from_millis(15));
        let mut r2 = r1;
        r2.flows.insert(
            "workspace_check".to_owned(),
            vec![RecipeStep {
                action: "verify_window_count_min".to_owned(),
                args: serde_json::json!({ "min": 1 }),
                wait_for_stable_frame_ms: None,
                description: None,
                method: Some("window_meta".to_owned()),
                safety_level: Some(SafetyLevel::ReadOnly),
                latency_ms_est: Some(20),
                fallback_method: None,
            }],
        );
        save_recipe_to_dir(dir.path(), &r2).unwrap();

        let reloaded = cache.get("thinkorswim", "1994.1.16", "6f8008dc").unwrap();
        assert_eq!(reloaded.flows.len(), 1);
        assert!(reloaded.flows.contains_key("workspace_check"));
    }

    #[test]
    fn find_best_recipe_merges_curated_overlay_onto_version_pinned_base() {
        let dir = tempfile::tempdir().unwrap();
        let mut base = sample_recipe("1994.1.16", "6f8008dc11112222");
        base.app_id = "thinkorswim".to_owned();
        base.tech_stack = Some("java_install4j".to_owned());
        base.relative_anchors.push(RelativeAnchor {
            name: "charts_tab".to_owned(),
            role: Some("tab".to_owned()),
            title_pattern: None,
            rel_x: 0.1,
            rel_y: 0.1,
        });
        save_recipe_to_dir(dir.path(), &base).unwrap();

        let mut overlay = sample_recipe("seeded", "seeded");
        overlay.app_id = "thinkorswim".to_owned();
        overlay.tech_stack = Some("overlay_stack".to_owned());
        overlay.relative_anchors.push(RelativeAnchor {
            name: "charts_tab".to_owned(),
            role: Some("tab".to_owned()),
            title_pattern: None,
            rel_x: 0.33,
            rel_y: 0.03,
        });
        overlay.flows.insert(
            "curated_flow".to_owned(),
            vec![RecipeStep {
                action: "wait_for_stable_frame".to_owned(),
                args: serde_json::json!({ "ms": 100 }),
                wait_for_stable_frame_ms: None,
                description: None,
                method: None,
                safety_level: None,
                latency_ms_est: None,
                fallback_method: None,
            }],
        );
        overlay.capabilities.insert(
            "workspace_health".to_owned(),
            CapabilitySpec {
                data_channel: DataChannel::WindowMeta,
                flow: Some("curated_flow".to_owned()),
                safety_level: SafetyLevel::ReadOnly,
                latency_ms_est: Some(50),
                artifact_path: None,
                fallback_method: Some(DataChannel::ScreenshotRoi),
                fallback_capability: None,
                output_schema: None,
            },
        );
        overlay.safety_policy = Some(SafetyPolicy {
            default_max_level: SafetyLevel::ReadOnly,
            blocked_shortcuts: vec!["ctrl+enter".to_owned()],
            blocked_flows: vec!["submit_order".to_owned()],
            notes: Some("no order submission".to_owned()),
        });
        std::fs::write(
            dir.path().join("thinkorswim.json"),
            serde_json::to_string_pretty(&overlay).unwrap(),
        )
        .unwrap();

        let merged = find_best_recipe_for_app(
            dir.path(),
            "thinkorswim",
            Some("1994.1.16"),
            Some("6f8008dc11112222"),
        )
        .expect("merged recipe");

        // Base identity preserved
        assert_eq!(merged.app_version, "1994.1.16");
        assert_eq!(merged.fingerprint_sha256, "6f8008dc11112222");
        assert_eq!(merged.tech_stack.as_deref(), Some("java_install4j"));
        // Overlay merged
        assert!(merged.flows.contains_key("curated_flow"));
        assert!(merged.capabilities.contains_key("workspace_health"));
        assert_eq!(merged.relative_anchors[0].rel_x, 0.33);
        assert_eq!(
            merged.safety_policy.as_ref().unwrap().blocked_flows,
            vec!["submit_order".to_owned()]
        );
    }

    #[test]
    fn backward_compatible_deserialization_and_capability_safety_schema() {
        let legacy_json = serde_json::json!({
            "schema_version": 1,
            "app_id": "legacy_app",
            "app_version": "1.0.0",
            "version_source": "unknown",
            "fingerprint_sha256": "deadbeef",
            "flows": {
                "ping": [{ "action": "wait_for_stable_frame", "args": { "ms": 10 } }]
            },
            "state_machine": {
                "initial_state": "ready",
                "states": [],
                "transitions": []
            }
        });
        let parsed: AppRecipe = serde_json::from_value(legacy_json).unwrap();
        assert!(parsed.capabilities.is_empty());
        assert!(parsed.safety_policy.is_none());
        assert!(SafetyLevel::ReadOnly < SafetyLevel::AuthOnly);
        assert!(SafetyLevel::AuthOnly < SafetyLevel::Restricted);
    }
}
