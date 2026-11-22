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

/// Find a recipe in `dir` matching `(app_id, app_version, fp8)`.
pub fn find_matching_recipe(
    dir: &Path,
    app_id: &str,
    app_version: &str,
    sha256_hex: &str,
) -> Option<AppRecipe> {
    let exact = dir.join(canonical_recipe_filename(app_id, app_version, sha256_hex));
    if exact.is_file() {
        if let Ok(recipe) = load_recipe(&exact) {
            return Some(recipe);
        }
    }
    None
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

/// In-memory hot cache for verified [`AppRecipe`] instances.
#[derive(Default)]
pub struct AppRecipeCache {
    entries: RwLock<HashMap<String, Arc<AppRecipe>>>,
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
        let guard = self.entries.read().ok()?;
        guard.get(&key).cloned()
    }

    pub fn insert(&self, recipe: AppRecipe) -> Arc<AppRecipe> {
        let key = Self::key(&recipe.app_id, &recipe.app_version, recipe.fp8());
        let arc = Arc::new(recipe);
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(key, Arc::clone(&arc));
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
}
