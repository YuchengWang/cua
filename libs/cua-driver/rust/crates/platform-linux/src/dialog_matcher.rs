// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Configuration-driven native dialog matcher & executor (`dialog_rules.json`).
//!
//! Hot-reloads `~/.config/cua-ycwang/dialog_rules.json` using `mtime + len`
//! caching (via [`crate::hot_config::HotJsonCache`]) and shares AT-SPI tree
//! predicates with [`crate::browser_consent_ui`].

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cua_driver_core::delivery::FocusPolicy;
use cua_driver_core::ycwang_env::resolve_ycwang_config_dir;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::atspi::AtspiNode;
use crate::hot_config::HotJsonCache;
use crate::interaction::{session_policy, with_target_foreground};
use crate::tools::mcp_type_secret::{
    resolve_secret_from_env, type_secret_into_context, validate_env_key,
};
use crate::x11::context::{global_screen_pool, DisplayTarget};

pub const DIALOG_RULES_FILENAME: &str = "dialog_rules.json";
const DEFAULT_WAIT_MS: u64 = 5_000;
const MIN_WAIT_MS: u64 = 100;
const MAX_WAIT_MS: u64 = 30_000;
const DEFAULT_VERIFY_MS: u64 = 2_000;

fn default_true() -> bool {
    true
}

fn default_root_roles() -> Vec<String> {
    vec!["alert".into(), "dialog".into()]
}

fn default_button_roles() -> Vec<String> {
    vec!["push button".into(), "button".into()]
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DialogRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, alias = "WM_CLASS", skip_serializing_if = "Option::is_none")]
    pub wm_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_regex: Option<String>,
    #[serde(default = "default_root_roles")]
    pub root_roles: Vec<String>,
    #[serde(default = "default_true")]
    pub exclude_web_content: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_regex: Option<String>,
    #[serde(default = "default_button_roles")]
    pub button_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_name_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_button_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_button_index: Option<usize>,
    #[serde(default)]
    pub focus_policy: FocusPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_role_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub press_enter: Option<bool>,
    #[serde(default = "default_true")]
    pub verify_disappeared: bool,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DialogRulesFile {
    Array(Vec<DialogRule>),
    Object {
        #[serde(default)]
        rules: Vec<DialogRule>,
    },
}

static DIALOG_RULES_CACHE: HotJsonCache<DialogRulesFile> = HotJsonCache::new();

pub fn default_dialog_rules_path() -> Option<PathBuf> {
    resolve_ycwang_config_dir().map(|dir| dir.join(DIALOG_RULES_FILENAME))
}

pub fn load_dialog_rules_from_path(path: &Path) -> anyhow::Result<Option<Vec<DialogRule>>> {
    let loaded = DIALOG_RULES_CACHE.get_or_load(path)?;
    Ok(loaded.map(|cfg| {
        let mut rules = match &*cfg {
            DialogRulesFile::Array(r) => r.clone(),
            DialogRulesFile::Object { rules } => rules.clone(),
        };
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        rules
    }))
}

pub fn load_dialog_rules() -> anyhow::Result<Vec<DialogRule>> {
    if let Some(path) = default_dialog_rules_path() {
        if let Some(rules) = load_dialog_rules_from_path(&path)? {
            return Ok(rules);
        }
    }
    Ok(builtin_default_rules())
}

pub fn builtin_default_rules() -> Vec<DialogRule> {
    vec![DialogRule {
        id: "chrome_remote_debugging_en".into(),
        description: Some("Fallback rule for English Chrome remote-debugging consent prompt".into()),
        wm_class: Some("(?i)chrome|chromium".into()),
        title_regex: None,
        root_roles: vec!["alert".into()],
        exclude_web_content: true,
        heading_regex: Some("(?i)Allow remote debugging".into()),
        body_regex: None,
        button_roles: default_button_roles(),
        button_name_regex: Some("(?i)^Allow$".into()),
        exclude_names: vec!["Cancel".into(), "Turn off".into()],
        expected_button_count: Some(3),
        target_button_index: Some(0),
        focus_policy: FocusPolicy::Default,
        env_key: None,
        env_file: None,
        input_role_regex: None,
        press_enter: None,
        verify_disappeared: true,
        priority: 10,
    }]
}

// ── Shared AT-SPI tree predicates (also used by browser_consent_ui) ───────────

pub(crate) fn role_is(node: &AtspiNode, accepted: &[&str]) -> bool {
    let role = node.role.trim().to_ascii_lowercase();
    accepted
        .iter()
        .any(|candidate| role == candidate.trim().to_ascii_lowercase())
}

pub(crate) fn is_in_web_content(nodes: &[AtspiNode], node: &AtspiNode) -> bool {
    let mut parent = node.parent_element_index;
    for _ in 0..nodes.len() {
        let Some(parent_index) = parent else {
            return false;
        };
        let Some(parent_node) = nodes
            .iter()
            .find(|candidate| candidate.element_index == Some(parent_index))
        else {
            return false;
        };
        if role_is(parent_node, &["document web", "document frame", "document"]) {
            return true;
        }
        parent = parent_node.parent_element_index;
    }
    true
}

pub(crate) fn trusted_prompt_nodes(
    nodes: &[AtspiNode],
) -> impl DoubleEndedIterator<Item = &AtspiNode> {
    nodes.iter().filter(|node| {
        !node.in_web_content
            && !role_is(node, &["document web", "document frame", "document"])
            && !is_in_web_content(nodes, node)
    })
}

pub(crate) fn has_nonempty_accessible_text(node: &AtspiNode) -> bool {
    [
        node.name.as_deref(),
        node.value.as_deref(),
        node.description.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty())
}

pub(crate) fn is_descendant_of(
    nodes: &[AtspiNode],
    node: &AtspiNode,
    ancestor_index: usize,
) -> bool {
    let mut parent = node.parent_element_index;
    for _ in 0..nodes.len() {
        let Some(parent_index) = parent else {
            return false;
        };
        if parent_index == ancestor_index {
            return true;
        }
        let Some(parent_node) = nodes
            .iter()
            .find(|candidate| candidate.element_index == Some(parent_index))
        else {
            return false;
        };
        parent = parent_node.parent_element_index;
    }
    false
}

pub(crate) fn exact_button_center(
    bounds: &[(usize, i32, i32, u32, u32)],
    element_index: usize,
) -> anyhow::Result<(i32, i32)> {
    let (_, x, y, width, height) = bounds
        .iter()
        .find(|(index, _, _, width, height)| *index == element_index && *width > 1 && *height > 1)
        .ok_or_else(|| anyhow::anyhow!("target dialog button had empty screen bounds"))?;
    let center_x = x
        .checked_add(i32::try_from(width / 2)?)
        .ok_or_else(|| anyhow::anyhow!("button center x overflowed"))?;
    let center_y = y
        .checked_add(i32::try_from(height / 2)?)
        .ok_or_else(|| anyhow::anyhow!("button center y overflowed"))?;
    Ok((center_x, center_y))
}

// ── Generic rule matching ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MatchedDialog {
    pub rule: DialogRule,
    pub root_index: usize,
    pub root_role: String,
    pub root_name: Option<String>,
    pub target_button: Option<AtspiNode>,
    pub input_node: Option<AtspiNode>,
    pub candidate_buttons_count: usize,
}

fn node_text_segments(node: &AtspiNode) -> Vec<&str> {
    [
        node.name.as_deref(),
        node.value.as_deref(),
        node.description.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .collect()
}

fn matches_pattern(haystack: &str, pattern: &str) -> anyhow::Result<bool> {
    let re = Regex::new(pattern)
        .map_err(|e| anyhow::anyhow!("invalid dialog rule regex '{pattern}': {e}"))?;
    Ok(re.is_match(haystack))
}

fn is_excluded_name(name: &str, exclude_names: &[String]) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    exclude_names.iter().any(|excl| {
        let trimmed = excl.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Ok(re) = Regex::new(trimmed) {
            if re.is_match(name) {
                return true;
            }
        }
        lower.contains(&trimmed.to_ascii_lowercase())
    })
}

fn rule_matches_window_meta(
    rule: &DialogRule,
    wm_class: Option<&str>,
    window_title: Option<&str>,
) -> anyhow::Result<bool> {
    if let Some(ref pat) = rule.wm_class {
        let actual = wm_class.unwrap_or("");
        if actual.is_empty() {
            return Ok(false);
        }
        let ok = if let Ok(re) = Regex::new(pat) {
            re.is_match(actual)
        } else {
            actual.to_ascii_lowercase().contains(&pat.to_ascii_lowercase())
        };
        if !ok {
            return Ok(false);
        }
    }
    if let Some(ref pat) = rule.title_regex {
        let actual = window_title.unwrap_or("");
        if !matches_pattern(actual, pat)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn match_dialog_in_tree(
    rules: &[DialogRule],
    wm_class: Option<&str>,
    window_title: Option<&str>,
    nodes: &[AtspiNode],
) -> anyhow::Result<Option<MatchedDialog>> {
    let mut sorted: Vec<&DialogRule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in sorted {
        if !rule_matches_window_meta(rule, wm_class, window_title)? {
            continue;
        }
        if let Some(matched) = match_single_rule(rule, nodes)? {
            return Ok(Some(matched));
        }
    }
    Ok(None)
}

fn match_single_rule(rule: &DialogRule, nodes: &[AtspiNode]) -> anyhow::Result<Option<MatchedDialog>> {
    let root_roles_ref: Vec<&str> = if rule.root_roles.is_empty() {
        vec!["alert", "dialog"]
    } else {
        rule.root_roles.iter().map(String::as_str).collect()
    };
    let button_roles_ref: Vec<&str> = if rule.button_roles.is_empty() {
        vec!["push button", "button"]
    } else {
        rule.button_roles.iter().map(String::as_str).collect()
    };

    let scoped_nodes: Vec<&AtspiNode> = if rule.exclude_web_content {
        trusted_prompt_nodes(nodes).collect()
    } else {
        nodes.iter().collect()
    };

    for root in scoped_nodes.iter().copied() {
        let Some(root_index) = root.element_index else {
            continue;
        };
        if !role_is(root, &root_roles_ref) {
            continue;
        }

        let subtree: Vec<&AtspiNode> = scoped_nodes
            .iter()
            .copied()
            .filter(|n| n.element_index == Some(root_index) || is_descendant_of(nodes, n, root_index))
            .collect();

        if let Some(ref heading_pat) = rule.heading_regex {
            let re = Regex::new(heading_pat)
                .map_err(|e| anyhow::anyhow!("invalid heading_regex '{heading_pat}': {e}"))?;
            let heading_matched = subtree.iter().any(|n| {
                (role_is(n, &["heading", "label", "title", "static"]) || n.element_index == Some(root_index))
                    && node_text_segments(n).into_iter().any(|t| re.is_match(t))
            });
            if !heading_matched {
                continue;
            }
        }

        if let Some(ref body_pat) = rule.body_regex {
            let re = Regex::new(body_pat)
                .map_err(|e| anyhow::anyhow!("invalid body_regex '{body_pat}': {e}"))?;
            let body_matched = subtree.iter().any(|n| {
                !role_is(n, &button_roles_ref)
                    && node_text_segments(n).into_iter().any(|t| re.is_match(t))
            });
            if !body_matched {
                continue;
            }
        }

        // All actionable enabled buttons inside the root (before exclude_names / button_name_regex).
        let mut all_buttons: Vec<&AtspiNode> = subtree
            .iter()
            .copied()
            .filter(|n| {
                role_is(n, &button_roles_ref)
                    && n.enabled != Some(false)
                    && n.element_index.is_some()
            })
            .collect();
        all_buttons.sort_by_key(|n| n.element_index.unwrap_or(usize::MAX));

        if let Some(expected_count) = rule.expected_button_count {
            if all_buttons.len() != expected_count {
                continue;
            }
        }

        let filtered_buttons: Vec<&AtspiNode> = all_buttons
            .into_iter()
            .filter(|n| {
                let name = n.name.as_deref().unwrap_or("");
                !is_excluded_name(name, &rule.exclude_names)
            })
            .filter(|n| match rule.button_name_regex {
                Some(ref pat) => Regex::new(pat)
                    .map(|re| re.is_match(n.name.as_deref().unwrap_or("")))
                    .unwrap_or(false),
                None => true,
            })
            .collect();

        // Optional editable input node for `env_key` secret typing.
        let input_node = if rule.env_key.is_some() {
            let role_re = rule
                .input_role_regex
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| anyhow::anyhow!("invalid input_role_regex: {e}"))?;
            subtree
                .iter()
                .copied()
                .filter(|n| n.enabled != Some(false) && n.element_index.is_some())
                .find(|n| {
                    if let Some(ref re) = role_re {
                        re.is_match(&n.role)
                    } else {
                        role_is(n, &["password text"])
                    }
                })
                .or_else(|| {
                    subtree
                        .iter()
                        .copied()
                        .filter(|n| n.enabled != Some(false) && n.element_index.is_some())
                        .find(|n| role_is(n, &["text", "entry", "combo box"]))
                })
                .cloned()
        } else {
            None
        };

        let target_button = if let Some(idx) = rule.target_button_index {
            match filtered_buttons.get(idx) {
                Some(btn) => Some((*btn).clone()),
                None => continue,
            }
        } else if !filtered_buttons.is_empty() {
            Some(filtered_buttons[0].clone())
        } else if rule.env_key.is_some() && input_node.is_some() {
            None
        } else {
            continue;
        };

        if rule.env_key.is_some() && input_node.is_none() {
            continue;
        }

        return Ok(Some(MatchedDialog {
            rule: rule.clone(),
            root_index,
            root_role: root.role.clone(),
            root_name: root.name.clone(),
            target_button,
            input_node,
            candidate_buttons_count: filtered_buttons.len(),
        }));
    }

    Ok(None)
}

#[derive(Clone, Debug, Default)]
pub struct MatchAndActRequest {
    pub pid: Option<u32>,
    pub window_id: Option<u64>,
    pub display_id: Option<String>,
    pub rule_id: Option<String>,
    pub inline_rule: Option<DialogRule>,
    pub focus_policy: Option<FocusPolicy>,
    pub env_key: Option<String>,
    pub env_file: Option<String>,
    pub verify_disappeared: Option<bool>,
    pub wait_ms: Option<u64>,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct MatchAndActOutcome {
    pub matched: bool,
    pub acted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wm_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_button_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_button_index: Option<usize>,
    pub focus_policy: String,
    pub secret_injected: bool,
    pub verified_disappeared: bool,
    pub elapsed_ms: u64,
}

fn click_button_with_policy(
    pid: u32,
    window_id: u64,
    bounds: &[(usize, i32, i32, u32, u32)],
    element_index: usize,
    focus_policy: FocusPolicy,
) -> anyhow::Result<()> {
    let (cx, cy) = exact_button_center(bounds, element_index)?;
    let send = move || {
        if crate::desktop::desktop() != crate::desktop::Desktop::X11 {
            crate::wayland::click_focused((cx, cy).into(), 1, 1)
        } else {
            crate::input::send_click_xtest_desktop(cx, cy, 1, 1)
        }
    };
    if focus_policy.is_preserve_host() {
        send()
    } else {
        with_target_foreground(pid, window_id, session_policy().setup, send)
    }
}

fn inject_secret_into_dialog(
    pid: u32,
    window_id: u64,
    display_id: Option<&str>,
    input_node: &AtspiNode,
    env_key: &str,
    env_file: Option<&str>,
    press_enter: bool,
    focus_policy: FocusPolicy,
) -> anyhow::Result<()> {
    validate_env_key(env_key)?;
    let secret = resolve_secret_from_env(env_key, env_file)?;
    if let Some(ref oref) = input_node.object_ref {
        if crate::atspi::native::set_value_ref(oref, &secret).is_ok()
            || crate::atspi::native::type_into_editable_ref(oref, &secret).is_ok()
        {
            if press_enter {
                if let Ok(target) = DisplayTarget::from_display_id(display_id) {
                    if let Ok(ctx) = global_screen_pool().get_or_connect(&target) {
                        let _ = crate::x11::virtual_input::xtest_press_key(&ctx, "Return");
                    }
                }
            }
            return Ok(());
        }
    }
    let target = DisplayTarget::from_display_id(display_id)?;
    let ctx = global_screen_pool().get_or_connect(&target)?;
    if !focus_policy.is_preserve_host() {
        let _ = crate::x11::virtual_input::xtest_focus_window(&ctx, window_id);
    }
    if let Some(idx) = input_node.element_index {
        let _ = crate::atspi::focus_element(pid, idx);
    }
    let _ = type_secret_into_context(&ctx, env_key, &secret, press_enter)?;
    Ok(())
}

fn resolve_candidate_windows(
    pid: Option<u32>,
    window_id: Option<u64>,
) -> Vec<(u32, u64, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    if let Some(wid) = window_id {
        let info = crate::x11::window_info(wid);
        let resolved_pid = pid.or_else(|| info.as_ref().and_then(|w| w.pid)).unwrap_or(0);
        if resolved_pid != 0 {
            let wm_class = crate::x11::wm_class_for_window(wid)
                .map(|(i, c)| format!("{i} {c}").trim().to_owned());
            let title = info.map(|w| w.title);
            out.push((resolved_pid, wid, wm_class, title));
            return out;
        }
    }
    for w in crate::wayland::list_windows_dispatch(pid) {
        if let Some(wpid) = w.pid {
            let wm_class = crate::x11::wm_class_for_window(w.xid)
                .map(|(i, c)| format!("{i} {c}").trim().to_owned())
                .or_else(|| (!w.app_name.is_empty()).then_some(w.app_name.clone()));
            out.push((wpid, w.xid, wm_class, Some(w.title)));
        }
    }
    out
}

pub fn match_and_act(req: MatchAndActRequest) -> anyhow::Result<MatchAndActOutcome> {
    let started = Instant::now();
    let mut rules = if let Some(ref inline) = req.inline_rule {
        vec![inline.clone()]
    } else {
        load_dialog_rules()?
    };
    if let Some(ref wanted_id) = req.rule_id {
        rules.retain(|r| r.id == *wanted_id);
        if rules.is_empty() {
            anyhow::bail!("dialog rule '{wanted_id}' not found in dialog_rules.json");
        }
    }
    for rule in &mut rules {
        if let Some(fp) = req.focus_policy {
            rule.focus_policy = fp;
        }
        if let Some(ref key) = req.env_key {
            validate_env_key(key)?;
            rule.env_key = Some(key.clone());
        }
        if let Some(ref file) = req.env_file {
            rule.env_file = Some(file.clone());
        }
        if let Some(v) = req.verify_disappeared {
            rule.verify_disappeared = v;
        }
    }

    let wait_ms = req
        .wait_ms
        .unwrap_or(DEFAULT_WAIT_MS)
        .clamp(MIN_WAIT_MS, MAX_WAIT_MS);
    let deadline = Instant::now() + Duration::from_millis(wait_ms);

    loop {
        let candidates = resolve_candidate_windows(req.pid, req.window_id);
        for (wpid, wid, wm_class, title) in candidates {
            let tree = crate::atspi::walk_tree_no_web_content(wpid, wid, None);
            if let Some(matched) =
                match_dialog_in_tree(&rules, wm_class.as_deref(), title.as_deref(), &tree.nodes)?
            {
                let eff_focus = matched.rule.focus_policy;
                let btn_name = matched.target_button.as_ref().and_then(|b| b.name.clone());
                let btn_index = matched.target_button.as_ref().and_then(|b| b.element_index);
                if req.dry_run {
                    return Ok(MatchAndActOutcome {
                        matched: true,
                        acted: false,
                        rule_id: Some(matched.rule.id),
                        pid: Some(wpid),
                        window_id: Some(wid),
                        wm_class,
                        root_role: Some(matched.root_role),
                        target_button_name: btn_name,
                        target_button_index: btn_index,
                        focus_policy: eff_focus.as_str().into(),
                        secret_injected: false,
                        verified_disappeared: false,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    });
                }

                let mut secret_injected = false;
                if let (Some(ref key), Some(ref input_node)) =
                    (&matched.rule.env_key, &matched.input_node)
                {
                    inject_secret_into_dialog(
                        wpid,
                        wid,
                        req.display_id.as_deref(),
                        input_node,
                        key,
                        matched.rule.env_file.as_deref(),
                        matched.rule.press_enter.unwrap_or(false) && matched.target_button.is_none(),
                        eff_focus,
                    )?;
                    secret_injected = true;
                }

                if let Some(ref btn) = matched.target_button {
                    let a11y_res = crate::atspi::action_sent(
                        crate::atspi::perform_action_walked(wpid, wid, btn),
                    );
                    if a11y_res.is_err() {
                        if let Some(idx) = btn.element_index {
                            click_button_with_policy(wpid, wid, &tree.bounds, idx, eff_focus)?;
                        } else {
                            a11y_res?;
                        }
                    }
                }

                let mut verified_disappeared = !matched.rule.verify_disappeared;
                if matched.rule.verify_disappeared {
                    let verify_deadline =
                        deadline.min(Instant::now() + Duration::from_millis(DEFAULT_VERIFY_MS));
                    let mut fallback_clicked = false;
                    let acted_at = Instant::now();
                    loop {
                        let re_tree = crate::atspi::walk_tree_no_web_content(wpid, wid, None);
                        let still_there = match_single_rule(&matched.rule, &re_tree.nodes)?.is_some();
                        if !still_there {
                            verified_disappeared = true;
                            break;
                        }
                        if !fallback_clicked
                            && acted_at.elapsed() >= Duration::from_millis(150)
                        {
                            if let Some(idx) = btn_index {
                                let _ = click_button_with_policy(
                                    wpid,
                                    wid,
                                    &re_tree.bounds,
                                    idx,
                                    eff_focus,
                                );
                                fallback_clicked = true;
                            }
                        }
                        if Instant::now() >= verify_deadline {
                            anyhow::bail!(
                                "dialog rule '{}' acted on button {:?} (pid={wpid}, window_id={wid}), but dialog remained visible after verification timeout",
                                matched.rule.id,
                                btn_name
                            );
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }

                return Ok(MatchAndActOutcome {
                    matched: true,
                    acted: true,
                    rule_id: Some(matched.rule.id),
                    pid: Some(wpid),
                    window_id: Some(wid),
                    wm_class,
                    root_role: Some(matched.root_role),
                    target_button_name: btn_name,
                    target_button_index: btn_index,
                    focus_policy: eff_focus.as_str().into(),
                    secret_injected,
                    verified_disappeared,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                });
            }
        }

        if Instant::now() >= deadline {
            return Ok(MatchAndActOutcome {
                matched: false,
                acted: false,
                rule_id: req.rule_id,
                pid: req.pid,
                window_id: req.window_id,
                wm_class: None,
                root_role: None,
                target_button_name: None,
                target_button_index: None,
                focus_policy: req.focus_policy.unwrap_or_default().as_str().into(),
                secret_injected: false,
                verified_disappeared: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(index: usize, role: &str, name: &str, parent: Option<usize>) -> AtspiNode {
        AtspiNode {
            element_index: Some(index),
            role: role.into(),
            name: Some(name.into()),
            value: None,
            checked: None,
            enabled: Some(true),
            selected: None,
            focused: None,
            description: None,
            document_uri: None,
            actions: vec!["press".into()],
            element_key: index as u64,
            identity: None,
            depth: 1,
            parent_element_index: parent,
            in_web_content: false,
            object_ref: None,
        }
    }

    #[test]
    fn hot_reloads_dialog_rules_json_by_mtime_and_len() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dialog_rules.json");

        std::fs::write(
            &path,
            r#"{
                "rules": [
                    {
                        "id": "rule_v1",
                        "WM_CLASS": "google-chrome",
                        "root_roles": ["alert"],
                        "heading_regex": "Allow",
                        "button_name_regex": "^Allow$",
                        "expected_button_count": 3
                    }
                ]
            }"#,
        )
        .unwrap();
        let r1 = load_dialog_rules_from_path(&path).unwrap().unwrap();
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].id, "rule_v1");
        assert_eq!(r1[0].wm_class.as_deref(), Some("google-chrome"));

        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(
            &path,
            r#"[
                {
                    "id": "rule_v2_high",
                    "priority": 100,
                    "root_roles": ["dialog"],
                    "button_name_regex": "^Unlock$",
                    "focus_policy": "preserve_host",
                    "env_key": "CUA_YCWANG_TEST_PIN",
                    "verify_disappeared": true
                }
            ]"#,
        )
        .unwrap();
        let r2 = load_dialog_rules_from_path(&path).unwrap().unwrap();
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].id, "rule_v2_high");
        assert_eq!(r2[0].focus_policy, FocusPolicy::PreserveHost);
        assert_eq!(r2[0].env_key.as_deref(), Some("CUA_YCWANG_TEST_PIN"));
    }

    #[test]
    fn matches_dialog_rule_fields_exclusions_button_count_and_index() {
        let nodes = vec![
            node(0, "frame", "Chrome", None),
            node(10, "alert", "Allow remote debugging?", Some(0)),
            node(11, "heading", "Allow remote debugging?", Some(10)),
            node(
                12,
                "static",
                "An external app wants full control over this Chrome session.",
                Some(10),
            ),
            node(13, "push button", "Turn off in settings", Some(10)),
            node(14, "push button", "Cancel", Some(10)),
            node(15, "push button", "Allow", Some(10)),
        ];

        let rule = DialogRule {
            id: "consent".into(),
            description: None,
            wm_class: Some("google-chrome".into()),
            title_regex: None,
            root_roles: vec!["alert".into()],
            exclude_web_content: true,
            heading_regex: Some("remote debugging".into()),
            body_regex: Some("external app".into()),
            button_roles: vec!["push button".into()],
            button_name_regex: Some("Allow|Cancel".into()),
            exclude_names: vec!["Cancel".into(), "Turn off".into()],
            expected_button_count: Some(3),
            target_button_index: Some(0),
            focus_policy: FocusPolicy::PreserveHost,
            env_key: None,
            env_file: None,
            input_role_regex: None,
            press_enter: None,
            verify_disappeared: true,
            priority: 1,
        };

        let matched = match_dialog_in_tree(&[rule.clone()], Some("google-chrome"), None, &nodes)
            .unwrap()
            .expect("rule should match");
        assert_eq!(matched.root_index, 10);
        assert_eq!(
            matched.target_button.as_ref().and_then(|b| b.element_index),
            Some(15)
        );

        // Wrong WM_CLASS must not match.
        assert!(match_dialog_in_tree(&[rule.clone()], Some("firefox"), None, &nodes)
            .unwrap()
            .is_none());

        // Wrong expected_button_count must not match.
        let mut bad_count = rule;
        bad_count.expected_button_count = Some(2);
        assert!(match_dialog_in_tree(&[bad_count], Some("google-chrome"), None, &nodes)
            .unwrap()
            .is_none());
    }

    #[test]
    fn matches_password_dialog_with_env_key_and_rejects_web_content() {
        let mut doc = node(1, "document web", "Phishing", Some(0));
        doc.in_web_content = true;
        let mut fake_alert = node(2, "alert", "Unlock Keyring", Some(1));
        fake_alert.in_web_content = true;
        let mut fake_btn = node(3, "push button", "Unlock", Some(2));
        fake_btn.in_web_content = true;

        let nodes_web_only = vec![node(0, "frame", "Chrome", None), doc, fake_alert, fake_btn];
        let rule = DialogRule {
            id: "keyring_unlock".into(),
            description: None,
            wm_class: None,
            title_regex: None,
            root_roles: vec!["dialog".into(), "alert".into()],
            exclude_web_content: true,
            heading_regex: Some("Unlock Keyring".into()),
            body_regex: None,
            button_roles: vec!["push button".into()],
            button_name_regex: Some("^Unlock$".into()),
            exclude_names: vec![],
            expected_button_count: None,
            target_button_index: Some(0),
            focus_policy: FocusPolicy::Default,
            env_key: Some("CUA_YCWANG_KEYRING_PASS".into()),
            env_file: None,
            input_role_regex: None,
            press_enter: None,
            verify_disappeared: true,
            priority: 5,
        };
        assert!(match_dialog_in_tree(&[rule.clone()], None, None, &nodes_web_only)
            .unwrap()
            .is_none());

        let native_nodes = vec![
            node(0, "frame", "Keyring", None),
            node(10, "dialog", "Unlock Keyring", Some(0)),
            node(11, "password text", "Password", Some(10)),
            node(12, "push button", "Cancel", Some(10)),
            node(13, "push button", "Unlock", Some(10)),
        ];
        let matched = match_dialog_in_tree(&[rule], None, None, &native_nodes)
            .unwrap()
            .expect("native dialog should match");
        assert_eq!(
            matched.input_node.as_ref().and_then(|n| n.element_index),
            Some(11)
        );
        assert_eq!(
            matched.target_button.as_ref().and_then(|n| n.element_index),
            Some(13)
        );
    }
}
