// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Linux implementation of the cross-platform `PageBackend` trait.
//!
//! Read paths use AT-SPI via the existing `walk_tree` infrastructure
//! (`crate::atspi`).

use async_trait::async_trait;
use cua_driver_core::page::{PageBackend, PageReadResult};

pub struct LinuxPageBackend;

impl LinuxPageBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxPageBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PageBackend for LinuxPageBackend {
    async fn get_text(&self, pid: i32, window_id: u64) -> anyhow::Result<PageReadResult> {
        let pid_u = pid as u32;
        let xid = window_id;
        let result = tokio::task::spawn_blocking(move || crate::atspi::walk_tree(pid_u, xid, None))
            .await
            .map_err(|e| anyhow::anyhow!("AT-SPI walk task failed: {e}"))?;
        Ok(PageReadResult::text(extract_page_text(&result)))
    }

    async fn query_dom(
        &self,
        pid: i32,
        window_id: u64,
        css_selector: &str,
        attributes: &[String],
    ) -> anyhow::Result<PageReadResult> {
        let pid_u = pid as u32;
        let xid = window_id;
        let selector = css_selector.to_owned();
        let result = tokio::task::spawn_blocking(move || crate::atspi::walk_tree(pid_u, xid, None))
            .await
            .map_err(|e| anyhow::anyhow!("AT-SPI walk task failed: {e}"))?;

        if selector.contains("[data-") {
            anyhow::bail!(
                "`[data-*]` selectors are not reachable via AT-SPI on Linux. \
                 Tiered WebView fallback: (1) CDP (`get_browser_state` + `browser_*` tools); \
                 (2) AT-SPI (`page` with tag/role selectors); \
                 (3) AppRecipe ROI anchors (`run_app_recipe` / `acquire_app_data`)."
            );
        }

        let role = role_for_selector(&selector);
        let selector_is_wildcard = {
            let s = selector.trim();
            s.is_empty() || s == "*"
        };
        // `role_for_selector` collapses both "wildcard / match-all" AND
        // "unrecognised" into `None`. The first should keep every node; the
        // second should fail loudly so an agent doesn't get a misleading
        // dump of every element on the page when its `.foo` / `#bar` query
        // wasn't actually understood.
        if role.is_none() && !selector_is_wildcard {
            anyhow::bail!(
                "Selector '{selector}' is not supported by Linux AT-SPI role mapping. \
                 Use a tag or ARIA role selector (a, button, input, textarea, h1-h6, img, li, \
                 p, select, nav, main, form, table, tr, td, th, tab, menu, menuitem, dialog, \
                 checkbox, radio, [role=...], *). Tiered WebView fallback: (1) CDP (`get_browser_state` \
                 + `browser_*`); (2) AT-SPI (`page`); (3) AppRecipe ROI anchors (`run_app_recipe`)."
            );
        }
        let lines = format_matched_nodes(&result.nodes, role.as_deref(), attributes);

        let content = if lines.is_empty() {
            "No elements found.".to_owned()
        } else {
            lines.join("\n")
        };
        Ok(PageReadResult::text(content))
    }
}

fn format_matched_nodes(
    nodes: &[crate::atspi::AtspiNode],
    role: Option<&str>,
    attributes: &[String],
) -> Vec<String> {
    nodes
        .iter()
        .filter(|n| match role {
            Some(r) => n.role.eq_ignore_ascii_case(r),
            None => true,
        })
        .map(|n| {
            let name = n.name.as_deref().unwrap_or("");
            let value = n.value.as_deref().unwrap_or("");
            let index = n
                .element_index
                .map(|i| format!("[{i}] "))
                .unwrap_or_default();
            let base = if value.is_empty() {
                format!("- {index}{} \"{}\"", n.role, name)
            } else {
                format!("- {index}{} \"{}\" = \"{}\"", n.role, name, value)
            };
            if attributes.is_empty() {
                return base;
            }
            let attrs: Vec<String> = attributes
                .iter()
                .filter_map(|attr| {
                    node_attribute_value(n, attr).map(|val| format!("{attr}=\"{val}\""))
                })
                .collect();
            if attrs.is_empty() {
                base
            } else {
                format!("{base} {{{}}}", attrs.join(", "))
            }
        })
        .collect()
}

fn node_attribute_value(node: &crate::atspi::AtspiNode, attr: &str) -> Option<String> {
    match attr.trim().to_ascii_lowercase().as_str() {
        "role" => Some(node.role.clone()),
        "name" | "aria-label" | "title" | "alt" => node.name.clone().filter(|s| !s.is_empty()),
        "value" => node.value.clone().filter(|s| !s.is_empty()),
        "description" | "aria-description" => node.description.clone().filter(|s| !s.is_empty()),
        "href" | "src" | "document_uri" | "url" => {
            node.document_uri.clone().filter(|s| !s.is_empty())
        }
        "checked" | "aria-checked" => node.checked.map(|b| b.to_string()),
        "enabled" | "disabled" => node.enabled.map(|b| {
            if attr.trim().eq_ignore_ascii_case("disabled") {
                (!b).to_string()
            } else {
                b.to_string()
            }
        }),
        "selected" | "aria-selected" => node.selected.map(|b| b.to_string()),
        "focused" => node.focused.map(|b| b.to_string()),
        "actions" => (!node.actions.is_empty()).then(|| node.actions.join("|")),
        "in_web_content" => Some(node.in_web_content.to_string()),
        _ => None,
    }
}

/// Map common CSS selectors and `[role=...]` / ARIA roles to AT-SPI role names
/// (covering Chrome, Electron, CEF, and WebKitGTK trees). Returns `None` for
/// `*` or unrecognised selectors (caller treats `None` as "no role filter").
fn role_for_selector(sel: &str) -> Option<String> {
    let s = sel.trim();
    if let Some(rest) = s.strip_prefix("[role=") {
        if let Some(end) = rest.find(']') {
            let role_val = rest[..end].trim().trim_matches(['"', '\'']);
            if !role_val.is_empty() {
                return Some(role_val.to_ascii_lowercase());
            }
        }
    }
    // Trim trailing [attr=...] or .class / #id qualifiers — we filter on
    // role only here (the macOS backend has richer JS-side filtering).
    let tag_end = s.find(['[', '.', '#']).unwrap_or(s.len());
    let tag = &s[..tag_end];
    let role = match tag.to_ascii_lowercase().as_str() {
        "a" | "link" => "link",
        "button" => "push button",
        "input" | "textarea" => "entry",
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "heading" => "heading",
        "img" | "image" => "image",
        "li" => "list item",
        "ul" | "ol" | "list" => "list",
        "p" | "paragraph" => "paragraph",
        "select" => "combo box",
        "nav" | "navigation" => "landmark",
        "main" => "landmark",
        "form" => "form",
        "table" => "table",
        "tr" => "table row",
        "td" | "th" => "table cell",
        "label" => "label",
        "checkbox" => "check box",
        "radio" => "radio button",
        "tab" => "page tab",
        "tabpanel" => "page tab list",
        "menu" => "menu",
        "menuitem" => "menu item",
        "dialog" => "dialog",
        "alert" => "alert",
        "progress" | "progressbar" => "progress bar",
        "slider" => "slider",
        "document" | "webview" => "document web",
        "" | "*" => return None,
        _ => return None,
    };
    Some(role.to_owned())
}

const MAX_PAGE_TEXT_BYTES: usize = 8000;

/// Extract page text from an AT-SPI tree result:
/// 1. Prefer `document web` / `document frame` subtrees in `tree_markdown`.
/// 2. Otherwise, if any node/observation has `in_web_content`, use those lines.
/// 3. Otherwise, fall back to the full `tree_markdown`.
/// Finally, deduplicate consecutive blank/identical lines and truncate UTF-8
/// safely to `<= MAX_PAGE_TEXT_BYTES`.
fn extract_page_text(result: &crate::atspi::AtspiTreeResult) -> String {
    if let Some(doc_md) = filter_document_subtrees(&result.tree_markdown) {
        return finalize_page_text(&extract_text_from_markdown(&doc_md));
    }

    let has_web_content = result.nodes.iter().any(|n| n.in_web_content)
        || result
            .observations
            .iter()
            .any(|o| o.in_web_content == Some(true));
    if has_web_content {
        let mut lines = Vec::new();
        for n in &result.nodes {
            if n.in_web_content {
                if let Some(name) = n.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    lines.push(name.to_owned());
                } else if let Some(val) = n.value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    lines.push(val.to_owned());
                }
            }
        }
        for o in &result.observations {
            if o.in_web_content == Some(true) {
                if let Some(label) = o.label.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    lines.push(label.to_owned());
                } else if let Some(val) = o.value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    lines.push(val.to_owned());
                }
            }
        }
        return finalize_page_text(&dedup_lines(lines));
    }

    finalize_page_text(&extract_text_from_markdown(&result.tree_markdown))
}

fn is_document_subtree_root(trimmed_after_bullet: &str) -> bool {
    let rest = if let Some(after_bracket) = trimmed_after_bullet.strip_prefix('[') {
        if let Some(end) = after_bracket.find(']') {
            after_bracket[end + 1..].trim_start()
        } else {
            trimmed_after_bullet
        }
    } else {
        trimmed_after_bullet
    };
    let lower = rest.to_ascii_lowercase();
    ["document web", "document frame"].iter().any(|role| {
        lower
            .strip_prefix(role)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with([' ', '=', '"']))
    })
}

fn filter_document_subtrees(md: &str) -> Option<String> {
    let mut kept = Vec::new();
    let mut active_doc_indent: Option<usize> = None;

    for line in md.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let after_bullet = trimmed.trim_start_matches('-').trim_start();
        let is_doc_root = is_document_subtree_root(after_bullet);

        if is_doc_root {
            active_doc_indent = Some(indent);
            kept.push(line);
            continue;
        }

        if let Some(doc_indent) = active_doc_indent {
            if indent > doc_indent {
                kept.push(line);
            } else {
                active_doc_indent = None;
            }
        }
    }

    if kept.is_empty() {
        None
    } else {
        Some(kept.join("\n"))
    }
}

/// Strip Markdown tree formatting and concatenate the human-readable text.
fn extract_text_from_markdown(md: &str) -> String {
    let lines = md.lines().map(|l| {
        // Strip leading indent + bullet markers `-` / `[N]` so the result
        // reads like flowing text.
        let trimmed = l.trim_start();
        let trimmed = trimmed.trim_start_matches('-').trim_start();
        // Drop the `[N] ` element-index prefix.
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                return rest[end + 1..].trim_start().to_owned();
            }
        }
        trimmed.to_owned()
    });
    dedup_lines(lines)
}

fn dedup_lines<I>(lines: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let mut out: Vec<String> = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if out.last().is_some_and(|prev| prev == trimmed) {
            continue;
        }
        out.push(trimmed.to_owned());
    }
    out.join("\n")
}

fn finalize_page_text(text: &str) -> String {
    if text.len() <= MAX_PAGE_TEXT_BYTES {
        return text.to_owned();
    }
    let notice = format!(
        "\n[truncated: showing <= {MAX_PAGE_TEXT_BYTES} of {} bytes]",
        text.len()
    );
    let budget = MAX_PAGE_TEXT_BYTES.saturating_sub(notice.len());
    let mut end = budget.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{notice}", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atspi::{AtspiNode, AtspiTreeResult};
    use cua_driver_contract::WindowObservation;

    fn empty_tree_result(tree_markdown: &str) -> AtspiTreeResult {
        AtspiTreeResult {
            tree_markdown: tree_markdown.to_owned(),
            nodes: Vec::new(),
            observations: Vec::new(),
            bounds: Vec::new(),
            trusted: true,
            degraded_reason: None,
            window_scoped: true,
            truncated: false,
            truncation_reason: None,
            nodes_visited: 0,
            nodes_pending: 0,
            bounds_complete: true,
            elapsed_ms: 0,
        }
    }

    #[test]
    fn prefers_document_web_subtree_and_dedups_lines() {
        let md = "\
- [0] frame \"Browser\"
  - [1] tool bar \"Navigation\"
    - [2] push button \"Reload\"
  - [3] document web \"Example Page\"
    - heading = \"Hello\"
    - heading = \"Hello\"
    -
    - [4] link \"Read more\"
  - [5] status bar \"Done\"";
        let res = empty_tree_result(md);
        let text = extract_page_text(&res);
        assert!(text.contains("Example Page"));
        assert!(text.contains("Hello"));
        assert!(text.contains("Read more"));
        assert!(!text.contains("Reload"));
        assert!(!text.contains("status bar"));
        assert_eq!(text.matches("heading = \"Hello\"").count(), 1);
    }

    #[test]
    fn falls_back_to_in_web_content_when_no_document_role_in_markdown() {
        let mut res = empty_tree_result("- [0] frame \"Chrome\"\n  - [1] push button \"Back\"");
        res.nodes.push(AtspiNode {
            element_index: Some(2),
            role: "link".into(),
            name: Some("Web Link".into()),
            value: None,
            checked: None,
            enabled: Some(true),
            selected: None,
            focused: Some(false),
            description: None,
            document_uri: None,
            actions: vec![],
            element_key: 2,
            identity: None,
            depth: 1,
            parent_element_index: None,
            in_web_content: true,
            object_ref: None,
        });
        res.observations.push(WindowObservation {
            role: "paragraph".into(),
            depth: 1,
            label: Some("Web Body".into()),
            value: None,
            frame: None,
            parent_index: None,
            in_web_content: Some(true),
        });
        let text = extract_page_text(&res);
        assert_eq!(text, "Web Link\nWeb Body");
    }

    #[test]
    fn falls_back_to_full_tree_when_no_web_markers_exist() {
        let res = empty_tree_result("- [0] frame \"App\"\n  - label = \"Plain text\"");
        let text = extract_page_text(&res);
        assert!(text.contains("frame \"App\""));
        assert!(text.contains("Plain text"));
    }

    #[test]
    fn truncates_utf8_safely_within_8000_bytes() {
        let long_line = "中".repeat(4000); // 12000 bytes
        let res = empty_tree_result(&format!("- [0] document web \"Big\"\n  - text = \"{long_line}\""));
        let text = extract_page_text(&res);
        assert!(text.len() <= MAX_PAGE_TEXT_BYTES);
        assert!(text.contains("[truncated:"));
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }

    #[test]
    fn role_mapping_and_attribute_extraction_support_webview_controls() {
        assert_eq!(role_for_selector("nav").as_deref(), Some("landmark"));
        assert_eq!(role_for_selector("checkbox").as_deref(), Some("check box"));
        assert_eq!(role_for_selector("menuitem").as_deref(), Some("menu item"));
        assert_eq!(role_for_selector("[role=\"dialog\"]").as_deref(), Some("dialog"));
        assert_eq!(role_for_selector("webview").as_deref(), Some("document web"));

        let mut node = AtspiNode {
            element_index: Some(7),
            role: "check box".into(),
            name: Some("Enable".into()),
            value: None,
            checked: Some(true),
            enabled: Some(true),
            selected: None,
            focused: Some(false),
            description: Some("Toggle setting".into()),
            document_uri: None,
            actions: vec!["press".into()],
            element_key: 7,
            identity: None,
            depth: 2,
            parent_element_index: None,
            in_web_content: true,
            object_ref: None,
        };
        node.document_uri = Some("https://example.test/app".into());
        let lines = format_matched_nodes(
            &[node],
            Some("check box"),
            &["checked".into(), "actions".into(), "href".into()],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("checked=\"true\""));
        assert!(lines[0].contains("actions=\"press\""));
        assert!(lines[0].contains("href=\"https://example.test/app\""));
    }
}
