// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Tiered real-time application flow inspector (`inspect_app_flow`).
//!
//! Tier 1: X11 `WM_CLASS` + `_NET_WM_PID` + `/proc/<pid>` + AT-SPI2 control/menu tree
//!         + Electron `resources/app/package.json` / `keybindings.json`.
//! Tier 2: Java `install4j` (`response.varfile` + highest-version JAR `MANIFEST.MF` +
//!         zip resource/shortcut scan) & `.NET / Avalonia` (`*.deps.json`).
//! Browser exemption: Chrome/Chromium targets immediately return `channel: "browser_exempt"`
//!                    guiding callers to `chrome_devtools` / `browser_*`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use cua_driver_core::app_recipe::{fp8_of, MenuEntry, RelativeAnchor, VerifiedShortcut, VersionSource};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::x11::context::{global_screen_pool, DisplayTarget};

/// Input parameters for [`inspect_app_flow`].
#[derive(Debug, Clone, Default)]
pub struct InspectAppFlowRequest {
    pub pid: Option<u32>,
    pub window_id: Option<u64>,
    pub app_path: Option<String>,
    pub display_id: Option<String>,
}

/// Salient visual region hotspot in normalized window coordinates (`0.0..=1.0`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisualHotspot {
    pub id: String,
    pub rel_x: f64,
    pub rel_y: f64,
    pub rel_w: f64,
    pub rel_h: f64,
    pub hint: String,
}

/// Structured output returned by `inspect_app_flow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppFlowInspection {
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exempt_reason: Option<String>,
    pub app_id: String,
    pub app_version: String,
    pub version_source: VersionSource,
    pub tech_stack: String,
    pub fingerprint_sha256: String,
    pub fp8: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wm_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_title: Option<String>,
    pub verified_shortcuts: Vec<VerifiedShortcut>,
    pub menu_topology: Vec<MenuEntry>,
    pub interactive_elements_count: usize,
    pub atspi_blind: bool,
    pub recommended_interaction: String,
    #[serde(default)]
    pub remediation_hints: Vec<String>,
    #[serde(default)]
    pub launch_isolation_hints: Vec<String>,
    #[serde(default)]
    pub visual_hotspots: Vec<VisualHotspot>,
    #[serde(default)]
    pub discovered_anchors: Vec<RelativeAnchor>,
    pub sample_roles: Vec<String>,
    pub notes: Vec<String>,
}

/// Inspect a running or installed Linux desktop application and extract its
/// version, binary/manifest SHA-256 fingerprint, tech stack, menu/control
/// topology, and shortcut metadata.
pub fn inspect_app_flow(req: InspectAppFlowRequest) -> Result<AppFlowInspection> {
    let mut pid = req.pid;
    let mut window_title = None;
    let mut wm_class = None;
    let mut window_geom: Option<(i32, i32, u32, u32)> = None;

    if let Some(xid) = req.window_id {
        let target = DisplayTarget::from_display_id(req.display_id.as_deref())?;
        if let Ok(ctx) = global_screen_pool().get_or_connect(&target) {
            if let Some(info) = crate::x11::window_info_with_context(&ctx, xid) {
                pid = pid.or(info.pid);
                if !info.title.is_empty() {
                    window_title = Some(info.title);
                }
                if !info.app_name.is_empty() {
                    wm_class = Some(info.app_name);
                }
                if info.width > 0 && info.height > 0 {
                    window_geom = Some((info.x, info.y, info.width, info.height));
                }
            }
        }
    }

    let exe_path = req
        .app_path
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| pid.and_then(resolve_proc_exe));

    let cmdline = pid.and_then(resolve_proc_cmdline).unwrap_or_default();

    // Browser exemption check (Chrome / Chromium).
    if is_chrome_or_chromium(
        exe_path.as_deref(),
        wm_class.as_deref(),
        &cmdline,
        req.app_path.as_deref(),
    ) {
        let resolved_exe = exe_path.clone().or_else(|| {
            let candidate = PathBuf::from("/opt/google/chrome/chrome");
            candidate.is_file().then_some(candidate)
        });
        let mut notes = vec!["Routed to browser_exempt channel (hybrid CDP + OS recipe)".to_owned()];
        let (app_version, version_source) =
            if let Some(exe) = resolved_exe.as_deref().filter(|p| p.is_file()) {
                if let Some(dpkg_ver) = query_dpkg_version(exe) {
                    notes.push("Chrome version resolved via dpkg-query".to_owned());
                    (dpkg_ver, VersionSource::Dpkg)
                } else if let Some(cli_ver) = query_chrome_cli_version(exe) {
                    notes.push("Chrome version resolved via --version".to_owned());
                    (cli_ver, VersionSource::PeOrElf)
                } else {
                    ("unknown".to_owned(), VersionSource::Unknown)
                }
            } else {
                ("unknown".to_owned(), VersionSource::Unknown)
            };
        let fp = resolved_exe
            .as_deref()
            .and_then(|p| sha256_file(p).ok())
            .unwrap_or_else(|| sha256_bytes(b"chrome-browser-exempt"));
        let fp8 = fp8_of(&fp).to_owned();
        return Ok(AppFlowInspection {
            channel: "browser_exempt".to_owned(),
            exempt_reason: Some(
                "Chrome/Chromium is exempt from GUI reverse-engineering; use chrome_devtools MCP for DOM/network or run_app_recipe/acquire_app_data with google-chrome.json for OS-layer flows."
                    .to_owned(),
            ),
            app_id: "google-chrome".to_owned(),
            app_version,
            version_source,
            tech_stack: "chromium_browser".to_owned(),
            fingerprint_sha256: fp,
            fp8,
            executable_path: resolved_exe.map(|p| p.display().to_string()),
            wm_class,
            window_title,
            verified_shortcuts: Vec::new(),
            menu_topology: Vec::new(),
            interactive_elements_count: 0,
            atspi_blind: false,
            recommended_interaction: "hybrid_cdp_and_os_chrome".to_owned(),
            remediation_hints: Vec::new(),
            launch_isolation_hints: vec![
                "--user-data-dir=${CUA_YCWANG_HOME:-$HOME/.cua-ycwang}/chrome-profile".to_owned(),
                "--disable-features=UsePortal".to_owned(),
                "--no-first-run".to_owned(),
                "--no-default-browser-check".to_owned(),
                "--remote-debugging-port=9222".to_owned(),
            ],
            visual_hotspots: Vec::new(),
            discovered_anchors: Vec::new(),
            sample_roles: Vec::new(),
            notes,
        });
    }

    let mut notes = Vec::new();
    let mut shortcuts = Vec::new();
    let mut menu_topology = Vec::new();
    let mut launch_isolation_hints = Vec::new();

    // Resolve base directory for static artifact inspection.
    let base_dir = exe_path.as_deref().map(|p| {
        if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent().unwrap_or_else(|| Path::new("/")).to_path_buf()
        }
    });
    let install4j_dir = resolve_install4j_dir(base_dir.as_deref(), pid, &cmdline);

    let (app_id, app_version, version_source, tech_stack, fp_target) =
        if let Some(dir) = install4j_dir.as_deref() {
            inspect_java_install4j(
                dir,
                window_title.as_deref(),
                &mut shortcuts,
                &mut menu_topology,
                &mut launch_isolation_hints,
                &mut notes,
            )
            .unwrap_or_else(|| {
                inspect_native_fallback(exe_path.as_deref(), wm_class.as_deref(), &mut notes)
            })
        } else if let Some(dir) = base_dir.as_deref() {
            if let Some(dotnet) = inspect_dotnet_avalonia(dir, exe_path.as_deref(), &mut notes) {
                dotnet
            } else if let Some(electron) = inspect_electron_app(
                dir,
                exe_path.as_deref(),
                &mut shortcuts,
                &mut menu_topology,
                &mut launch_isolation_hints,
                &mut notes,
            ) {
                electron
            } else {
                inspect_native_fallback(exe_path.as_deref(), wm_class.as_deref(), &mut notes)
            }
        } else {
            inspect_native_fallback(exe_path.as_deref(), wm_class.as_deref(), &mut notes)
        };

    let fingerprint_sha256 = fp_target
        .as_deref()
        .and_then(|p| if p.is_file() { sha256_file(p).ok() } else { None })
        .unwrap_or_else(|| sha256_bytes(format!("{app_id}:{app_version}").as_bytes()));
    let fp8 = fp8_of(&fingerprint_sha256).to_owned();

    // Tier 1 runtime AT-SPI2 tree walk when a live PID is available.
    let mut interactive_elements_count = 0usize;
    let mut sample_roles = BTreeSet::new();
    let mut discovered_anchors = Vec::new();
    if let Some(live_pid) = pid {
        let xid = req.window_id.unwrap_or(0);
        let walked = crate::atspi::walk_tree(live_pid, xid, None);
        interactive_elements_count = walked.nodes.len();
        let bounds_map: std::collections::HashMap<usize, (i32, i32, u32, u32)> = walked
            .bounds
            .iter()
            .map(|&(idx, bx, by, bw, bh)| (idx, (bx, by, bw, bh)))
            .collect();

        for node in walked.nodes.iter().take(200) {
            if !node.role.is_empty() {
                sample_roles.insert(node.role.clone());
            }
            if let Some(ref name) = node.name {
                if !name.is_empty() {
                    if (node.role.contains("menu")
                        || node.role.contains("tab")
                        || node.role.contains("button"))
                        && menu_topology.len() < 80
                    {
                        menu_topology.push(MenuEntry {
                            path: vec![name.clone()],
                            label: name.clone(),
                            shortcut: None,
                            role: Some(node.role.clone()),
                        });
                    }
                    if discovered_anchors.len() < 40 {
                        if let Some(el_idx) = node.element_index {
                            if let Some(&(bx, by, bw, bh)) = bounds_map.get(&el_idx) {
                                let (rel_x, rel_y) = if let Some((wx, wy, ww, wh)) = window_geom {
                                    (
                                        (f64::from(bx - wx) + f64::from(bw) * 0.5) / f64::from(ww.max(1)),
                                        (f64::from(by - wy) + f64::from(bh) * 0.5) / f64::from(wh.max(1)),
                                    )
                                } else {
                                    (f64::from(bx), f64::from(by))
                                };
                                discovered_anchors.push(RelativeAnchor {
                                    name: name.clone(),
                                    role: Some(node.role.clone()),
                                    title_pattern: window_title.clone(),
                                    rel_x,
                                    rel_y,
                                });
                            }
                        }
                    }
                }
            }
        }
        if let Some(reason) = walked.degraded_reason {
            notes.push(format!("AT-SPI note: {reason}"));
        }
    }

    let atspi_blind = ((pid.is_some() || req.window_id.is_some())
        && (interactive_elements_count == 0
            || (tech_stack == "java_install4j"
                && is_shell_only_atspi(&sample_roles, interactive_elements_count))))
        || (pid.is_none() && tech_stack == "java_install4j");
    let mut remediation_hints = Vec::new();
    let recommended_interaction = if atspi_blind {
        if tech_stack == "java_install4j" {
            remediation_hints.push(
                "Configure accessibility.properties (org.GNOME.Accessibility.AtkWrapper) in the app JRE, or rely on visual grounding + hotkeys."
                    .to_owned(),
            );
        } else if tech_stack == "electron" {
            remediation_hints.push(
                "Launch with --force-renderer-accessibility for full AT-SPI2 DOM tree, or rely on visual grounding + hotkeys."
                    .to_owned(),
            );
        } else {
            remediation_hints.push(
                "AT-SPI2 returned 0 interactive elements; use visual grounding + hotkeys."
                    .to_owned(),
            );
        }
        "visual_grounding_plus_hotkeys".to_owned()
    } else {
        "atspi_semantic".to_owned()
    };

    let visual_hotspots = if atspi_blind {
        extract_visual_hotspots(req.window_id, pid, req.display_id.as_deref())
    } else {
        Vec::new()
    };

    Ok(AppFlowInspection {
        channel: "desktop_recipe".to_owned(),
        exempt_reason: None,
        app_id,
        app_version,
        version_source,
        tech_stack,
        fingerprint_sha256,
        fp8,
        executable_path: exe_path.map(|p| p.display().to_string()),
        wm_class,
        window_title,
        verified_shortcuts: shortcuts,
        menu_topology,
        interactive_elements_count,
        atspi_blind,
        recommended_interaction,
        remediation_hints,
        launch_isolation_hints,
        visual_hotspots,
        discovered_anchors,
        sample_roles: sample_roles.into_iter().collect(),
        notes,
    })
}

fn is_shell_only_atspi(sample_roles: &BTreeSet<String>, interactive_elements_count: usize) -> bool {
    if interactive_elements_count == 0 {
        return true;
    }
    let has_actionable = sample_roles.iter().any(|r| {
        matches!(
            r.as_str(),
            "push button"
                | "push_button"
                | "menu item"
                | "menu_item"
                | "text"
                | "password text"
                | "table"
                | "table cell"
                | "page tab"
                | "tab"
                | "check box"
                | "radio button"
                | "combo box"
                | "list item"
                | "tree item"
        )
    });
    !has_actionable
}

fn extract_visual_hotspots(
    window_id: Option<u64>,
    pid: Option<u32>,
    display_id: Option<&str>,
) -> Vec<VisualHotspot> {
    let target_xid = window_id.or_else(|| {
        let p = pid?;
        let target = DisplayTarget::from_display_id(display_id).ok()?;
        let ctx = global_screen_pool().get_or_connect(&target).ok()?;
        crate::x11::list_windows_with_context(&ctx, Some(p))
            .into_iter()
            .next()
            .map(|w| w.xid)
    });

    if let Some(xid) = target_xid {
        if let Ok(target) = DisplayTarget::from_display_id(display_id) {
            if let Ok(ctx) = global_screen_pool().get_or_connect(&target) {
                if let Ok(png) = crate::capture::screenshot_window_bytes_with_context(&ctx, xid) {
                    if let Some(spots) = compute_salient_grid_hotspots(&png) {
                        if !spots.is_empty() {
                            return spots;
                        }
                    }
                }
            }
        }
    }

    // Fallback structural hotspots for AT-SPI-blind windows when offscreen capture is unavailable.
    vec![
        VisualHotspot {
            id: "toolbar_band".to_owned(),
            rel_x: 0.5,
            rel_y: 0.08,
            rel_w: 0.9,
            rel_h: 0.1,
            hint: "Top menu/toolbar region (visual fallback)".to_owned(),
        },
        VisualHotspot {
            id: "primary_workspace".to_owned(),
            rel_x: 0.5,
            rel_y: 0.5,
            rel_w: 0.8,
            rel_h: 0.65,
            hint: "Central interactive canvas/table region (visual fallback)".to_owned(),
        },
        VisualHotspot {
            id: "modal_action_bar".to_owned(),
            rel_x: 0.5,
            rel_y: 0.88,
            rel_w: 0.6,
            rel_h: 0.12,
            hint: "Bottom dialog confirm/dismiss button band (visual fallback)".to_owned(),
        },
    ]
}

fn compute_salient_grid_hotspots(png_bytes: &[u8]) -> Option<Vec<VisualHotspot>> {
    let img = image::load_from_memory(png_bytes).ok()?.to_luma8();
    let (w, h) = img.dimensions();
    if w < 12 || h < 8 {
        return None;
    }
    let cols = 6u32;
    let rows = 4u32;
    let cw = (w / cols).max(1);
    let ch = (h / rows).max(1);
    let mut scored: Vec<(u64, u32, u32)> = Vec::new();

    for r in 0..rows {
        for c in 0..cols {
            let x0 = c * cw;
            let y0 = r * ch;
            let x1 = ((c + 1) * cw).min(w);
            let y1 = ((r + 1) * ch).min(h);
            let mut edge_sum: u64 = 0;
            for y in y0..y1.saturating_sub(1) {
                for x in x0..x1.saturating_sub(1) {
                    let p = i32::from(img.get_pixel(x, y).0[0]);
                    let px = i32::from(img.get_pixel(x + 1, y).0[0]);
                    let py = i32::from(img.get_pixel(x, y + 1).0[0]);
                    edge_sum += ((p - px).abs() + (p - py).abs()) as u64;
                }
            }
            if edge_sum > 0 {
                scored.push((edge_sum, c, r));
            }
        }
    }

    scored.sort_by_key(|b| std::cmp::Reverse(b.0));
    let hotspots = scored
        .into_iter()
        .take(6)
        .enumerate()
        .map(|(idx, (_score, c, r))| {
            let rel_w = 1.0 / f64::from(cols);
            let rel_h = 1.0 / f64::from(rows);
            let rel_x = (f64::from(c) + 0.5) * rel_w;
            let rel_y = (f64::from(r) + 0.5) * rel_h;
            VisualHotspot {
                id: format!("hotspot_{idx}_{c}_{r}"),
                rel_x,
                rel_y,
                rel_w,
                rel_h,
                hint: format!("High-contrast visual region (grid {c},{r})"),
            }
        })
        .collect();
    Some(hotspots)
}

fn is_chrome_or_chromium(
    exe_path: Option<&Path>,
    wm_class: Option<&str>,
    cmdline: &str,
    raw_app_path: Option<&str>,
) -> bool {
    let check = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("google-chrome")
            || lower.ends_with("/chrome")
            || lower == "chrome"
            || lower.contains("chromium")
    };
    exe_path
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .is_some_and(check)
        || wm_class.is_some_and(check)
        || raw_app_path.is_some_and(check)
        || cmdline.split_whitespace().next().is_some_and(check)
}

fn resolve_proc_exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

fn resolve_proc_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Some(parts.join(" "))
}

type DetectedTuple = (String, String, VersionSource, String, Option<PathBuf>);

fn is_install4j_dir(dir: &Path) -> bool {
    dir.join(".install4j").join("response.varfile").exists()
        || dir.join("jars").is_dir()
        || dir.join("usergui").is_dir()
}

fn resolve_install4j_dir(
    base_dir: Option<&Path>,
    pid: Option<u32>,
    cmdline: &str,
) -> Option<PathBuf> {
    if let Some(dir) = base_dir {
        if is_install4j_dir(dir) {
            return Some(dir.to_path_buf());
        }
    }
    if let Some(p) = pid {
        if let Ok(cwd) = fs::read_link(format!("/proc/{p}/cwd")) {
            if is_install4j_dir(&cwd) {
                return Some(cwd);
            }
        }
    }
    for token in cmdline.split(|c: char| c.is_whitespace() || c == ':') {
        if let Some(idx) = token.find("/.install4j/") {
            let root = PathBuf::from(&token[..idx]);
            if is_install4j_dir(&root) {
                return Some(root);
            }
        }
        if token.ends_with("/launcher.jar") || token.contains("twslaunch") {
            let p = Path::new(token);
            if let Some(parent) = p.parent() {
                let candidate = if parent.file_name().and_then(|n| n.to_str()) == Some("jars") {
                    parent.parent().unwrap_or(parent)
                } else {
                    parent
                };
                if is_install4j_dir(candidate) {
                    return Some(candidate.to_path_buf());
                }
            }
        }
    }
    None
}

/// Tier 2: Java `install4j` detector (e.g. IBKR TWS and Schwab Thinkorswim).
fn inspect_java_install4j(
    dir: &Path,
    window_title: Option<&str>,
    shortcuts: &mut Vec<VerifiedShortcut>,
    menu_topology: &mut Vec<MenuEntry>,
    launch_isolation_hints: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Option<DetectedTuple> {
    let varfile = dir.join(".install4j").join("response.varfile");
    let jars_dir = dir.join("jars");
    let usergui_dir = dir.join("usergui");
    if !varfile.exists() && !jars_dir.is_dir() && !usergui_dir.is_dir() {
        return None;
    }

    let mut version = find_highest_usergui_jar(&usergui_dir).map(|(ver, _)| ver);
    let usergui_jar = find_highest_usergui_jar(&usergui_dir).map(|(_, jar)| jar);

    if version.is_none() {
        if let Ok(text) = fs::read_to_string(&varfile) {
            version = parse_install4j_version(&text);
        }
    }

    // Pick the highest-versioned launch JAR (e.g. twslaunch-1052.jar > twslaunch-1050.jar),
    // or fall back to Thinkorswim's `tos-usergui-base-*.jar` / `launcher.jar`.
    let primary_jar = usergui_jar
        .or_else(|| find_highest_version_jar(&jars_dir))
        .or_else(|| {
            let launcher = dir.join("launcher.jar");
            launcher.is_file().then_some(launcher)
        });
    if let Some(ref jar_path) = primary_jar {
        if let Ok((impl_ver, main_class, jar_shortcuts)) = inspect_jar_archive(jar_path) {
            if version.is_none() {
                version = impl_ver;
            }
            if let Some(mc) = main_class {
                notes.push(format!("Main-Class: {mc}"));
                menu_topology.push(MenuEntry {
                    path: vec!["Entry".to_owned(), mc.clone()],
                    label: mc,
                    shortcut: None,
                    role: Some("java_main_class".to_owned()),
                });
            }
            shortcuts.extend(jar_shortcuts);
        }
    }

    if version.is_none() {
        version = window_title.and_then(parse_window_title_build);
    }

    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("java-app")
        .to_ascii_lowercase();
    let is_thinkorswim = dir_name.contains("thinkorswim")
        || dir.join("thinkorswim").is_file()
        || usergui_dir.is_dir()
        || dir.join("jxbrowser").is_dir()
        || window_title.is_some_and(|t| t.to_ascii_lowercase().contains("thinkorswim"));
    let is_tws = !is_thinkorswim && (dir_name.contains("tws") || dir.join("tws.vmoptions").is_file());

    let app_id = if is_thinkorswim {
        "thinkorswim".to_owned()
    } else if is_tws {
        "tws".to_owned()
    } else {
        dir_name
    };

    if is_thinkorswim {
        launch_isolation_hints.push("unset DBUS_SESSION_BUS_ADDRESS".to_owned());
        launch_isolation_hints.push("-Djxbrowser.linux.deps.check.disabled=true".to_owned());
        if dir.join("jxbrowser").is_dir() {
            notes.push("Embedded JxBrowser Chromium runtime detected".to_owned());
        }
        if shortcuts.is_empty() {
            shortcuts.push(VerifiedShortcut {
                id: "tos.dismiss_modal".to_owned(),
                keys: vec!["Escape".to_owned()],
                description: Some("Dismiss modal dialog or popup".to_owned()),
                source: "java_install4j_default".to_owned(),
            });
            shortcuts.push(VerifiedShortcut {
                id: "tos.symbol_focus".to_owned(),
                keys: vec!["ctrl".to_owned(), "l".to_owned()],
                description: Some("Focus symbol lookup box".to_owned()),
                source: "java_install4j_default".to_owned(),
            });
        }
    } else if is_tws {
        launch_isolation_hints.push(
            "-J-DjtsConfigDir=${CUA_YCWANG_HOME:-$HOME/.cua-ycwang}/jts".to_owned(),
        );
        if shortcuts.is_empty() {
            shortcuts.push(VerifiedShortcut {
                id: "tws.dismiss_modal".to_owned(),
                keys: vec!["Escape".to_owned()],
                description: Some("Dismiss startup warning or pending tasks modal".to_owned()),
                source: "java_install4j_default".to_owned(),
            });
            shortcuts.push(VerifiedShortcut {
                id: "tws.order_ticket".to_owned(),
                keys: vec!["ctrl".to_owned(), "o".to_owned()],
                description: Some("Open Order Ticket".to_owned()),
                source: "java_install4j_default".to_owned(),
            });
        }
    }

    let ver = version.unwrap_or_else(|| "unknown".to_owned());
    Some((
        app_id,
        ver,
        VersionSource::Install4j,
        "java_install4j".to_owned(),
        primary_jar.or_else(|| varfile.exists().then_some(varfile)),
    ))
}

pub(crate) fn parse_install4j_version(text: &str) -> Option<String> {
    // Matches e.g. `# Trader Workstation latest (10.52.1d)` or `# install4j response file for thinkorswim 1991.3.0`
    for line in text.lines() {
        if let (Some(start), Some(end)) = (line.rfind('('), line.rfind(')')) {
            if start < end {
                let candidate = line[start + 1..end].trim();
                if candidate.chars().any(|c| c.is_ascii_digit()) {
                    return Some(candidate.to_owned());
                }
            }
        }
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            if let Some(last) = trimmed.split_whitespace().last() {
                if last.chars().any(|c| c.is_ascii_digit()) && last.contains('.') {
                    return Some(last.to_owned());
                }
            }
        }
    }
    None
}

pub(crate) fn parse_window_title_build(title: &str) -> Option<String> {
    // Matches e.g. `Main@thinkorswim [build 1994]`
    let lower = title.to_ascii_lowercase();
    let idx = lower.find("[build ")?;
    let rest = &title[idx + 7..];
    let end = rest.find(']')?;
    let build = rest[..end].trim();
    (!build.is_empty() && build.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .then(|| build.to_owned())
}

fn parse_version_tuple(s: &str) -> Vec<u64> {
    s.split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

fn find_highest_usergui_jar(usergui_dir: &Path) -> Option<(String, PathBuf)> {
    let entries = fs::read_dir(usergui_dir).ok()?;
    let mut candidates: Vec<(Vec<u64>, String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let Some(ver_name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !ver_name.chars().any(|c| c.is_ascii_digit()) {
            continue;
        }
        let base_jar = dir.join(format!("tos-usergui-base-{ver_name}.jar"));
        let jar_path = if base_jar.is_file() {
            Some(base_jar)
        } else {
            fs::read_dir(&dir).ok().and_then(|sub| {
                sub.flatten()
                    .map(|e| e.path())
                    .find(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("tos-usergui-base-") && n.ends_with(".jar"))
                    })
            })
        };
        if let Some(jar) = jar_path {
            candidates.push((parse_version_tuple(ver_name), ver_name.to_owned(), jar));
        }
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    candidates.into_iter().next().map(|(_, ver, jar)| (ver, jar))
}

fn find_highest_version_jar(jars_dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(jars_dir).ok()?;
    let mut jars: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jar"))
        .collect();
    // Prefer `twslaunch-*.jar` or `launcher*.jar`, sorted by numeric version descending.
    jars.sort_by(|a, b| {
        let name_a = a.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let name_b = b.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let is_launch_a = name_a.contains("launch");
        let is_launch_b = name_b.contains("launch");
        is_launch_b
            .cmp(&is_launch_a)
            .then_with(|| extract_trailing_number(name_b).cmp(&extract_trailing_number(name_a)))
            .then_with(|| name_b.cmp(name_a))
    });
    jars.into_iter().next()
}

fn extract_trailing_number(s: &str) -> u64 {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().unwrap_or(0)
}

fn inspect_jar_archive(
    jar_path: &Path,
) -> Result<(Option<String>, Option<String>, Vec<VerifiedShortcut>)> {
    let file = fs::File::open(jar_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut impl_ver = None;
    let mut main_class = None;
    let shortcuts = Vec::new();

    if let Ok(mut manifest) = archive.by_name("META-INF/MANIFEST.MF") {
        let mut content = String::new();
        manifest.read_to_string(&mut content)?;
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("Implementation-Version:") {
                impl_ver = Some(v.trim().to_owned());
            } else if let Some(mc) = line.strip_prefix("Main-Class:") {
                main_class = Some(mc.trim().to_owned());
            }
        }
    }

    Ok((impl_ver, main_class, shortcuts))
}

/// Tier 2: `.NET / Avalonia` detector (e.g. `/opt/v2rayN/`).
fn inspect_dotnet_avalonia(
    dir: &Path,
    exe_path: Option<&Path>,
    notes: &mut Vec<String>,
) -> Option<DetectedTuple> {
    let deps_path = fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        name.ends_with(".deps.json").then_some(p)
    })?;

    let text = fs::read_to_string(&deps_path).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    let stem = deps_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".deps.json"))
        .unwrap_or("dotnet-app")
        .to_owned();

    let mut app_version = "unknown".to_owned();
    if let Some(targets) = json.get("targets").and_then(Value::as_object) {
        for (_target_name, libs) in targets {
            if let Some(lib_map) = libs.as_object() {
                for key in lib_map.keys() {
                    if let Some((name, ver)) = key.split_once('/') {
                        if name.eq_ignore_ascii_case(&stem) {
                            app_version = ver.to_owned();
                        } else if name == "Avalonia" {
                            notes.push(format!("Avalonia/{ver}"));
                        }
                    }
                }
            }
        }
    }

    let fp_target = exe_path
        .filter(|p| p.is_file())
        .map(Path::to_path_buf)
        .unwrap_or(deps_path);
    Some((
        stem.to_ascii_lowercase(),
        app_version,
        VersionSource::DotnetDeps,
        "dotnet_avalonia".to_owned(),
        Some(fp_target),
    ))
}

/// Tier 1: Electron / VS Code detector (handles unpacked `resources/app/package.json` without `app.asar`).
fn inspect_electron_app(
    dir: &Path,
    exe_path: Option<&Path>,
    shortcuts: &mut Vec<VerifiedShortcut>,
    menu_topology: &mut Vec<MenuEntry>,
    launch_isolation_hints: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Option<DetectedTuple> {
    let pkg_json = dir.join("resources").join("app").join("package.json");
    if !pkg_json.is_file() {
        return None;
    }

    let text = fs::read_to_string(&pkg_json).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    let name = json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("electron-app")
        .to_ascii_lowercase();
    let version = json
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();

    launch_isolation_hints
        .push("--user-data-dir=${CUA_YCWANG_HOME:-$HOME/.cua-ycwang}/electron_profile".to_owned());

    let collect_contributes = |doc: &Value,
                               source: &str,
                               shortcuts: &mut Vec<VerifiedShortcut>,
                               menu_topology: &mut Vec<MenuEntry>| {
        if let Some(kb) = doc.pointer("/contributes/keybindings").and_then(Value::as_array) {
            for item in kb {
                if shortcuts.len() >= 64 {
                    break;
                }
                if let (Some(cmd), Some(key)) = (
                    item.get("command").and_then(Value::as_str),
                    item.get("key").and_then(Value::as_str),
                ) {
                    shortcuts.push(VerifiedShortcut {
                        id: cmd.to_owned(),
                        keys: key.split('+').map(str::trim).map(ToOwned::to_owned).collect(),
                        description: None,
                        source: source.to_owned(),
                    });
                }
            }
        }

        if let Some(cmds) = doc.pointer("/contributes/commands").and_then(Value::as_array) {
            for item in cmds {
                if menu_topology.len() >= 64 {
                    break;
                }
                if let Some(title) = item.get("title").and_then(Value::as_str) {
                    menu_topology.push(MenuEntry {
                        path: vec![title.to_owned()],
                        label: title.to_owned(),
                        shortcut: None,
                        role: Some("command".to_owned()),
                    });
                }
            }
        }
    };

    collect_contributes(&json, "package.json", shortcuts, menu_topology);

    // Built-in Electron extensions (e.g. VS Code extensions/*/package.json).
    let ext_dir = dir.join("resources").join("app").join("extensions");
    if ext_dir.is_dir() && (shortcuts.is_empty() || menu_topology.is_empty()) {
        if let Ok(entries) = fs::read_dir(&ext_dir) {
            for entry in entries.flatten().take(30) {
                let ext_pkg = entry.path().join("package.json");
                if let Ok(ext_text) = fs::read_to_string(&ext_pkg) {
                    if let Ok(ext_json) = serde_json::from_str::<Value>(&ext_text) {
                        collect_contributes(&ext_json, "extension_package.json", shortcuts, menu_topology);
                    }
                }
                if shortcuts.len() >= 32 && menu_topology.len() >= 32 {
                    break;
                }
            }
        }
    }

    // Read VS Code user keybindings.json if present.
    if name == "code" {
        if let Ok(home) = std::env::var("HOME") {
            let user_kb = PathBuf::from(home).join(".config/Code/User/keybindings.json");
            if user_kb.is_file() {
                notes.push(format!("User keybindings: {}", user_kb.display()));
                if let Ok(kb_text) = fs::read_to_string(&user_kb) {
                    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&kb_text) {
                        for item in arr.iter().take(64) {
                            if let (Some(cmd), Some(key)) = (
                                item.get("command").and_then(Value::as_str),
                                item.get("key").and_then(Value::as_str),
                            ) {
                                shortcuts.push(VerifiedShortcut {
                                    id: cmd.to_owned(),
                                    keys: key
                                        .split('+')
                                        .map(str::trim)
                                        .map(ToOwned::to_owned)
                                        .collect(),
                                    description: None,
                                    source: "user_keybindings.json".to_owned(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let fp_target = exe_path
        .filter(|p| p.is_file())
        .map(Path::to_path_buf)
        .unwrap_or(pkg_json);
    Some((
        name,
        version,
        VersionSource::PackageJson,
        "electron".to_owned(),
        Some(fp_target),
    ))
}

fn inspect_native_fallback(
    exe_path: Option<&Path>,
    wm_class: Option<&str>,
    notes: &mut Vec<String>,
) -> DetectedTuple {
    let app_id = exe_path
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .or(wm_class)
        .unwrap_or("unknown-app")
        .to_ascii_lowercase();

    let mut version = "unknown".to_owned();
    let mut source = VersionSource::PeOrElf;
    if let Some(exe) = exe_path.filter(|p| p.is_file()) {
        if let Some(dpkg_ver) = query_dpkg_version(exe) {
            version = dpkg_ver;
            source = VersionSource::Dpkg;
            notes.push("Version resolved via dpkg-query".to_owned());
        }
    }

    (
        app_id,
        version,
        source,
        "native_elf".to_owned(),
        exe_path.map(Path::to_path_buf),
    )
}

fn query_dpkg_version(path: &Path) -> Option<String> {
    let out = std::process::Command::new("dpkg-query")
        .arg("-S")
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pkg = stdout.split(':').next()?.trim();
    if pkg.is_empty() {
        return None;
    }
    let ver_out = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}\n", pkg])
        .output()
        .ok()?;
    ver_out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&ver_out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn query_chrome_cli_version(path: &Path) -> Option<String> {
    let out = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split_whitespace()
        .rev()
        .find(|tok| tok.chars().any(|c| c.is_ascii_digit()) && tok.contains('.'))
        .map(ToOwned::to_owned)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_targets_route_to_browser_exempt() {
        let res = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some("/opt/google/chrome/chrome".to_owned()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res.channel, "browser_exempt");
        assert_eq!(res.app_id, "google-chrome");
        assert_eq!(res.tech_stack, "chromium_browser");
        assert_eq!(res.recommended_interaction, "hybrid_cdp_and_os_chrome");
        assert!(!res.launch_isolation_hints.is_empty());
        assert!(res.exempt_reason.is_some());
        if Path::new("/opt/google/chrome/chrome").is_file() {
            assert_ne!(res.app_version, "unknown");
            assert_ne!(res.app_version, "exempt");
            assert!(matches!(
                res.version_source,
                VersionSource::Dpkg | VersionSource::PeOrElf
            ));
            assert_eq!(res.fp8.len(), 8);
        }
    }

    #[test]
    fn parses_install4j_response_varfile_version() {
        let sample = "# Trader Workstation latest (10.52.1d)\nsys.installationDir=/home/ycwang/Jts\n";
        assert_eq!(parse_install4j_version(sample).as_deref(), Some("10.52.1d"));
    }

    #[test]
    fn inspects_dotnet_avalonia_deps_json() {
        let dir = tempfile::tempdir().unwrap();
        let deps = dir.path().join("v2rayN.deps.json");
        fs::write(
            &deps,
            r#"{
              "runtimeTarget": { "name": ".NETCoreApp,Version=v10.0/linux-x64" },
              "targets": {
                ".NETCoreApp,Version=v10.0/linux-x64": {
                  "v2rayN/7.25.1": {},
                  "Avalonia/12.1.2": {}
                }
              }
            }"#,
        )
        .unwrap();

        let res = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some(dir.path().display().to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res.app_id, "v2rayn");
        assert_eq!(res.app_version, "7.25.1");
        assert_eq!(res.version_source, VersionSource::DotnetDeps);
        assert_eq!(res.tech_stack, "dotnet_avalonia");
        assert!(res.notes.iter().any(|n| n.contains("Avalonia/12.1.2")));
    }

    #[test]
    fn inspects_electron_unpacked_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let app_dir = dir.path().join("resources").join("app");
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join("package.json"),
            r#"{
              "name": "MyElectronApp",
              "version": "1.146.0",
              "contributes": {
                "keybindings": [{"command": "workbench.action.files.save", "key": "ctrl+s"}],
                "commands": [{"title": "Save File"}]
              }
            }"#,
        )
        .unwrap();

        let res = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some(dir.path().display().to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res.app_id, "myelectronapp");
        assert_eq!(res.app_version, "1.146.0");
        assert_eq!(res.version_source, VersionSource::PackageJson);
        assert_eq!(res.verified_shortcuts.len(), 1);
        assert_eq!(res.menu_topology.len(), 1);
    }

    #[test]
    fn parses_thinkorswim_varfile_and_window_title_build() {
        let varfile = "# install4j response file for thinkorswim 1991.3.0\nuserDomain=schwab\n";
        assert_eq!(parse_install4j_version(varfile).as_deref(), Some("1991.3.0"));
        assert_eq!(
            parse_window_title_build("Main@thinkorswim [build 1994]").as_deref(),
            Some("1994")
        );
    }

    #[test]
    fn inspects_thinkorswim_usergui_jar_and_jxbrowser_isolation_hints() {
        let dir = tempfile::tempdir().unwrap();
        let i4j = dir.path().join(".install4j");
        let ug1 = dir.path().join("usergui").join("1994.1.10");
        let ug2 = dir.path().join("usergui").join("1994.1.16");
        let jxb = dir.path().join("jxbrowser");
        fs::create_dir_all(&i4j).unwrap();
        fs::create_dir_all(&ug1).unwrap();
        fs::create_dir_all(&ug2).unwrap();
        fs::create_dir_all(&jxb).unwrap();
        fs::write(
            i4j.join("response.varfile"),
            "# install4j response file for thinkorswim 1991.3.0\n",
        )
        .unwrap();
        fs::write(ug1.join("tos-usergui-base-1994.1.10.jar"), b"old").unwrap();
        fs::write(ug2.join("tos-usergui-base-1994.1.16.jar"), b"new").unwrap();
        fs::write(dir.path().join("thinkorswim"), b"#!/bin/sh\n").unwrap();

        let res = inspect_app_flow(InspectAppFlowRequest {
            app_path: Some(dir.path().display().to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res.app_id, "thinkorswim");
        assert_eq!(res.app_version, "1994.1.16");
        assert_eq!(res.version_source, VersionSource::Install4j);
        assert_eq!(res.tech_stack, "java_install4j");
        assert!(res
            .launch_isolation_hints
            .iter()
            .any(|h| h.contains("unset DBUS_SESSION_BUS_ADDRESS")));
        assert!(res
            .notes
            .iter()
            .any(|n| n.contains("JxBrowser")));
    }

    #[test]
    fn java_install4j_shell_only_atspi_nodes_stay_atspi_blind() {
        let mut shell_roles = BTreeSet::new();
        shell_roles.insert("application".to_owned());
        shell_roles.insert("frame".to_owned());
        shell_roles.insert("panel".to_owned());
        assert!(is_shell_only_atspi(&shell_roles, 3));

        shell_roles.insert("push button".to_owned());
        assert!(!is_shell_only_atspi(&shell_roles, 4));
    }
}
