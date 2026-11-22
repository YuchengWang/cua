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
use cua_driver_core::app_recipe::{fp8_of, MenuEntry, VerifiedShortcut, VersionSource};
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
        let fp = exe_path
            .as_deref()
            .and_then(|p| sha256_file(p).ok())
            .unwrap_or_else(|| sha256_bytes(b"chrome-browser-exempt"));
        let fp8 = fp8_of(&fp).to_owned();
        return Ok(AppFlowInspection {
            channel: "browser_exempt".to_owned(),
            exempt_reason: Some(
                "Chrome/Chromium is exempt from GUI reverse-engineering; use chrome_devtools MCP or browser_* tools."
                    .to_owned(),
            ),
            app_id: "google-chrome".to_owned(),
            app_version: "exempt".to_owned(),
            version_source: VersionSource::Unknown,
            tech_stack: "chromium_browser".to_owned(),
            fingerprint_sha256: fp,
            fp8,
            executable_path: exe_path.map(|p| p.display().to_string()),
            wm_class,
            window_title,
            verified_shortcuts: Vec::new(),
            menu_topology: Vec::new(),
            interactive_elements_count: 0,
            sample_roles: Vec::new(),
            notes: vec!["Routed to browser_exempt channel".to_owned()],
        });
    }

    let mut notes = Vec::new();
    let mut shortcuts = Vec::new();
    let mut menu_topology = Vec::new();

    // Resolve base directory for static artifact inspection.
    let base_dir = exe_path.as_deref().map(|p| {
        if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent().unwrap_or_else(|| Path::new("/")).to_path_buf()
        }
    });

    let (app_id, app_version, version_source, tech_stack, fp_target) =
        if let Some(dir) = base_dir.as_deref() {
            if let Some(java) = inspect_java_install4j(dir, &mut shortcuts, &mut notes) {
                java
            } else if let Some(dotnet) = inspect_dotnet_avalonia(dir, exe_path.as_deref(), &mut notes)
            {
                dotnet
            } else if let Some(electron) =
                inspect_electron_app(dir, exe_path.as_deref(), &mut shortcuts, &mut menu_topology, &mut notes)
            {
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
    if let Some(live_pid) = pid {
        let xid = req.window_id.unwrap_or(0);
        let walked = crate::atspi::walk_tree(live_pid, xid, None);
        interactive_elements_count = walked.nodes.len();
        for node in walked.nodes.iter().take(200) {
            if !node.role.is_empty() {
                sample_roles.insert(node.role.clone());
            }
            if node.role.contains("menu") {
                if let Some(ref name) = node.name {
                    if !name.is_empty() {
                        menu_topology.push(MenuEntry {
                            path: vec![name.clone()],
                            label: name.clone(),
                            shortcut: None,
                            role: Some(node.role.clone()),
                        });
                    }
                }
            }
        }
        if let Some(reason) = walked.degraded_reason {
            notes.push(format!("AT-SPI note: {reason}"));
        }
    }

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
        sample_roles: sample_roles.into_iter().collect(),
        notes,
    })
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

/// Tier 2: Java `install4j` detector (e.g. IBKR TWS).
fn inspect_java_install4j(
    dir: &Path,
    shortcuts: &mut Vec<VerifiedShortcut>,
    notes: &mut Vec<String>,
) -> Option<DetectedTuple> {
    let varfile = dir.join(".install4j").join("response.varfile");
    let jars_dir = dir.join("jars");
    if !varfile.exists() && !jars_dir.is_dir() {
        return None;
    }

    let mut version = None;
    if let Ok(text) = fs::read_to_string(&varfile) {
        version = parse_install4j_version(&text);
    }

    // Pick the highest-versioned launch JAR (e.g. twslaunch-1052.jar > twslaunch-1050.jar).
    let primary_jar = find_highest_version_jar(&jars_dir);
    if let Some(ref jar_path) = primary_jar {
        if let Ok((impl_ver, main_class, jar_shortcuts)) = inspect_jar_archive(jar_path) {
            if version.is_none() {
                version = impl_ver;
            }
            if let Some(mc) = main_class {
                notes.push(format!("Main-Class: {mc}"));
            }
            shortcuts.extend(jar_shortcuts);
        }
    }

    let app_id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("java-app")
        .to_ascii_lowercase();
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
    // Matches e.g. `# Trader Workstation latest (10.52.1d)`
    for line in text.lines() {
        if let (Some(start), Some(end)) = (line.rfind('('), line.rfind(')')) {
            if start < end {
                let candidate = line[start + 1..end].trim();
                if candidate.chars().any(|c| c.is_ascii_digit()) {
                    return Some(candidate.to_owned());
                }
            }
        }
    }
    None
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

    if let Some(kb) = json.pointer("/contributes/keybindings").and_then(Value::as_array) {
        for item in kb.iter().take(64) {
            if let (Some(cmd), Some(key)) = (
                item.get("command").and_then(Value::as_str),
                item.get("key").and_then(Value::as_str),
            ) {
                shortcuts.push(VerifiedShortcut {
                    id: cmd.to_owned(),
                    keys: key.split('+').map(str::trim).map(ToOwned::to_owned).collect(),
                    description: None,
                    source: "package.json".to_owned(),
                });
            }
        }
    }

    if let Some(cmds) = json.pointer("/contributes/commands").and_then(Value::as_array) {
        for item in cmds.iter().take(64) {
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
        assert_eq!(res.tech_stack, "chromium_browser");
        assert!(res.exempt_reason.is_some());
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
}
