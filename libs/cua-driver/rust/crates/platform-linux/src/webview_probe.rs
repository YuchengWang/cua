// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Configurable WebView debug endpoint prober (`~/.config/cua-ycwang/webview_probes.json`).
//!
//! Discovers Electron, CEF, JxBrowser (TWS/ThinkorSwim), QtWebEngine,
//! WebKitGTK, and user-configured WebView debug targets attached to a process
//! tree by correlating:
//! - `/proc/<pid>/{comm,cmdline,exe,environ,maps}` rule matches,
//! - `/proc/<pid>/fd` socket inodes with `/proc/net/{tcp,tcp6}` loopback listeners,
//! - `/proc/<pid>/fd` + `/proc/net/unix` Inspector Unix Domain Sockets, and
//! - live loopback HTTP `/json/version` & `/json/list` DevTools endpoints.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::browser_platform::{
    parse_proc_net_loopback_listeners, process_family_pids, socket_inodes_for_process_tree,
};
use crate::hot_config::HotJsonCache;

const DEFAULT_HTTP_PROBE_TIMEOUT_MS: u64 = 1_200;
const MAX_HTTP_PROBE_PORTS: usize = 16;
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_MAPS_BYTES: usize = 512 * 1024;

static WEBVIEW_PROBE_CACHE: OnceLock<HotJsonCache<WebviewProbeConfig>> = OnceLock::new();

fn probe_cache() -> &'static HotJsonCache<WebviewProbeConfig> {
    WEBVIEW_PROBE_CACHE.get_or_init(HotJsonCache::new)
}

pub fn default_config_path() -> Option<PathBuf> {
    cua_driver_core::ycwang_env::resolve_ycwang_config_dir().map(|d| d.join("webview_probes.json"))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebviewProbeConfig {
    #[serde(default)]
    pub replace_defaults: bool,
    #[serde(default)]
    pub rules: Vec<WebviewProbeRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebviewProbeRule {
    pub id: String,
    pub engine: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub cmdline_regex: Option<String>,
    #[serde(default)]
    pub exe_regex: Option<String>,
    #[serde(default)]
    pub comm_regex: Option<String>,
    #[serde(default)]
    pub maps_regex: Option<String>,
    #[serde(default)]
    pub unix_socket_regex: Option<String>,
    #[serde(default)]
    pub port_flags: Vec<String>,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default)]
    pub default_ports: Vec<u16>,
    #[serde(default)]
    pub hints: Option<String>,
}

fn default_protocol() -> String {
    "cdp".to_owned()
}

pub fn builtin_rules() -> Vec<WebviewProbeRule> {
    vec![
        WebviewProbeRule {
            id: "electron".into(),
            engine: "electron".into(),
            protocol: "cdp".into(),
            cmdline_regex: Some(
                r"(?i)(electron\.app|resources/app\.asar|--enable-electron|electron\b|--type=renderer)"
                    .into(),
            ),
            exe_regex: Some(r"(?i)(/electron$|/electron\b)".into()),
            comm_regex: Some(r"(?i)^electron$".into()),
            maps_regex: Some(r"(?i)libelectron|electron".into()),
            unix_socket_regex: Some(r"(?i)(devtools|electron|inspector)".into()),
            port_flags: vec![
                "--remote-debugging-port=".into(),
                "--inspect=".into(),
                "--inspect-brk=".into(),
            ],
            env_keys: vec!["ELECTRON_REMOTE_DEBUGGING_PORT".into()],
            default_ports: Vec::new(),
            hints: Some(
                "Electron WebView: relaunch with --remote-debugging-port=9222 if no listener is open."
                    .into(),
            ),
        },
        WebviewProbeRule {
            id: "cef".into(),
            engine: "cef".into(),
            protocol: "cdp".into(),
            cmdline_regex: Some(r"(?i)(libcef|cef_subprocess|--cef|--remote-debugging-port=)".into()),
            exe_regex: Some(r"(?i)(cef|libcef)".into()),
            comm_regex: None,
            maps_regex: Some(r"(?i)libcef\.so".into()),
            unix_socket_regex: Some(r"(?i)(cef|devtools)".into()),
            port_flags: vec!["--remote-debugging-port=".into()],
            env_keys: vec!["CEF_REMOTE_DEBUGGING_PORT".into()],
            default_ports: Vec::new(),
            hints: Some(
                "CEF embedded browser: enable remote_debugging_port or pass --remote-debugging-port=9222."
                    .into(),
            ),
        },
        WebviewProbeRule {
            id: "jxbrowser".into(),
            engine: "jxbrowser".into(),
            protocol: "cdp".into(),
            cmdline_regex: Some(
                r"(?i)(jxbrowser|teamdev\.jxbrowser|-Djxbrowser\.|--remote-debugging-port=)"
                    .into(),
            ),
            exe_regex: Some(r"(?i)(jxbrowser|chromium)".into()),
            comm_regex: None,
            maps_regex: Some(r"(?i)jxbrowser|libjxbrowser".into()),
            unix_socket_regex: Some(r"(?i)(jxbrowser|devtools)".into()),
            port_flags: vec![
                "--remote-debugging-port=".into(),
                "-Djxbrowser.remote.debugging.port=".into(),
                "-Djxbrowser.debugging.port=".into(),
            ],
            env_keys: vec!["JXBROWSER_REMOTE_DEBUGGING_PORT".into()],
            default_ports: Vec::new(),
            hints: Some(
                "JxBrowser (e.g. ThinkorSwim/TWS): pass -Djxbrowser.remote.debugging.port=9222 (or EngineOptions.remoteDebuggingPort)."
                    .into(),
            ),
        },
        WebviewProbeRule {
            id: "qtwebengine".into(),
            engine: "qtwebengine".into(),
            protocol: "cdp".into(),
            cmdline_regex: Some(r"(?i)(qtwebengineprocess|qtwebengine)".into()),
            exe_regex: Some(r"(?i)qtwebengine".into()),
            comm_regex: Some(r"(?i)qtwebengine".into()),
            maps_regex: Some(r"(?i)libQt[56]WebEngineCore\.so".into()),
            unix_socket_regex: Some(r"(?i)(qtwebengine|devtools)".into()),
            port_flags: vec!["--remote-debugging-port=".into()],
            env_keys: vec!["QTWEBENGINE_REMOTE_DEBUGGING".into()],
            default_ports: Vec::new(),
            hints: Some(
                "QtWebEngine: set QTWEBENGINE_REMOTE_DEBUGGING=127.0.0.1:9222 or pass --remote-debugging-port=9222."
                    .into(),
            ),
        },
        WebviewProbeRule {
            id: "webkitgtk".into(),
            engine: "webkitgtk".into(),
            protocol: "webkit_inspector".into(),
            cmdline_regex: Some(
                r"(?i)(webkitnetworkprocess|webkitwebprocess|webkit2gtk|--inspector-port=)"
                    .into(),
            ),
            exe_regex: Some(r"(?i)webkit".into()),
            comm_regex: Some(r"(?i)webkit".into()),
            maps_regex: Some(r"(?i)libwebkit2gtk".into()),
            unix_socket_regex: Some(r"(?i)(webkit|inspector)".into()),
            port_flags: vec!["--inspector-port=".into()],
            env_keys: vec![
                "WEBKIT_INSPECTOR_SERVER".into(),
                "WEBKIT_INSPECTOR_HTTP_SERVER".into(),
            ],
            default_ports: Vec::new(),
            hints: Some(
                "WebKitGTK: set WEBKIT_INSPECTOR_SERVER=127.0.0.1:2999 or WEBKIT_INSPECTOR_HTTP_SERVER=127.0.0.1:2999."
                    .into(),
            ),
        },
    ]
}

pub fn load_rules(config_override: Option<&Path>) -> Result<(Vec<WebviewProbeRule>, Option<PathBuf>)> {
    let resolved = config_override
        .map(Path::to_path_buf)
        .or_else(default_config_path);
    let mut rules = Vec::new();
    let mut active_path = None;
    if let Some(path) = resolved {
        if let Some(cfg) = probe_cache().get_or_load(&path)? {
            active_path = Some(path);
            rules.extend(cfg.rules.iter().cloned());
            if cfg.replace_defaults {
                return Ok((rules, active_path));
            }
        }
    }
    rules.extend(builtin_rules());
    Ok((rules, active_path))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcProcessSnapshot {
    pub pid: i64,
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline_args: Vec<String>,
    pub cmdline_joined: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MatchedEngine {
    pub rule_id: String,
    pub engine: String,
    pub protocol: String,
    pub matched_pid: i64,
    pub match_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnixSocketEntry {
    pub inode: u64,
    pub listening: bool,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InspectorUnixSocket {
    pub inode: u64,
    pub path: String,
    pub listening: bool,
    pub matched_rules: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CdpPageTarget {
    pub id: Option<String>,
    pub title: Option<String>,
    pub target_type: Option<String>,
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbedHttpEndpoint {
    pub port: u16,
    pub cdp_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_ws_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub page_targets: Vec<CdpPageTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WebviewProbeReport {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    pub process_count: usize,
    pub matched_engines: Vec<MatchedEngine>,
    pub listening_ports: Vec<u16>,
    pub configured_ports: Vec<u16>,
    pub unix_sockets: Vec<InspectorUnixSocket>,
    pub endpoints: Vec<ProbedHttpEndpoint>,
}

#[derive(Clone, Debug)]
pub struct WebviewSummary {
    pub engines: Vec<String>,
    pub listening_ports: Vec<u16>,
    pub unix_sockets: Vec<String>,
    pub hints: Vec<String>,
}

struct CompiledRule {
    rule: WebviewProbeRule,
    cmdline_re: Option<Regex>,
    exe_re: Option<Regex>,
    comm_re: Option<Regex>,
    maps_re: Option<Regex>,
    unix_socket_re: Option<Regex>,
}

impl CompiledRule {
    fn compile(rule: WebviewProbeRule) -> Result<Self> {
        let compile_opt = |pat: &Option<String>, field: &str, id: &str| -> Result<Option<Regex>> {
            pat.as_deref()
                .map(|p| {
                    Regex::new(p).with_context(|| {
                        format!("invalid regex in webview rule '{id}' field '{field}'")
                    })
                })
                .transpose()
        };
        Ok(Self {
            cmdline_re: compile_opt(&rule.cmdline_regex, "cmdline_regex", &rule.id)?,
            exe_re: compile_opt(&rule.exe_regex, "exe_regex", &rule.id)?,
            comm_re: compile_opt(&rule.comm_regex, "comm_regex", &rule.id)?,
            maps_re: compile_opt(&rule.maps_regex, "maps_regex", &rule.id)?,
            unix_socket_re: compile_opt(&rule.unix_socket_regex, "unix_socket_regex", &rule.id)?,
            rule,
        })
    }

    fn match_process(
        &self,
        proc_snap: &ProcProcessSnapshot,
        maps_text: Option<&str>,
    ) -> Option<&'static str> {
        if let Some(re) = &self.cmdline_re {
            if re.is_match(&proc_snap.cmdline_joined) {
                return Some("cmdline");
            }
        }
        if let (Some(re), Some(exe)) = (&self.exe_re, proc_snap.exe.as_deref()) {
            if re.is_match(exe) {
                return Some("exe");
            }
        }
        if let Some(re) = &self.comm_re {
            if re.is_match(&proc_snap.comm) {
                return Some("comm");
            }
        }
        if let (Some(re), Some(maps)) = (&self.maps_re, maps_text) {
            if re.is_match(maps) {
                return Some("maps");
            }
        }
        None
    }
}

/// Parse `/proc/net/unix` into socket entries retaining listening state & path.
pub fn parse_proc_net_unix_sockets(text: &str) -> Vec<UnixSocketEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            // Format: Num RefCount Protocol Flags Type St Inode [Path...]
            let mut parts = line.split_whitespace();
            let _num = parts.next()?;
            let _refcnt = parts.next()?;
            let _proto = parts.next()?;
            let flags_hex = parts.next()?;
            let _sock_type = parts.next()?;
            let _st = parts.next()?;
            let inode_str = parts.next()?;
            let path = parts.next().unwrap_or("").trim();
            if path.is_empty() {
                return None;
            }
            let inode = inode_str.parse::<u64>().ok()?;
            let flags = u64::from_str_radix(flags_hex, 16).unwrap_or(0);
            // SO_ACCEPTCON is 0x00010000 in Linux AF_UNIX /proc/net/unix Flags.
            let listening = (flags & 0x0001_0000) != 0;
            Some(UnixSocketEntry {
                inode,
                listening,
                path: path.to_owned(),
            })
        })
        .collect()
}

pub fn parse_loopback_port_value(raw: &str) -> Option<u16> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .strip_prefix("http://")
        .or_else(|| raw.trim().strip_prefix("ws://"))
        .unwrap_or_else(|| raw.trim());
    let host_port = trimmed.split('/').next().unwrap_or(trimmed);
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let host_lc = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
        if !matches!(
            host_lc.as_str(),
            "" | "127.0.0.1" | "localhost" | "::1" | "0.0.0.0"
        ) {
            return None;
        }
        let port = port_str.parse::<u16>().ok()?;
        return (port > 0).then_some(port);
    }
    let port = host_port.parse::<u16>().ok()?;
    (port > 0).then_some(port)
}

fn extract_ports_from_args_and_env(
    args: &[String],
    environ_pairs: &[(String, String)],
    rule: &WebviewProbeRule,
) -> Vec<u16> {
    let mut ports = Vec::new();
    for (idx, arg) in args.iter().enumerate() {
        for flag in &rule.port_flags {
            if let Some(rest) = arg.strip_prefix(flag.as_str()) {
                if let Some(p) = parse_loopback_port_value(rest) {
                    ports.push(p);
                }
            } else if flag.ends_with('=') {
                let bare = flag.trim_end_matches('=');
                if arg == bare {
                    if let Some(next_val) = args.get(idx + 1) {
                        if let Some(p) = parse_loopback_port_value(next_val) {
                            ports.push(p);
                        }
                    }
                }
            }
        }
    }
    for (k, v) in environ_pairs {
        if rule.env_keys.iter().any(|ek| ek == k) {
            if let Some(p) = parse_loopback_port_value(v) {
                ports.push(p);
            }
        }
    }
    ports
}

fn read_proc_snapshot(pid: i64) -> Option<(ProcProcessSnapshot, Vec<(String, String)>)> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    if !root.exists() {
        return None;
    }
    let comm = std::fs::read_to_string(root.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let cmd_bytes = std::fs::read(root.join("cmdline")).unwrap_or_default();
    let cmdline_args: Vec<String> = cmd_bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let cmdline_joined = cmdline_args.join(" ");
    let exe = std::fs::read_link(root.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let env_bytes = std::fs::read(root.join("environ")).unwrap_or_default();
    let environ_pairs: Vec<(String, String)> = env_bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| {
            let s = String::from_utf8_lossy(entry);
            let (k, v) = s.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect();

    Some((
        ProcProcessSnapshot {
            pid,
            comm,
            exe,
            cmdline_args,
            cmdline_joined,
        },
        environ_pairs,
    ))
}

fn read_bounded_maps(pid: i64) -> Option<String> {
    let data = std::fs::read(format!("/proc/{pid}/maps")).ok()?;
    let slice = &data[..data.len().min(MAX_MAPS_BYTES)];
    Some(String::from_utf8_lossy(slice).into_owned())
}

fn match_rules_against_snapshot(
    compiled: &[CompiledRule],
    proc_snap: &ProcProcessSnapshot,
    environ_pairs: &[(String, String)],
    maps_text: Option<&str>,
) -> (Vec<MatchedEngine>, Vec<u16>) {
    let mut matched = Vec::new();
    let mut configured_ports = Vec::new();
    for cr in compiled {
        if let Some(src) = cr.match_process(proc_snap, maps_text) {
            matched.push(MatchedEngine {
                rule_id: cr.rule.id.clone(),
                engine: cr.rule.engine.clone(),
                protocol: cr.rule.protocol.clone(),
                matched_pid: proc_snap.pid,
                match_source: src.to_owned(),
                hint: cr.rule.hints.clone(),
            });
            configured_ports.extend(cr.rule.default_ports.iter().copied());
        }
        configured_ports.extend(extract_ports_from_args_and_env(
            &proc_snap.cmdline_args,
            environ_pairs,
            &cr.rule,
        ));
    }
    (matched, configured_ports)
}

async fn http_get_loopback_json(port: u16, path: &str, timeout: Duration) -> Result<Value> {
    let addr = format!("127.0.0.1:{port}");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    let body = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connect {addr}"))?;
        stream.write_all(request.as_bytes()).await?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let take = n.min(MAX_HTTP_RESPONSE_BYTES.saturating_sub(raw.len()));
            raw.extend_from_slice(&buf[..take]);
            if raw.len() >= MAX_HTTP_RESPONSE_BYTES {
                break;
            }
        }
        Ok::<Vec<u8>, anyhow::Error>(raw)
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out reading http://{addr}{path}"))??;

    let text = String::from_utf8_lossy(&body);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response from http://{addr}{path}"))?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200 ") && !status.ends_with(" 200") {
        anyhow::bail!("unexpected HTTP status from http://{addr}{path}: {status}");
    }
    let decoded_body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked_body(rest)
    } else {
        rest.to_owned()
    };
    serde_json::from_str(decoded_body.trim())
        .with_context(|| format!("invalid JSON from http://{addr}{path}"))
}

fn decode_chunked_body(raw: &str) -> String {
    let mut out = String::new();
    let mut cursor = raw;
    while let Some((size_line, rest)) = cursor.split_once("\r\n") {
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(len) = usize::from_str_radix(hex_part, 16) else {
            return raw.to_owned();
        };
        if len == 0 {
            break;
        }
        if rest.len() < len {
            out.push_str(rest);
            break;
        }
        out.push_str(&rest[..len]);
        cursor = rest[len..].strip_prefix("\r\n").unwrap_or(&rest[len..]);
    }
    out
}

async fn probe_single_port(port: u16, timeout: Duration) -> ProbedHttpEndpoint {
    let version = http_get_loopback_json(port, "/json/version", timeout).await;
    let list = http_get_loopback_json(port, "/json/list", timeout).await;

    let mut browser_ws_url = None;
    let mut browser = None;
    let mut protocol_version = None;
    let mut user_agent = None;
    let mut cdp_verified = false;
    let mut errors = Vec::new();

    match version {
        Ok(val) => {
            cdp_verified = true;
            if let Some(ws) = val.get("webSocketDebuggerUrl").and_then(Value::as_str) {
                match cua_driver_core::browser::cdp_ws::validate_loopback_ws_url(ws) {
                    Ok(()) => browser_ws_url = Some(ws.to_owned()),
                    Err(err) => errors.push(format!("rejected non-loopback ws url: {err}")),
                }
            }
            browser = val.get("Browser").and_then(Value::as_str).map(str::to_owned);
            protocol_version = val
                .get("Protocol-Version")
                .and_then(Value::as_str)
                .map(str::to_owned);
            user_agent = val
                .get("User-Agent")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        Err(err) => errors.push(err.to_string()),
    }

    let mut page_targets = Vec::new();
    match list {
        Ok(Value::Array(items)) => {
            cdp_verified = true;
            for item in items.into_iter().take(64) {
                let ws_url = item
                    .get("webSocketDebuggerUrl")
                    .and_then(Value::as_str)
                    .filter(|ws| {
                        cua_driver_core::browser::cdp_ws::validate_loopback_ws_url(ws).is_ok()
                    })
                    .map(str::to_owned);
                page_targets.push(CdpPageTarget {
                    id: item.get("id").and_then(Value::as_str).map(str::to_owned),
                    title: item.get("title").and_then(Value::as_str).map(str::to_owned),
                    target_type: item.get("type").and_then(Value::as_str).map(str::to_owned),
                    url: item.get("url").and_then(Value::as_str).map(str::to_owned),
                    ws_url,
                });
            }
        }
        Ok(_) => {}
        Err(err) => errors.push(err.to_string()),
    }

    let error = if cdp_verified {
        None
    } else {
        Some(errors.join("; "))
    };
    ProbedHttpEndpoint {
        port,
        cdp_verified,
        browser_ws_url,
        browser,
        protocol_version,
        user_agent,
        page_targets,
        error,
    }
}

fn collect_static_proc_info(
    root_pid: u32,
    compiled: &[CompiledRule],
    include_maps: bool,
) -> Result<(
    usize,
    Vec<MatchedEngine>,
    BTreeSet<u16>,
    BTreeSet<u16>,
    Vec<InspectorUnixSocket>,
)> {
    let family = process_family_pids(root_pid as i64)
        .unwrap_or_else(|_| HashSet::from([root_pid as i64]));
    let process_count = family.len();
    let owned_inodes = socket_inodes_for_process_tree(root_pid as i64).unwrap_or_default();

    let mut matched_engines = Vec::new();
    let mut seen_rule_engine = HashSet::new();
    let mut configured_ports = BTreeSet::new();

    for pid in &family {
        let Some((snap, env_pairs)) = read_proc_snapshot(*pid) else {
            continue;
        };
        let maps = if include_maps {
            read_bounded_maps(*pid)
        } else {
            None
        };
        let (matches, cfg_ports) =
            match_rules_against_snapshot(compiled, &snap, &env_pairs, maps.as_deref());
        for m in matches {
            if seen_rule_engine.insert((m.rule_id.clone(), m.matched_pid)) {
                matched_engines.push(m);
            }
        }
        configured_ports.extend(cfg_ports);
    }

    let mut listening_ports = BTreeSet::new();
    if !owned_inodes.is_empty() {
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for (port, inode) in parse_proc_net_loopback_listeners(&text) {
                if owned_inodes.contains(&inode) && port > 0 {
                    listening_ports.insert(port);
                }
            }
        }
    }

    let mut unix_sockets = Vec::new();
    if !owned_inodes.is_empty() {
        if let Ok(unix_text) = std::fs::read_to_string("/proc/net/unix") {
            let mut seen_unix = HashSet::new();
            for entry in parse_proc_net_unix_sockets(&unix_text) {
                if !owned_inodes.contains(&entry.inode) {
                    continue;
                }
                let matched_rules: Vec<String> = compiled
                    .iter()
                    .filter(|cr| {
                        cr.unix_socket_re
                            .as_ref()
                            .is_some_and(|re| re.is_match(&entry.path))
                    })
                    .map(|cr| cr.rule.id.clone())
                    .collect();
                if entry.listening || !matched_rules.is_empty() {
                    if seen_unix.insert((entry.inode, entry.path.clone())) {
                        unix_sockets.push(InspectorUnixSocket {
                            inode: entry.inode,
                            path: entry.path,
                            listening: entry.listening,
                            matched_rules,
                        });
                    }
                }
            }
        }
    }

    Ok((
        process_count,
        matched_engines,
        listening_ports,
        configured_ports,
        unix_sockets,
    ))
}

/// Fast synchronous summary for `inspect_app_flow` (no network I/O).
pub fn detect_webview_summary(pid: u32) -> Option<WebviewSummary> {
    let (rules, _) = load_rules(None).ok()?;
    let compiled: Vec<CompiledRule> = rules
        .into_iter()
        .filter_map(|r| CompiledRule::compile(r).ok())
        .collect();
    let (_, matched, listening_ports, configured_ports, unix_sockets) =
        collect_static_proc_info(pid, &compiled, false).ok()?;
    if matched.is_empty() && listening_ports.is_empty() && unix_sockets.is_empty() {
        return None;
    }
    let mut engines = BTreeSet::new();
    let mut hints = BTreeSet::new();
    for m in matched {
        engines.insert(m.engine);
        if let Some(h) = m.hint {
            hints.insert(h);
        }
    }
    let mut ports = listening_ports;
    ports.extend(configured_ports);
    Some(WebviewSummary {
        engines: engines.into_iter().collect(),
        listening_ports: ports.into_iter().collect(),
        unix_sockets: unix_sockets.into_iter().map(|s| s.path).collect(),
        hints: hints.into_iter().collect(),
    })
}

/// Full asynchronous WebView probe across `/proc/<pid>/fd`, `/proc/net/tcp`,
/// `/proc/net/unix`, `webview_probes.json` rules, and `/json/version` + `/json/list`.
pub async fn probe_webview_targets(
    pid_opt: Option<u32>,
    window_id_opt: Option<u64>,
    probe_http: bool,
    config_override: Option<&Path>,
) -> Result<WebviewProbeReport> {
    let pid = match pid_opt {
        Some(p) => p,
        None => {
            let xid = window_id_opt.ok_or_else(|| {
                anyhow::anyhow!("probe_webview_targets requires pid or window_id")
            })?;
            crate::x11::window_pid(xid).ok_or_else(|| {
                anyhow::anyhow!("window_id {xid} does not advertise a valid _NET_WM_PID")
            })?
        }
    };

    let (rules, active_cfg_path) = load_rules(config_override)?;
    let compiled: Vec<CompiledRule> = rules
        .into_iter()
        .map(CompiledRule::compile)
        .collect::<Result<Vec<_>>>()?;

    let (process_count, matched_engines, listening_ports, configured_ports, unix_sockets) =
        tokio::task::spawn_blocking(move || collect_static_proc_info(pid, &compiled, true))
            .await??;

    let mut endpoints = Vec::new();
    if probe_http {
        let mut candidate_ports = BTreeSet::new();
        candidate_ports.extend(listening_ports.iter().copied());
        candidate_ports.extend(configured_ports.iter().copied());
        let timeout = Duration::from_millis(DEFAULT_HTTP_PROBE_TIMEOUT_MS);
        for port in candidate_ports.into_iter().take(MAX_HTTP_PROBE_PORTS) {
            endpoints.push(probe_single_port(port, timeout).await);
        }
    }

    Ok(WebviewProbeReport {
        pid,
        window_id: window_id_opt,
        config_path: active_cfg_path.map(|p| p.display().to_string()),
        process_count,
        matched_engines,
        listening_ports: listening_ports.into_iter().collect(),
        configured_ports: configured_ports.into_iter().collect(),
        unix_sockets,
        endpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_proc_net_unix_listening_and_abstract_inspector_sockets() {
        let sample = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 112233 /tmp/cef-devtools.sock
0000000000000000: 00000002 00000000 00010000 0001 01 445566 @webkit_inspector_12
0000000000000000: 00000003 00000000 00000000 0001 03 778899 /run/dbus/system_bus_socket
";
        let parsed = parse_proc_net_unix_sockets(sample);
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].listening);
        assert_eq!(parsed[0].inode, 112233);
        assert_eq!(parsed[0].path, "/tmp/cef-devtools.sock");
        assert!(parsed[1].listening);
        assert_eq!(parsed[1].path, "@webkit_inspector_12");
        assert!(!parsed[2].listening);
    }

    #[test]
    fn matches_all_five_webview_stacks_and_extracts_ports() {
        let compiled: Vec<CompiledRule> = builtin_rules()
            .into_iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>>>()
            .expect("compile builtin rules");

        let cases = [
            (
                "electron",
                ProcProcessSnapshot {
                    pid: 100,
                    comm: "electron".into(),
                    exe: Some("/opt/app/electron".into()),
                    cmdline_args: vec!["/opt/app/electron".into(), "--remote-debugging-port=9221".into()],
                    cmdline_joined: "/opt/app/electron --remote-debugging-port=9221".into(),
                },
                vec![],
                None,
                9221,
            ),
            (
                "cef",
                ProcProcessSnapshot {
                    pid: 101,
                    comm: "helper".into(),
                    exe: Some("/opt/app/cef_subprocess".into()),
                    cmdline_args: vec!["--remote-debugging-port=9222".into()],
                    cmdline_joined: "--remote-debugging-port=9222".into(),
                },
                vec![],
                Some("7f00-7f01 r-xp /opt/app/libcef.so"),
                9222,
            ),
            (
                "jxbrowser",
                ProcProcessSnapshot {
                    pid: 102,
                    comm: "java".into(),
                    exe: Some("/opt/tws/jre/bin/java".into()),
                    cmdline_args: vec![
                        "java".into(),
                        "-Djxbrowser.remote.debugging.port=9223".into(),
                    ],
                    cmdline_joined: "java -Djxbrowser.remote.debugging.port=9223".into(),
                },
                vec![],
                None,
                9223,
            ),
            (
                "qtwebengine",
                ProcProcessSnapshot {
                    pid: 103,
                    comm: "QtWebEngineProc".into(),
                    exe: Some("/usr/lib/qt6/libexec/QtWebEngineProcess".into()),
                    cmdline_args: vec![],
                    cmdline_joined: "/usr/lib/qt6/libexec/QtWebEngineProcess".into(),
                },
                vec![(
                    "QTWEBENGINE_REMOTE_DEBUGGING".into(),
                    "127.0.0.1:9224".into(),
                )],
                Some("7f00-7f01 r-xp /usr/lib/libQt6WebEngineCore.so"),
                9224,
            ),
            (
                "webkitgtk",
                ProcProcessSnapshot {
                    pid: 104,
                    comm: "WebKitWebProce".into(),
                    exe: Some("/usr/libexec/webkit2gtk-4.1/WebKitWebProcess".into()),
                    cmdline_args: vec![],
                    cmdline_joined: "/usr/libexec/webkit2gtk-4.1/WebKitWebProcess".into(),
                },
                vec![("WEBKIT_INSPECTOR_SERVER".into(), "127.0.0.1:2999".into())],
                Some("7f00-7f01 r-xp /usr/lib/libwebkit2gtk-4.1.so"),
                2999,
            ),
        ];

        for (expected_engine, snap, env, maps, expected_port) in cases {
            let (matched, ports) = match_rules_against_snapshot(&compiled, &snap, &env, maps);
            assert!(
                matched.iter().any(|m| m.engine == expected_engine),
                "expected engine {expected_engine}, got {matched:?}"
            );
            assert!(
                ports.contains(&expected_port),
                "expected port {expected_port} for {expected_engine}, got {ports:?}"
            );
        }
    }

    #[test]
    fn rejects_non_loopback_env_port_values() {
        assert_eq!(parse_loopback_port_value("127.0.0.1:9222"), Some(9222));
        assert_eq!(parse_loopback_port_value("localhost:9229"), Some(9229));
        assert_eq!(parse_loopback_port_value("9333"), Some(9333));
        assert_eq!(parse_loopback_port_value("192.168.1.10:9222"), None);
        assert_eq!(parse_loopback_port_value("0"), None);
    }

    #[test]
    fn hot_reloads_webview_probes_json_on_edit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg_path = dir.path().join("webview_probes.json");
        std::fs::write(
            &cfg_path,
            serde_json::json!({
                "replace_defaults": false,
                "rules": [{
                    "id": "custom-webview",
                    "engine": "custom_wv",
                    "protocol": "cdp",
                    "cmdline_regex": "custom-wv",
                    "default_ports": [9444]
                }]
            })
            .to_string(),
        )
        .expect("write v1");
        let (rules_v1, _) = load_rules(Some(&cfg_path)).expect("load v1");
        assert!(rules_v1.iter().any(|r| r.id == "custom-webview"));
        assert!(rules_v1.iter().any(|r| r.id == "electron"));

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            &cfg_path,
            serde_json::json!({
                "replace_defaults": true,
                "rules": [{
                    "id": "custom-only-v2",
                    "engine": "custom_v2",
                    "protocol": "cdp",
                    "cmdline_regex": "custom-v2",
                    "default_ports": [9555]
                }]
            })
            .to_string(),
        )
        .expect("write v2");
        let (rules_v2, _) = load_rules(Some(&cfg_path)).expect("load v2");
        assert_eq!(rules_v2.len(), 1);
        assert_eq!(rules_v2[0].id, "custom-only-v2");
    }

    #[tokio::test]
    async fn probes_loopback_json_version_and_json_list_and_rejects_remote_ws() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut req_buf = [0u8; 1024];
                let n = sock.read(&mut req_buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&req_buf[..n]);
                let body = if req.contains("GET /json/version") {
                    serde_json::json!({
                        "Browser": "JxBrowser/130.0",
                        "Protocol-Version": "1.3",
                        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/abc")
                    })
                    .to_string()
                } else {
                    serde_json::json!([
                        {
                            "id": "page-1",
                            "title": "Trade Grid",
                            "type": "page",
                            "url": "https://trade.example",
                            "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/page-1")
                        },
                        {
                            "id": "remote-evil",
                            "title": "Remote",
                            "type": "page",
                            "url": "https://evil.example",
                            "webSocketDebuggerUrl": "ws://evil.example:9222/devtools/page/remote"
                        }
                    ])
                    .to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let probed = probe_single_port(port, Duration::from_secs(2)).await;
        server.await.expect("server");
        assert!(probed.cdp_verified);
        assert_eq!(probed.browser.as_deref(), Some("JxBrowser/130.0"));
        assert_eq!(
            probed.browser_ws_url.as_deref(),
            Some(format!("ws://127.0.0.1:{port}/devtools/browser/abc").as_str())
        );
        assert_eq!(probed.page_targets.len(), 2);
        assert!(probed.page_targets[0].ws_url.is_some());
        assert!(probed.page_targets[1].ws_url.is_none());
    }
}
