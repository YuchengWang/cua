// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Bounded asynchronous OS event bus & ring queue for AT-SPI2 + X11 events.
//!
//! Subscribes to:
//! - AT-SPI `Window:{Create,Activate,Destroy}`
//! - AT-SPI `Document:{LoadComplete,Reload}`
//! - AT-SPI `Object:ChildrenChanged` & `Object:StateChanged(showing)`
//! - X11 `override_redirect` popup `MapNotify` / `UnmapNotify` (and `DestroyNotify`)

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Notify;
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ChangeWindowAttributesAux, EventMask, MapState};
use x11rb::protocol::Event as X11Event;
use x11rb::rust_connection::RustConnection;

pub const DEFAULT_EVENT_RING_CAPACITY: usize = 2048;
pub const AUTH_GATE_EVENT_KIND: &str = "auth_gate_detected";
pub const AUTH_GATE_SUGGESTED_ACTION: &str =
    "Call resolve_auth_site + focus OTP field + type_totp_from_env or run_app_recipe";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthGateMatch {
    pub title: String,
    pub url_hint: Option<String>,
    pub suggested_action: &'static str,
}

fn contains_ascii_word(haystack_lower: &str, word: &str) -> bool {
    let bytes = haystack_lower.as_bytes();
    let wlen = word.len();
    haystack_lower.match_indices(word).any(|(idx, _)| {
        let before_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let after = idx + wlen;
        let after_ok = after == bytes.len() || !bytes[after].is_ascii_alphanumeric();
        before_ok && after_ok
    })
}

fn extract_domain_token(title: &str) -> Option<String> {
    for raw in title.split(|c: char| c.is_whitespace() || matches!(c, '|' | '·' | '/' | '(' | ')' | '[' | ']' | ',' | ';')) {
        let token = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        if token.len() < 4 || !token.contains('.') || token.starts_with('.') || token.ends_with('.') {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() < 2 || parts.iter().any(|p| p.is_empty() || p.starts_with('-') || p.ends_with('-')) {
            continue;
        }
        let tld = parts.last().copied().unwrap_or("");
        if tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
            return Some(format!("https://{lower}"));
        }
    }
    None
}

fn extract_url_hint_from_title(title: &str) -> Option<String> {
    let lower = title.to_ascii_lowercase();
    let known = [
        ("github", "https://github.com"),
        ("google accounts", "https://accounts.google.com"),
        ("accounts.google.com", "https://accounts.google.com"),
        ("interactive brokers", "https://www.interactivebrokers.com"),
        ("ibkr", "https://www.interactivebrokers.com"),
        ("microsoft", "https://login.microsoftonline.com"),
        ("office 365", "https://login.microsoftonline.com"),
        ("amazon web services", "https://signin.aws.amazon.com"),
        ("aws", "https://signin.aws.amazon.com"),
        ("openai", "https://auth.openai.com"),
        ("chatgpt", "https://auth.openai.com"),
        ("cloudflare", "https://dash.cloudflare.com"),
        ("stripe", "https://dashboard.stripe.com"),
        ("gitlab", "https://gitlab.com"),
        ("bitbucket", "https://bitbucket.org"),
        ("okta", "https://okta.com"),
        ("wise", "https://wise.com"),
    ];
    for (needle, url) in known {
        if lower.contains(needle) {
            return Some(url.to_owned());
        }
    }
    extract_domain_token(title)
}

/// Detect whether a browser/app window title represents a 2FA or authentication gate.
pub fn detect_auth_gate_from_title(title: &str) -> Option<AuthGateMatch> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let phrase_matched = [
        "two-factor authentication",
        "two factor authentication",
        "two-factor",
        "two-step verification",
        "two step verification",
        "2-step verification",
        "verify your identity",
        "verify it's you",
        "verify it\u{2019}s you",
        "identity verification",
        "second factor",
        "authenticator app",
        "verification code",
        "security code",
        "one-time password",
        "one-time code",
        "authentication required",
        "sign in to ",
        "sign in - ",
        "sign in \u{2013} ",
        "log in to ",
    ]
    .iter()
    .any(|pat| lower.contains(pat));

    let word_matched =
        contains_ascii_word(&lower, "2fa") || contains_ascii_word(&lower, "otp");

    if !phrase_matched && !word_matched {
        return None;
    }

    Some(AuthGateMatch {
        title: trimmed.to_owned(),
        url_hint: extract_url_hint_from_title(trimmed),
        suggested_action: AUTH_GATE_SUGGESTED_ACTION,
    })
}

fn should_check_auth_gate(ev: &OsEvent) -> bool {
    if ev.kind == AUTH_GATE_EVENT_KIND {
        return false;
    }
    if matches!(
        ev.kind.as_str(),
        "window.destroy" | "x11.popup_unmap" | "object.children_changed.remove"
    ) {
        return false;
    }
    if ev.kind == "object.state_changed.showing" && ev.showing == Some(false) {
        return false;
    }
    true
}

fn build_auth_gate_draft(trigger: &OsEvent, gate: AuthGateMatch) -> OsEventDraft {
    let mut detail = json!({
        "window_id": trigger.window_id,
        "pid": trigger.pid,
        "title": gate.title,
        "suggested_action": gate.suggested_action,
        "trigger_kind": trigger.kind,
        "trigger_seq": trigger.seq,
    });
    if let Some(ref url_hint) = gate.url_hint {
        detail["url_hint"] = json!(url_hint);
    }
    OsEventDraft {
        source: trigger.source.clone(),
        kind: AUTH_GATE_EVENT_KIND.into(),
        pid: trigger.pid,
        window_id: trigger.window_id,
        role: trigger.role.clone(),
        name: Some(gate.title),
        bus_name: trigger.bus_name.clone(),
        object_path: trigger.object_path.clone(),
        showing: trigger.showing,
        override_redirect: trigger.override_redirect,
        detail: Some(detail),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsEvent {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub source: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub showing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_redirect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct OsEventDraft {
    pub source: String,
    pub kind: String,
    pub pid: Option<u32>,
    pub window_id: Option<u64>,
    pub role: Option<String>,
    pub name: Option<String>,
    pub bus_name: Option<String>,
    pub object_path: Option<String>,
    pub showing: Option<bool>,
    pub override_redirect: Option<bool>,
    pub detail: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct OsEventFilter {
    pub pid: Option<u32>,
    pub event_kinds: Vec<String>,
    pub role: Option<String>,
    pub name_regex: Option<Regex>,
}

impl OsEventFilter {
    pub fn from_params(
        pid: Option<u32>,
        event_kinds: Vec<String>,
        role: Option<String>,
        name_regex: Option<&str>,
    ) -> anyhow::Result<Self> {
        let compiled = name_regex
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Regex::new)
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid name_regex: {e}"))?;
        let normalized_kinds = event_kinds
            .into_iter()
            .map(|k| k.trim().to_ascii_lowercase())
            .filter(|k| !k.is_empty())
            .collect();
        let normalized_role = role
            .map(|r| r.trim().to_ascii_lowercase())
            .filter(|r| !r.is_empty());
        Ok(Self {
            pid,
            event_kinds: normalized_kinds,
            role: normalized_role,
            name_regex: compiled,
        })
    }

    pub fn matches(&self, ev: &OsEvent) -> bool {
        if let Some(pid) = self.pid {
            if ev.pid != Some(pid) {
                return false;
            }
        }
        if !self.event_kinds.is_empty() {
            let ev_kind = ev.kind.to_ascii_lowercase();
            let matched = self.event_kinds.iter().any(|pat| {
                if let Some(prefix) = pat.strip_suffix('*') {
                    ev_kind.starts_with(prefix)
                } else {
                    ev_kind == *pat
                        || ev_kind
                            .strip_prefix(pat.as_str())
                            .is_some_and(|rest| rest.starts_with('.'))
                }
            });
            if !matched {
                return false;
            }
        }
        if let Some(ref want_role) = self.role {
            let Some(ref ev_role) = ev.role else {
                return false;
            };
            if ev_role.trim().to_ascii_lowercase() != *want_role {
                return false;
            }
        }
        if let Some(ref re) = self.name_regex {
            let candidate = ev.name.as_deref().unwrap_or("");
            if !re.is_match(candidate) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PollOsEventsResult {
    pub events: Vec<OsEvent>,
    pub count: usize,
    pub next_cursor: u64,
    pub latest_seq: u64,
    pub oldest_seq: u64,
    pub ring_capacity: usize,
    pub gaps_detected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitForOsEventResult {
    pub matched: bool,
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<OsEvent>,
    pub next_cursor: u64,
    pub elapsed_ms: u64,
}

pub struct OsEventBus {
    capacity: usize,
    next_seq: AtomicU64,
    ring: Mutex<VecDeque<OsEvent>>,
    notify: Notify,
    bus_pid_cache: Mutex<HashMap<String, Option<u32>>>,
}

impl OsEventBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_seq: AtomicU64::new(0),
            ring: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            notify: Notify::new(),
            bus_pid_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn latest_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Acquire)
    }

    pub fn record_bus_pid(&self, bus_name: &str, pid: Option<u32>) {
        if bus_name.is_empty() {
            return;
        }
        let mut cache = self.bus_pid_cache.lock().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(bus_name.to_owned(), pid);
    }

    pub fn cached_bus_pid(&self, bus_name: &str) -> Option<Option<u32>> {
        self.bus_pid_cache.lock().unwrap().get(bus_name).copied()
    }

    pub fn push(&self, draft: OsEventDraft) -> u64 {
        let mut pid = draft.pid;
        if pid.is_none() {
            if let Some(ref bus) = draft.bus_name {
                if let Some(Some(cached)) = self.cached_bus_pid(bus) {
                    pid = Some(cached);
                }
            }
        }
        let seq = self.next_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let event = OsEvent {
            seq,
            timestamp_ms,
            source: draft.source,
            kind: draft.kind,
            pid,
            window_id: draft.window_id,
            role: draft.role,
            name: draft.name,
            bus_name: draft.bus_name,
            object_path: draft.object_path,
            showing: draft.showing,
            override_redirect: draft.override_redirect,
            detail: draft.detail,
        };
        let auth_gate_draft = if should_check_auth_gate(&event) {
            event
                .name
                .as_deref()
                .and_then(detect_auth_gate_from_title)
                .map(|gate| build_auth_gate_draft(&event, gate))
        } else {
            None
        };
        {
            let mut ring = self.ring.lock().unwrap();
            while ring.len() >= self.capacity {
                ring.pop_front();
            }
            ring.push_back(event);
        }
        self.notify.notify_waiters();
        if let Some(auth_draft) = auth_gate_draft {
            self.push(auth_draft);
        }
        seq
    }

    /// Update metadata on a retained event after non-blocking background
    /// enrichment resolves `pid` / `role` / `name` from D-Bus.
    pub fn patch_event_metadata(
        &self,
        seq: u64,
        pid: Option<u32>,
        role: Option<String>,
        name: Option<String>,
    ) {
        let mut changed = false;
        let mut auth_gate_draft = None;
        {
            let mut ring = self.ring.lock().unwrap();
            if let Some(ev) = ring.iter_mut().rev().find(|e| e.seq == seq) {
                if ev.pid.is_none() && pid.is_some() {
                    ev.pid = pid;
                    changed = true;
                }
                if ev.role.is_none() && role.is_some() {
                    ev.role = role;
                    changed = true;
                }
                if ev.name.is_none() && name.is_some() {
                    ev.name = name;
                    changed = true;
                    if should_check_auth_gate(ev) {
                        if let Some(gate) = ev.name.as_deref().and_then(detect_auth_gate_from_title) {
                            auth_gate_draft = Some(build_auth_gate_draft(ev, gate));
                        }
                    }
                }
            }
        }
        if changed {
            self.notify.notify_waiters();
        }
        if let Some(auth_draft) = auth_gate_draft {
            self.push(auth_draft);
        }
    }

    pub fn poll(
        &self,
        cursor: Option<u64>,
        filter: &OsEventFilter,
        limit: usize,
    ) -> PollOsEventsResult {
        let after_seq = cursor.unwrap_or(0);
        let max_items = limit.clamp(1, 500);
        let bus_cache = self.bus_pid_cache.lock().unwrap().clone();
        let ring = self.ring.lock().unwrap();
        let oldest_seq = ring.front().map(|e| e.seq).unwrap_or(0);
        let latest_seq = ring.back().map(|e| e.seq).unwrap_or_else(|| self.latest_seq());
        let gaps_detected = after_seq > 0 && oldest_seq > 0 && after_seq + 1 < oldest_seq;

        let mut events = Vec::new();
        let mut last_scanned_seq = after_seq;
        for ev in ring.iter() {
            if ev.seq <= after_seq {
                continue;
            }
            last_scanned_seq = ev.seq;
            let mut resolved = ev.clone();
            if resolved.pid.is_none() {
                if let Some(ref bus) = resolved.bus_name {
                    if let Some(Some(pid)) = bus_cache.get(bus) {
                        resolved.pid = Some(*pid);
                    }
                }
            }
            if filter.matches(&resolved) {
                events.push(resolved);
                if events.len() >= max_items {
                    break;
                }
            }
        }
        let next_cursor = if events.len() >= max_items {
            last_scanned_seq
        } else {
            latest_seq.max(after_seq)
        };
        let count = events.len();
        PollOsEventsResult {
            events,
            count,
            next_cursor,
            latest_seq,
            oldest_seq,
            ring_capacity: self.capacity,
            gaps_detected,
        }
    }

    pub async fn wait_for(
        &self,
        cursor: Option<u64>,
        filter: &OsEventFilter,
        timeout: Duration,
    ) -> WaitForOsEventResult {
        let started = Instant::now();
        let start_cursor = cursor.unwrap_or_else(|| self.latest_seq());
        let mut scan_cursor = start_cursor;
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Register notification BEFORE inspecting the ring so an event
            // arriving right during our scan cannot be missed.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let poll = self.poll(Some(scan_cursor), filter, 1);
            if let Some(ev) = poll.events.into_iter().next() {
                let next_cursor = ev.seq;
                return WaitForOsEventResult {
                    matched: true,
                    timed_out: false,
                    event: Some(ev),
                    next_cursor,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                };
            }
            // Note: DO NOT advance `scan_cursor` past unenriched events if we
            // are filtering on pid/role/name_regex, because background
            // enrichment can patch an already-pushed event's metadata!
            if filter.pid.is_none() && filter.role.is_none() && filter.name_regex.is_none() {
                scan_cursor = poll.next_cursor;
            }

            if tokio::time::Instant::now() >= deadline {
                return WaitForOsEventResult {
                    matched: false,
                    timed_out: true,
                    event: None,
                    next_cursor: self.latest_seq().max(start_cursor),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                };
            }

            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                // Re-check once after timeout in case metadata landed right on
                // the boundary.
                let final_poll = self.poll(Some(scan_cursor), filter, 1);
                if let Some(ev) = final_poll.events.into_iter().next() {
                    let next_cursor = ev.seq;
                    return WaitForOsEventResult {
                        matched: true,
                        timed_out: false,
                        event: Some(ev),
                        next_cursor,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    };
                }
                return WaitForOsEventResult {
                    matched: false,
                    timed_out: true,
                    event: None,
                    next_cursor: self.latest_seq().max(start_cursor),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                };
            }
        }
    }
}

pub fn global_os_event_bus() -> &'static OsEventBus {
    static BUS: OnceLock<OsEventBus> = OnceLock::new();
    BUS.get_or_init(|| OsEventBus::new(DEFAULT_EVENT_RING_CAPACITY))
}

#[derive(Clone, Debug)]
pub(crate) struct X11PopupMeta {
    pid: Option<u32>,
    name: Option<String>,
    detail: Value,
}

fn read_x11_popup_meta(conn: &RustConnection, window: u32) -> Option<X11PopupMeta> {
    let attrs = conn.get_window_attributes(window).ok()?.reply().ok()?;
    if !attrs.override_redirect {
        return None;
    }
    let pid = crate::x11::get_window_pid(conn, window).ok().flatten();
    let title = crate::x11::get_window_title(conn, window)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let wm_class = crate::x11::get_window_class(conn, window);
    let geom = conn.get_geometry(window).ok().and_then(|c| c.reply().ok());
    let name = title.clone().or_else(|| {
        wm_class
            .as_ref()
            .map(|(inst, cls)| if !cls.is_empty() { cls.clone() } else { inst.clone() })
            .filter(|s| !s.is_empty())
    });
    let detail = json!({
        "wm_class": wm_class.map(|(inst, cls)| json!({"instance": inst, "class": cls})),
        "title": title,
        "x": geom.as_ref().map(|g| g.x),
        "y": geom.as_ref().map(|g| g.y),
        "width": geom.as_ref().map(|g| g.width),
        "height": geom.as_ref().map(|g| g.height),
    });
    Some(X11PopupMeta { pid, name, detail })
}

fn seed_mapped_popups(conn: &RustConnection, root: u32) -> HashMap<u32, X11PopupMeta> {
    let mut out = HashMap::new();
    let Ok(Ok(tree)) = conn.query_tree(root).map(|c| c.reply()) else {
        return out;
    };
    for win in tree.children {
        if crate::overlay::is_x11_overlay_window(win) {
            continue;
        }
        let Ok(Ok(attrs)) = conn.get_window_attributes(win).map(|c| c.reply()) else {
            continue;
        };
        if attrs.override_redirect && attrs.map_state == MapState::VIEWABLE {
            if let Some(meta) = read_x11_popup_meta(conn, win) {
                out.insert(win, meta);
            }
        }
    }
    out
}

pub(crate) fn process_x11_event(
    bus: &OsEventBus,
    known_popups: &mut HashMap<u32, X11PopupMeta>,
    conn: Option<&RustConnection>,
    event: X11Event,
) {
    match event {
        X11Event::MapNotify(ev) => {
            if crate::overlay::is_x11_overlay_window(ev.window) {
                return;
            }
            let meta = conn.and_then(|c| read_x11_popup_meta(c, ev.window));
            let Some(meta) = meta else {
                return;
            };
            known_popups.insert(ev.window, meta.clone());
            bus.push(OsEventDraft {
                source: "x11".into(),
                kind: "x11.popup_map".into(),
                pid: meta.pid,
                window_id: Some(u64::from(ev.window)),
                role: Some("popup".into()),
                name: meta.name,
                override_redirect: Some(true),
                detail: Some(meta.detail),
                ..Default::default()
            });
        }
        X11Event::UnmapNotify(ev) => {
            if let Some(meta) = known_popups.remove(&ev.window) {
                bus.push(OsEventDraft {
                    source: "x11".into(),
                    kind: "x11.popup_unmap".into(),
                    pid: meta.pid,
                    window_id: Some(u64::from(ev.window)),
                    role: Some("popup".into()),
                    name: meta.name,
                    override_redirect: Some(true),
                    detail: Some(meta.detail),
                    ..Default::default()
                });
            }
        }
        X11Event::DestroyNotify(ev) => {
            if let Some(meta) = known_popups.remove(&ev.window) {
                bus.push(OsEventDraft {
                    source: "x11".into(),
                    kind: "x11.popup_unmap".into(),
                    pid: meta.pid,
                    window_id: Some(u64::from(ev.window)),
                    role: Some("popup".into()),
                    name: meta.name,
                    override_redirect: Some(true),
                    detail: Some(meta.detail),
                    ..Default::default()
                });
            }
        }
        _ => {}
    }
}

static X11_WATCHER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Start the background X11 `override_redirect` `MapNotify`/`UnmapNotify`
/// watcher once when `DISPLAY` is configured.
pub fn ensure_x11_popup_watcher() {
    static START: Once = Once::new();
    if std::env::var_os("DISPLAY")
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return;
    }
    START.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("cua-x11-popup-events".into())
            .spawn(|| {
                let Ok((conn, screen_num)) = RustConnection::connect(None) else {
                    return;
                };
                let Some(root) = conn.setup().roots.get(screen_num).map(|s| s.root) else {
                    return;
                };
                let attr_ok = match conn.change_window_attributes(
                    root,
                    &ChangeWindowAttributesAux::new().event_mask(EventMask::SUBSTRUCTURE_NOTIFY),
                ) {
                    Ok(cookie) => cookie.check().is_ok(),
                    Err(_) => false,
                };
                if !attr_ok {
                    return;
                }
                X11_WATCHER_RUNNING.store(true, Ordering::Release);
                let mut known_popups = seed_mapped_popups(&conn, root);
                let bus = global_os_event_bus();
                while let Ok(event) = conn.wait_for_event() {
                    process_x11_event(bus, &mut known_popups, Some(&conn), event);
                }
                X11_WATCHER_RUNNING.store(false, Ordering::Release);
            });
    });
}

pub fn x11_popup_watcher_running() -> bool {
    X11_WATCHER_RUNNING.load(Ordering::Acquire)
}

/// Ensure both AT-SPI2 event subscriptions and the X11 popup watcher are active.
pub fn ensure_watchers_active() {
    ensure_x11_popup_watcher();
    if std::env::var_os("NO_AT_BRIDGE").as_deref() != Some(std::ffi::OsStr::new("1")) {
        let _ = crate::atspi::ensure_listener_active();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_queue_bounds_capacity_and_detects_cursor_gaps() {
        let bus = OsEventBus::new(3);
        for i in 1..=5 {
            let seq = bus.push(OsEventDraft {
                source: "atspi".into(),
                kind: "window.create".into(),
                pid: Some(100 + i),
                name: Some(format!("Win {i}")),
                ..Default::default()
            });
            assert_eq!(seq, u64::from(i));
        }

        let filter = OsEventFilter::default();
        let all = bus.poll(None, &filter, 50);
        assert_eq!(all.count, 3);
        assert_eq!(all.oldest_seq, 3);
        assert_eq!(all.latest_seq, 5);
        assert_eq!(all.next_cursor, 5);
        assert!(!all.gaps_detected);

        let gapped = bus.poll(Some(1), &filter, 50);
        assert!(gapped.gaps_detected);
        assert_eq!(gapped.count, 3);

        let tail = bus.poll(Some(4), &filter, 50);
        assert!(!tail.gaps_detected);
        assert_eq!(tail.count, 1);
        assert_eq!(tail.events[0].seq, 5);
    }

    #[test]
    fn filter_matches_pid_kinds_role_and_name_regex() {
        let bus = OsEventBus::new(16);
        bus.push(OsEventDraft {
            source: "atspi".into(),
            kind: "window.create".into(),
            pid: Some(42),
            role: Some("alert".into()),
            name: Some("Allow remote debugging?".into()),
            ..Default::default()
        });
        bus.push(OsEventDraft {
            source: "atspi".into(),
            kind: "document.load_complete".into(),
            pid: Some(42),
            role: Some("document web".into()),
            name: Some("Example Page".into()),
            ..Default::default()
        });
        bus.push(OsEventDraft {
            source: "x11".into(),
            kind: "x11.popup_map".into(),
            pid: Some(99),
            role: Some("popup".into()),
            name: Some("Autofill".into()),
            override_redirect: Some(true),
            ..Default::default()
        });

        let filter = OsEventFilter::from_params(
            Some(42),
            vec!["window".into()],
            Some("alert".into()),
            Some("remote debugging"),
        )
        .unwrap();
        let res = bus.poll(None, &filter, 10);
        assert_eq!(res.count, 1);
        assert_eq!(res.events[0].kind, "window.create");

        let popup_filter =
            OsEventFilter::from_params(None, vec!["x11.popup_map".into()], None, Some("Autofill"))
                .unwrap();
        let popup_res = bus.poll(None, &popup_filter, 10);
        assert_eq!(popup_res.count, 1);
        assert_eq!(popup_res.events[0].pid, Some(99));
    }

    #[tokio::test]
    async fn wait_for_wakes_on_push_and_on_metadata_patch() {
        let bus = std::sync::Arc::new(OsEventBus::new(16));
        let bus_writer = bus.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let seq = bus_writer.push(OsEventDraft {
                source: "atspi".into(),
                kind: "object.state_changed.showing".into(),
                bus_name: Some(":1.77".into()),
                showing: Some(true),
                ..Default::default()
            });
            tokio::time::sleep(Duration::from_millis(25)).await;
            bus_writer.patch_event_metadata(
                seq,
                Some(555),
                Some("alert".into()),
                Some("Remote Consent".into()),
            );
        });

        let filter = OsEventFilter::from_params(
            Some(555),
            vec!["object.state_changed.showing".into()],
            Some("alert".into()),
            Some("Consent"),
        )
        .unwrap();
        let waited = bus.wait_for(Some(0), &filter, Duration::from_secs(2)).await;
        assert!(waited.matched);
        assert!(!waited.timed_out);
        let ev = waited.event.unwrap();
        assert_eq!(ev.pid, Some(555));
        assert_eq!(ev.role.as_deref(), Some("alert"));
        assert_eq!(ev.name.as_deref(), Some("Remote Consent"));
    }

    #[tokio::test]
    async fn wait_for_times_out_cleanly_when_no_match_arrives() {
        let bus = OsEventBus::new(8);
        let filter = OsEventFilter::from_params(Some(123), vec![], None, None).unwrap();
        let waited = bus
            .wait_for(None, &filter, Duration::from_millis(60))
            .await;
        assert!(!waited.matched);
        assert!(waited.timed_out);
        assert!(waited.event.is_none());
    }

    #[test]
    fn x11_unmap_event_emits_popup_unmap_from_cached_override_redirect_meta() {
        let bus = OsEventBus::new(8);
        let mut known = HashMap::new();
        known.insert(
            0x220004,
            X11PopupMeta {
                pid: Some(8080),
                name: Some("Chrome".into()),
                detail: json!({"width": 300, "height": 180}),
            },
        );
        process_x11_event(
            &bus,
            &mut known,
            None,
            X11Event::UnmapNotify(x11rb::protocol::xproto::UnmapNotifyEvent {
                response_type: x11rb::protocol::xproto::UNMAP_NOTIFY_EVENT,
                sequence: 1,
                event: 1,
                window: 0x220004,
                from_configure: false,
            }),
        );
        let polled = bus.poll(None, &OsEventFilter::default(), 10);
        assert_eq!(polled.count, 1);
        assert_eq!(polled.events[0].kind, "x11.popup_unmap");
        assert_eq!(polled.events[0].pid, Some(8080));
        assert_eq!(polled.events[0].window_id, Some(0x220004));
        assert_eq!(polled.events[0].override_redirect, Some(true));
        assert!(known.is_empty());
    }

    #[test]
    fn detect_auth_gate_from_title_matches_gates_and_extracts_url_hint() {
        let gh = detect_auth_gate_from_title("Two-factor authentication · GitHub - Google Chrome")
            .expect("should match GitHub 2FA");
        assert_eq!(gh.url_hint.as_deref(), Some("https://github.com"));
        assert_eq!(gh.suggested_action, AUTH_GATE_SUGGESTED_ACTION);

        let google = detect_auth_gate_from_title("2-Step Verification - Google Accounts")
            .expect("should match Google 2-Step Verification");
        assert_eq!(
            google.url_hint.as_deref(),
            Some("https://accounts.google.com")
        );

        let verify = detect_auth_gate_from_title("Verify your identity - portal.example.com")
            .expect("should match Verify your identity with domain hint");
        assert_eq!(
            verify.url_hint.as_deref(),
            Some("https://portal.example.com")
        );

        let signin = detect_auth_gate_from_title("Sign in to GitHub")
            .expect("should match Sign in to GitHub");
        assert_eq!(signin.url_hint.as_deref(), Some("https://github.com"));

        assert!(detect_auth_gate_from_title("GitHub - Pull Requests - Google Chrome").is_none());
        assert!(detect_auth_gate_from_title("   ").is_none());
    }

    #[test]
    fn os_event_bus_emits_auth_gate_detected_on_push_and_metadata_patch() {
        let bus = OsEventBus::new(16);

        // 1. Direct push with matching title emits auth_gate_detected
        bus.push(OsEventDraft {
            source: "atspi".into(),
            kind: "window.activate".into(),
            pid: Some(4242),
            window_id: Some(0x1001),
            role: Some("frame".into()),
            name: Some("Sign in to GitHub - Google Chrome".into()),
            ..Default::default()
        });

        // 2. Push without title, then patch_event_metadata with matching title
        let seq2 = bus.push(OsEventDraft {
            source: "atspi".into(),
            kind: "window.create".into(),
            window_id: Some(0x1002),
            bus_name: Some(":1.88".into()),
            ..Default::default()
        });
        bus.patch_event_metadata(
            seq2,
            Some(5353),
            Some("frame".into()),
            Some("Two-Step Verification - Google Accounts".into()),
        );

        let filter = OsEventFilter::from_params(None, vec!["auth_gate_detected".into()], None, None)
            .unwrap();
        let res = bus.poll(None, &filter, 10);
        assert_eq!(res.count, 2);

        let first = &res.events[0];
        assert_eq!(first.kind, "auth_gate_detected");
        assert_eq!(first.pid, Some(4242));
        assert_eq!(first.window_id, Some(0x1001));
        let d1 = first.detail.as_ref().unwrap();
        assert_eq!(d1["url_hint"], "https://github.com");
        assert_eq!(d1["suggested_action"], AUTH_GATE_SUGGESTED_ACTION);
        assert_eq!(d1["trigger_kind"], "window.activate");

        let second = &res.events[1];
        assert_eq!(second.kind, "auth_gate_detected");
        assert_eq!(second.pid, Some(5353));
        assert_eq!(second.window_id, Some(0x1002));
        let d2 = second.detail.as_ref().unwrap();
        assert_eq!(d2["url_hint"], "https://accounts.google.com");
        assert_eq!(d2["trigger_kind"], "window.create");
    }
}
