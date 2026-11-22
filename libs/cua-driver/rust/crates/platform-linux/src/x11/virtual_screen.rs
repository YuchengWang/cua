// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Virtual X11 display lifecycle manager (`VirtualScreenManager`).
//!
//! Manages isolated Xvfb + Openbox + D-Bus + autocutsel (+ optional view-only
//! localhost x11vnc) virtual screens in `:99..:199` with per-screen `0600`
//! `XAUTHORITY` cookies, `reap_stale_runtime()` crash recovery, and
//! `SessionEndHook` cleanup.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};

/// Dynamic display number range scanned for free virtual X11 slots.
pub const VIRTUAL_DISPLAY_MIN: u16 = 99;
pub const VIRTUAL_DISPLAY_MAX: u16 = 199;
pub const DEFAULT_WIDTH: u16 = 1920;
pub const DEFAULT_HEIGHT: u16 = 1080;

/// Request to create an isolated virtual X11 screen.
#[derive(Debug, Clone, Default)]
pub struct CreateVirtualScreenRequest {
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub preferred_display: Option<u16>,
    pub enable_vnc: bool,
    pub vnc_interactive: bool,
    pub session_id: Option<String>,
}

/// Public metadata for an active virtual X11 screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualScreenInfo {
    pub display_id: String,
    pub display_num: u16,
    pub width: u16,
    pub height: u16,
    pub xauth_path: PathBuf,
    pub dbus_address: Option<String>,
    pub vnc_port: Option<u16>,
    pub session_id: Option<String>,
    pub pid_xvfb: u32,
    pub pid_openbox: Option<u32>,
    pub pid_dbus: Option<u32>,
    pub pid_autocutsel: Option<u32>,
    pub pid_x11vnc: Option<u32>,
}

/// Result of launching an application inside a virtual X11 screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchedAppInfo {
    pub display_id: String,
    pub pid: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRuntime {
    display_id: String,
    display_num: u16,
    width: u16,
    height: u16,
    xauth_path: PathBuf,
    vnc_passwd_path: Option<PathBuf>,
    dbus_address: Option<String>,
    vnc_port: Option<u16>,
    session_id: Option<String>,
    pid_xvfb: u32,
    pid_openbox: Option<u32>,
    pid_dbus: Option<u32>,
    pid_atspi: Option<u32>,
    pid_autocutsel: Option<u32>,
    pid_x11vnc: Option<u32>,
    created_at_epoch: u64,
}

struct ManagedScreen {
    info: VirtualScreenInfo,
    runtime_dir: PathBuf,
    vnc_passwd_path: Option<PathBuf>,
    children: Vec<Child>,
    launched_children: Vec<Child>,
}

impl Drop for ManagedScreen {
    fn drop(&mut self) {
        terminate_children(&mut self.launched_children);
        terminate_children(&mut self.children);
        let _ = fs::remove_dir_all(&self.runtime_dir);
        global_screen_pool().invalidate(&self.info.display_id);
    }
}

/// Thread-safe manager for isolated virtual X11 screens.
#[derive(Default)]
pub struct VirtualScreenManager {
    screens: Mutex<HashMap<String, ManagedScreen>>,
    reserved_displays: Mutex<HashSet<u16>>,
}

struct DisplayReservationGuard<'a> {
    reserved: &'a Mutex<HashSet<u16>>,
    display_num: u16,
}

impl Drop for DisplayReservationGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.reserved.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.display_num);
    }
}

impl VirtualScreenManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve runtime base directory under `~/.cua-ycwang/virtual_screens`
    /// (or `$CUA_YCWANG_HOME/virtual_screens`), falling back to `/tmp/cua-ycwang-<uid>`.
    pub fn runtime_root() -> PathBuf {
        if let Some(home) = cua_driver_core::ycwang_env::resolve_ycwang_home() {
            return home.join("virtual_screens");
        }
        let uid = current_uid();
        PathBuf::from(format!("/tmp/cua-ycwang-{uid}")).join("virtual_screens")
    }

    /// Reap orphaned virtual-screen processes, stale runtime directories, and
    /// dead `/tmp/.X<n>-lock` / `/tmp/.X11-unix/X<n>` files left by crashes (`SIGKILL`).
    pub fn reap_stale_runtime(&self) -> usize {
        let root = Self::runtime_root();
        let Ok(entries) = fs::read_dir(&root) else {
            return 0;
        };
        let active_displays: Vec<String> = {
            let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
            guard.keys().cloned().collect()
        };

        let mut reaped = 0usize;
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let rt_file = dir.join("runtime.json");
            let Ok(text) = fs::read_to_string(&rt_file) else {
                continue;
            };
            let Ok(rt) = serde_json::from_str::<PersistedRuntime>(&text) else {
                let _ = fs::remove_dir_all(&dir);
                reaped += 1;
                continue;
            };
            if active_displays.contains(&rt.display_id) {
                continue;
            }
            if is_pid_alive(rt.pid_xvfb) {
                // Only reap when Xvfb is dead (or orphaned from a prior crashed daemon).
                continue;
            }
            for pid in [
                rt.pid_x11vnc,
                rt.pid_autocutsel,
                rt.pid_openbox,
                rt.pid_atspi,
                rt.pid_dbus,
            ]
            .into_iter()
            .flatten()
            {
                if is_pid_alive(pid) {
                    send_sigterm_then_kill(pid);
                }
            }
            cleanup_x11_socket_and_lock(rt.display_num);
            let _ = fs::remove_dir_all(&dir);
            global_screen_pool().invalidate(&rt.display_id);
            reaped += 1;
        }
        reaped
    }

    /// Create and boot a new isolated virtual X11 screen.
    pub fn create(&self, req: CreateVirtualScreenRequest) -> Result<VirtualScreenInfo> {
        let _ = self.reap_stale_runtime();

        let width = req.width.unwrap_or(DEFAULT_WIDTH).max(320);
        let height = req.height.unwrap_or(DEFAULT_HEIGHT).max(240);
        let display_num = {
            let mut reserved = self
                .reserved_displays
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let active_nums: HashSet<u16> = {
                let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
                guard.values().map(|s| s.info.display_num).collect()
            };
            let n = allocate_free_display_excluding(req.preferred_display, &reserved, &active_nums)?;
            reserved.insert(n);
            n
        };
        let _reservation_guard = DisplayReservationGuard {
            reserved: &self.reserved_displays,
            display_num,
        };
        let display_id = format!(":{display_num}");

        let runtime_dir = Self::runtime_root().join(format!("display_{display_num}"));
        if runtime_dir.exists() {
            let _ = fs::remove_dir_all(&runtime_dir);
        }
        fs::create_dir_all(&runtime_dir)
            .with_context(|| format!("failed to create {}", runtime_dir.display()))?;

        let xauth_path = runtime_dir.join("Xauthority");
        let cookie = random_bytes::<16>()?;
        write_xauthority_file(&xauth_path, display_num, &cookie)?;

        let mut children: Vec<Child> = Vec::new();
        let geometry = format!("{width}x{height}x24");
        let xvfb = Command::new("Xvfb")
            .arg(&display_id)
            .args(["-screen", "0", &geometry])
            .arg("-auth")
            .arg(&xauth_path)
            .args([
                "+extension",
                "COMPOSITE",
                "+extension",
                "XTEST",
                "+extension",
                "MIT-SHM",
                "-nolisten",
                "tcp",
                "-s",
                "0",
                "-dpms",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn Xvfb")?;
        let pid_xvfb = xvfb.id();
        children.push(xvfb);

        if let Err(err) = wait_for_x11_ready(&display_id, &xauth_path, Duration::from_secs(5)) {
            terminate_children(&mut children);
            cleanup_x11_socket_and_lock(display_num);
            let _ = fs::remove_dir_all(&runtime_dir);
            return Err(err);
        }

        // Start independent D-Bus session daemon (if available).
        let (dbus_address, pid_dbus, pid_atspi, dbus_children) = spawn_dbus_session();
        children.extend(dbus_children);

        // Start Openbox WM preferring ~/.config/cua-ycwang/openbox/rc.xml.
        let (pid_openbox, openbox_child) =
            spawn_openbox(&display_id, &xauth_path, dbus_address.as_deref());
        if let Some(child) = openbox_child {
            children.push(child);
        }

        // Start autocutsel clipboard manager (if available).
        let (pid_autocutsel, autocutsel_child) = spawn_autocutsel(&display_id, &xauth_path);
        if let Some(child) = autocutsel_child {
            children.push(child);
        }

        // Optional localhost x11vnc with 0600 random passwdfile (never -nopw).
        // Defaults to -viewonly unless req.vnc_interactive is true (which enables -xkb).
        let (vnc_port, vnc_passwd_path, pid_x11vnc) = if req.enable_vnc {
            let port = 5900 + display_num;
            let pw_path = runtime_dir.join("vnc.passwd");
            let pw_hex = random_hex(12)?;
            write_mode_0600(&pw_path, pw_hex.as_bytes())?;
            let vnc_args =
                build_x11vnc_args(&display_id, &xauth_path, port, &pw_path, req.vnc_interactive);
            let mut vnc_cmd = Command::new("x11vnc");
            vnc_cmd
                .args(&vnc_args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child = vnc_cmd.spawn().context("failed to spawn x11vnc")?;
            let pid = child.id();
            children.push(child);
            (Some(port), Some(pw_path), Some(pid))
        } else {
            (None, None, None)
        };

        let info = VirtualScreenInfo {
            display_id: display_id.clone(),
            display_num,
            width,
            height,
            xauth_path: xauth_path.clone(),
            dbus_address: dbus_address.clone(),
            vnc_port,
            session_id: req.session_id.clone(),
            pid_xvfb,
            pid_openbox,
            pid_dbus,
            pid_autocutsel,
            pid_x11vnc,
        };

        let persisted = PersistedRuntime {
            display_id: info.display_id.clone(),
            display_num,
            width,
            height,
            xauth_path: xauth_path.clone(),
            vnc_passwd_path: vnc_passwd_path.clone(),
            dbus_address: dbus_address.clone(),
            vnc_port,
            session_id: req.session_id,
            pid_xvfb,
            pid_openbox,
            pid_dbus,
            pid_atspi,
            pid_autocutsel,
            pid_x11vnc,
            created_at_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let body = serde_json::to_string_pretty(&persisted)?;
        write_mode_0600(&runtime_dir.join("runtime.json"), body.as_bytes())?;

        // Warm X11ScreenPool entry with explicit xauth_path & dbus_address.
        let _ = global_screen_pool().get_or_connect_explicit(
            &DisplayTarget::Virtual(display_id.clone()),
            Some(&xauth_path),
            dbus_address.as_deref(),
        );

        let mut guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            display_id,
            ManagedScreen {
                info: info.clone(),
                runtime_dir,
                vnc_passwd_path,
                children,
                launched_children: Vec::new(),
            },
        );
        Ok(info)
    }

    /// List all active virtual screens managed by this process.
    pub fn list(&self) -> Vec<VirtualScreenInfo> {
        let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
        guard.values().map(|s| s.info.clone()).collect()
    }

    /// Destroy a managed virtual screen and clean up all child processes and locks.
    pub fn destroy(&self, display_id: &str) -> Result<()> {
        let removed = {
            let mut guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(display_id)
        };
        let Some(mut screen) = removed else {
            bail!("virtual screen '{display_id}' not found");
        };
        let display_num = screen.info.display_num;
        if let Some(pw) = screen.vnc_passwd_path.take() {
            let _ = fs::remove_file(pw);
        }
        drop(screen);
        cleanup_x11_socket_and_lock(display_num);
        Ok(())
    }

    /// Destroy all virtual screens bound to `session_id` (used by `SessionEndHook`).
    pub fn destroy_for_session(&self, session_id: &str) {
        let matching: Vec<String> = {
            let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .iter()
                .filter(|(_, s)| s.info.session_id.as_deref() == Some(session_id))
                .map(|(k, _)| k.clone())
                .collect()
        };
        for display_id in matching {
            let _ = self.destroy(&display_id);
        }
    }

    /// Resolve a `display_id` for a tool call from an explicit `display_id` or
    /// a `session_id` bound to a virtual screen.
    pub fn resolve_display_for_session(
        &self,
        session_id: Option<&str>,
        explicit_display_id: Option<&str>,
    ) -> Option<String> {
        if let Some(id) = explicit_display_id.filter(|s| !s.trim().is_empty()) {
            if id == "primary" {
                return None;
            }
            return Some(id.to_owned());
        }
        let sid = session_id?;
        let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .values()
            .find(|s| s.info.session_id.as_deref() == Some(sid))
            .map(|s| s.info.display_id.clone())
    }

    /// Connect to `display_id` through `X11ScreenPool` if it is a virtual display.
    pub fn connect_context(&self, display_id: &str) -> Result<std::sync::Arc<X11ScreenContext>> {
        let target = DisplayTarget::from_display_id(Some(display_id))?;
        global_screen_pool().get_or_connect(&target)
    }

    /// Launch an application inside `display_id` with isolated `DISPLAY`,
    /// `XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS`, `_JAVA_AWT_WM_NONREPARENTING=1`,
    /// and `GTK_IM_MODULE=xim`.
    pub fn launch_app(
        &self,
        display_id: &str,
        command: &str,
        args: &[String],
        extra_env: &HashMap<String, String>,
    ) -> Result<LaunchedAppInfo> {
        let info = {
            let guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .get(display_id)
                .map(|s| s.info.clone())
                .ok_or_else(|| anyhow!("virtual screen '{display_id}' not found"))?
        };

        let mut cmd = Command::new(command);
        cmd.args(args)
            .env("DISPLAY", &info.display_id)
            .env("XAUTHORITY", &info.xauth_path)
            .env("_JAVA_AWT_WM_NONREPARENTING", "1")
            .env("GTK_IM_MODULE", "xim")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if should_unset_dbus_for_launch(command, args, extra_env) {
            cmd.env_remove("DBUS_SESSION_BUS_ADDRESS");
        } else if let Some(ref dbus) = info.dbus_address {
            cmd.env("DBUS_SESSION_BUS_ADDRESS", dbus);
        }
        for (k, v) in extra_env {
            if matches!(
                k.as_str(),
                "DISPLAY" | "XAUTHORITY" | "DBUS_SESSION_BUS_ADDRESS" | "CUA_UNSET_DBUS"
            ) {
                continue;
            }
            cmd.env(k, v);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to launch '{command}' on {display_id}"))?;
        let pid = child.id();

        {
            let mut guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(screen) = guard.get_mut(&info.display_id) {
                screen
                    .launched_children
                    .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
                screen.launched_children.push(child);
            }
        }

        Ok(LaunchedAppInfo {
            display_id: info.display_id,
            pid,
            command: command.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn insert_test_screen_for_routing(&self, display_id: &str, session_id: &str) {
        let display_num = display_id
            .trim_start_matches(':')
            .split('.')
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(132);
        let mut guard = self.screens.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            display_id.to_owned(),
            ManagedScreen {
                info: VirtualScreenInfo {
                    display_id: display_id.to_owned(),
                    display_num,
                    width: DEFAULT_WIDTH,
                    height: DEFAULT_HEIGHT,
                    xauth_path: PathBuf::from("/tmp/nonexistent-xauth"),
                    dbus_address: None,
                    vnc_port: None,
                    session_id: Some(session_id.to_owned()),
                    pid_xvfb: 0,
                    pid_openbox: None,
                    pid_dbus: None,
                    pid_autocutsel: None,
                    pid_x11vnc: None,
                },
                runtime_dir: PathBuf::from("/tmp/nonexistent-cua-test-dir"),
                vnc_passwd_path: None,
                children: Vec::new(),
                launched_children: Vec::new(),
            },
        );
    }
}

/// Process-wide shared [`VirtualScreenManager`].
pub fn global_virtual_screen_manager() -> &'static VirtualScreenManager {
    static MANAGER: OnceLock<VirtualScreenManager> = OnceLock::new();
    MANAGER.get_or_init(VirtualScreenManager::new)
}

/// Check if `/tmp/.X11-unix/X<n>` and `/tmp/.X<n>-lock` are both absent.
pub fn is_display_slot_free(display_num: u16) -> bool {
    let sock = PathBuf::from(format!("/tmp/.X11-unix/X{display_num}"));
    let lock = PathBuf::from(format!("/tmp/.X{display_num}-lock"));
    !sock.exists() && !lock.exists()
}

/// Scan `:99..:199` (or validate `preferred`) for a free X11 display slot.
pub fn allocate_free_display(preferred: Option<u16>) -> Result<u16> {
    let empty = HashSet::new();
    allocate_free_display_excluding(preferred, &empty, &empty)
}

fn allocate_free_display_excluding(
    preferred: Option<u16>,
    reserved: &HashSet<u16>,
    active: &HashSet<u16>,
) -> Result<u16> {
    if let Some(n) = preferred {
        if !(VIRTUAL_DISPLAY_MIN..=VIRTUAL_DISPLAY_MAX).contains(&n) {
            bail!(
                "preferred_display {n} out of allowed range {VIRTUAL_DISPLAY_MIN}..={VIRTUAL_DISPLAY_MAX}"
            );
        }
        if !reserved.contains(&n) && !active.contains(&n) && is_display_slot_free(n) {
            return Ok(n);
        }
        bail!("preferred_display :{n} is already in use");
    }
    for n in VIRTUAL_DISPLAY_MIN..=VIRTUAL_DISPLAY_MAX {
        if !reserved.contains(&n) && !active.contains(&n) && is_display_slot_free(n) {
            return Ok(n);
        }
    }
    bail!(
        "no free virtual X11 display slot available in :{VIRTUAL_DISPLAY_MIN}..:{VIRTUAL_DISPLAY_MAX}"
    )
}

fn wait_for_x11_ready(display_id: &str, xauth_path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let display_num = display_id.trim_start_matches(':');
    let sock_path = PathBuf::from(format!("/tmp/.X11-unix/X{display_num}"));
    while Instant::now() < deadline {
        if sock_path.exists() && xauth_path.exists() {
            if let Ok(ctx) = X11ScreenContext::connect_with_explicit(
                &DisplayTarget::Virtual(display_id.into()),
                Some(xauth_path),
                None,
            ) {
                let _ = ctx.root_window();
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("Xvfb on {display_id} did not become ready within {timeout:?}")
}

fn spawn_dbus_session() -> (Option<String>, Option<u32>, Option<u32>, Vec<Child>) {
    let Ok(mut child) = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return (None, None, None, Vec::new());
    };

    let pid = child.id();
    let address = child.stdout.take().and_then(|mut out| {
        let mut buf = [0u8; 512];
        let n = out.read(&mut buf).ok()?;
        let line = std::str::from_utf8(&buf[..n]).ok()?;
        let addr = line.lines().next()?.trim().to_owned();
        (!addr.is_empty()).then_some(addr)
    });

    let mut spawned = vec![child];
    let mut pid_atspi = None;
    if let Some(ref addr) = address {
        // Best-effort AT-SPI bus launcher inside the isolated D-Bus session.
        for candidate in [
            "/usr/libexec/at-spi-bus-launcher",
            "/usr/lib/at-spi2-core/at-spi-bus-launcher",
        ] {
            if Path::new(candidate).exists() {
                if let Ok(atspi_child) = Command::new(candidate)
                    .env("DBUS_SESSION_BUS_ADDRESS", addr)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    pid_atspi = Some(atspi_child.id());
                    spawned.push(atspi_child);
                }
                break;
            }
        }
    }

    (address, Some(pid), pid_atspi, spawned)
}

fn spawn_openbox(
    display_id: &str,
    xauth_path: &Path,
    dbus_address: Option<&str>,
) -> (Option<u32>, Option<Child>) {
    let mut cmd = Command::new("openbox");
    cmd.env("DISPLAY", display_id)
        .env("XAUTHORITY", xauth_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dbus) = dbus_address {
        cmd.env("DBUS_SESSION_BUS_ADDRESS", dbus);
    }
    if let Some(cfg_dir) = cua_driver_core::ycwang_env::resolve_ycwang_config_dir() {
        let rc = cfg_dir.join("openbox").join("rc.xml");
        if rc.exists() {
            cmd.arg("--config-file").arg(rc);
        }
    }
    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            (Some(pid), Some(child))
        }
        Err(_) => (None, None),
    }
}

fn spawn_autocutsel(display_id: &str, xauth_path: &Path) -> (Option<u32>, Option<Child>) {
    match Command::new("autocutsel")
        .env("DISPLAY", display_id)
        .env("XAUTHORITY", xauth_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            (Some(pid), Some(child))
        }
        Err(_) => (None, None),
    }
}

fn terminate_children(children: &mut Vec<Child>) {
    // Terminate in reverse spawn order (apps / x11vnc / autocutsel / openbox / at-spi / dbus / Xvfb)
    // with SIGTERM -> bounded WNOHANG poll -> SIGKILL -> bounded WNOHANG reap so no <defunct> remains.
    for child in children.iter_mut().rev() {
        if matches!(child.try_wait(), Ok(None)) {
            // SAFETY: standard POSIX SIGTERM to a live child PID owned by this process.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
    }

    let term_deadline = Instant::now() + Duration::from_millis(150);
    while Instant::now() < term_deadline {
        let mut any_alive = false;
        for child in children.iter_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                any_alive = true;
            }
        }
        if !any_alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    for child in children.iter_mut().rev() {
        if matches!(child.try_wait(), Ok(None)) {
            let pid = child.id();
            let _ = child.kill();
            reap_child_with_timeout(child, pid, Duration::from_millis(500));
        }
    }
    children.clear();
}

fn reap_child_with_timeout(child: &mut Child, pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    reap_pid_with_timeout(pid, Duration::from_millis(50));
}

fn reap_pid_with_timeout(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: non-blocking waitpid on a specific PID.
        let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if rc == pid as libc::pid_t || rc < 0 {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_x11_socket_and_lock(display_num: u16) {
    let sock = PathBuf::from(format!("/tmp/.X11-unix/X{display_num}"));
    let lock = PathBuf::from(format!("/tmp/.X{display_num}-lock"));
    if lock.exists() {
        let _ = fs::remove_file(lock);
    }
    if sock.exists() {
        let _ = fs::remove_file(sock);
    }
}

fn is_pid_alive(pid: u32) -> bool {
    // Reap if it is a zombie child of this process so /proc/<pid> clears.
    // SAFETY: non-blocking waitpid on a specific PID.
    unsafe {
        libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG);
    }
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(after_comm) = stat.rfind(')') else {
        return false;
    };
    let state = stat[after_comm + 1..].trim_start().chars().next();
    !matches!(state, Some('Z') | Some('X') | None)
}

fn send_sigterm_then_kill(pid: u32) {
    // SAFETY: standard POSIX signal to a recorded child PID.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(50));
    if is_pid_alive(pid) {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        reap_pid_with_timeout(pid, Duration::from_millis(300));
    }
}

fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    let mut f = fs::File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn random_hex(num_bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; num_bytes];
    let mut f = fs::File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn write_mode_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Write a binary `.Xauthority` file with `0600` permissions containing a
/// `FamilyLocal` (`256`) `MIT-MAGIC-COOKIE-1` entry for `display_num`.
pub(crate) fn write_xauthority_file(path: &Path, display_num: u16, cookie: &[u8; 16]) -> Result<()> {
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "localhost".to_owned())
        .trim()
        .to_owned();
    let display_str = display_num.to_string();

    let mut blob = Vec::with_capacity(64);
    let push_field = |buf: &mut Vec<u8>, bytes: &[u8]| {
        let len = bytes.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    // FamilyLocal = 256
    blob.extend_from_slice(&256u16.to_be_bytes());
    push_field(&mut blob, hostname.as_bytes());
    push_field(&mut blob, display_str.as_bytes());
    push_field(&mut blob, b"MIT-MAGIC-COOKIE-1");
    push_field(&mut blob, cookie);

    write_mode_0600(path, &blob)
}

/// Build `x11vnc` CLI arguments. When `vnc_interactive` is true, `-xkb` is
/// included so Remmina/VNC keyboard typing works on `Xvfb` out-of-the-box.
pub(crate) fn build_x11vnc_args(
    display_id: &str,
    xauth_path: &Path,
    port: u16,
    pw_path: &Path,
    vnc_interactive: bool,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args = vec![
        OsString::from("-display"),
        OsString::from(display_id),
        OsString::from("-auth"),
        xauth_path.as_os_str().to_owned(),
        OsString::from("-localhost"),
    ];
    if vnc_interactive {
        args.push(OsString::from("-xkb"));
    } else {
        args.push(OsString::from("-viewonly"));
    }
    args.extend([
        OsString::from("-forever"),
        OsString::from("-shared"),
        OsString::from("-rfbport"),
        OsString::from(port.to_string()),
        OsString::from("-passwdfile"),
        pw_path.as_os_str().to_owned(),
    ]);
    args
}

/// Returns true when launching a `java_install4j` + JxBrowser app (e.g.
/// `thinkorswim`) or when explicit isolation hints request unsetting
/// `DBUS_SESSION_BUS_ADDRESS` to avoid the 25s OSCrypt Libsecret hang + SIGTRAP 133.
pub(crate) fn should_unset_dbus_for_launch(
    command: &str,
    args: &[String],
    extra_env: &HashMap<String, String>,
) -> bool {
    let matches_jxbrowser_app = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("thinkorswim") || lower.contains("jxbrowser")
    };
    if matches_jxbrowser_app(command) || args.iter().any(|a| matches_jxbrowser_app(a)) {
        return true;
    }
    if extra_env
        .get("CUA_UNSET_DBUS")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    {
        return true;
    }
    extra_env
        .get("DBUS_SESSION_BUS_ADDRESS")
        .is_some_and(|v| v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn xauthority_file_is_written_with_0600_mode() {
        let dir = tempfile::tempdir().unwrap();
        let auth = dir.path().join("Xauthority");
        let cookie = [0xABu8; 16];
        write_xauthority_file(&auth, 99, &cookie).unwrap();
        let meta = fs::metadata(&auth).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(fs::read(&auth).unwrap().ends_with(&cookie));
    }

    #[test]
    fn allocate_free_display_rejects_out_of_range_preferred() {
        assert!(allocate_free_display(Some(0)).is_err());
        assert!(allocate_free_display(Some(98)).is_err());
        assert!(allocate_free_display(Some(200)).is_err());
    }

    #[test]
    fn x11vnc_args_include_xkb_when_interactive_and_viewonly_otherwise() {
        let xauth = Path::new("/tmp/Xauthority");
        let pw = Path::new("/tmp/vnc.passwd");

        let interactive = build_x11vnc_args(":132", xauth, 6032, pw, true);
        let interactive_strs: Vec<String> = interactive
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(interactive_strs.contains(&"-xkb".to_owned()));
        assert!(!interactive_strs.contains(&"-viewonly".to_owned()));

        let viewonly = build_x11vnc_args(":132", xauth, 6032, pw, false);
        let viewonly_strs: Vec<String> = viewonly
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(viewonly_strs.contains(&"-viewonly".to_owned()));
        assert!(!viewonly_strs.contains(&"-xkb".to_owned()));
    }

    #[test]
    fn should_unset_dbus_for_thinkorswim_and_explicit_hint() {
        let empty_env = HashMap::new();
        assert!(should_unset_dbus_for_launch(
            "/home/ycwang/work/schwab/thinkorswim/thinkorswim",
            &[],
            &empty_env
        ));
        assert!(!should_unset_dbus_for_launch("/usr/bin/xterm", &[], &empty_env));

        let mut hinted = HashMap::new();
        hinted.insert("CUA_UNSET_DBUS".to_owned(), "1".to_owned());
        assert!(should_unset_dbus_for_launch("/usr/bin/java", &[], &hinted));
    }
}
