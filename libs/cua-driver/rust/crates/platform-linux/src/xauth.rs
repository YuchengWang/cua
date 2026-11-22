// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Xwayland `XAUTHORITY` auto-discovery for SSH-driven Wayland sessions.
//!
//! When cua-driver is driven over SSH against a Wayland+Xwayland desktop,
//! `DISPLAY` is typically inherited (e.g. `:0`) but `XAUTHORITY` is not.
//! Xwayland authenticates X11 clients with a per-session MIT cookie passed to
//! it via its own `-auth <file>` argument, which an X11 client cannot guess —
//! so every X11 connect fails with "Authorization required, but no
//! authorization protocol specified" (empty `list_windows`, failing
//! `get_screen_size` / `get_cursor_position`, overlay connect errors). See
//! issue #1926.
//!
//! [`ensure_xauthority_discovered`] recovers the cookie by reading the running
//! Xwayland (or Xorg) process's `-auth` argument out of `/proc` and exporting
//! it as `XAUTHORITY` before the first X11 connect. It is a no-op when
//! `XAUTHORITY` is already set or there is no `DISPLAY`, and runs at most once.

use std::sync::OnceLock;

static DONE: OnceLock<()> = OnceLock::new();

/// Discover and export `XAUTHORITY` from the running X server's `-auth`
/// argument when it is unset on a session that has a `DISPLAY`. Idempotent
/// (runs once per process) and safe to call eagerly at daemon startup.
pub fn ensure_xauthority_discovered() {
    DONE.get_or_init(|| {
        // Already have an explicit cookie, or no X11 DISPLAY to authenticate
        // against — nothing to do.
        if std::env::var_os("XAUTHORITY").is_some() {
            return;
        }
        if std::env::var_os("DISPLAY").is_none() {
            return;
        }
        if let Some(auth) = discover_xauth_from_proc() {
            // SAFETY: set early at startup, before any X11 connect / worker
            // thread reads the environment.
            std::env::set_var("XAUTHORITY", &auth);
            tracing::info!(
                target: "cua-driver",
                "XAUTHORITY was unset; adopted the running X server's auth cookie at {auth} (#1926)"
            );
        } else {
            tracing::debug!(
                target: "cua-driver",
                "XAUTHORITY unset and no X server -auth cookie found in /proc; \
                 X11 connects may fail with 'Authorization required' (#1926)"
            );
        }
    });
}

/// Parse virtual X11 display number (`:99`..`:199`, optionally with `.screen`).
fn parse_virtual_display_num(display_id: &str) -> Option<u16> {
    let rest = display_id.trim().strip_prefix(':')?;
    let num_part = rest.split('.').next().unwrap_or("");
    let num = num_part.parse::<u16>().ok()?;
    (99..=199).contains(&num).then_some(num)
}

fn virtual_screen_xauth_path(display_num: u16) -> Option<String> {
    let path = crate::x11::virtual_screen::VirtualScreenManager::runtime_root()
        .join(format!("display_{display_num}"))
        .join("Xauthority");
    path.exists().then(|| path.to_string_lossy().into_owned())
}

/// Resolve `XAUTHORITY` for a specific X11 `display_id` (e.g. `":99"`) without
/// mutating process-global environment variables.
///
/// For virtual displays (`:99`..`:199`), only the virtual screen's dedicated
/// `Xauthority` or a `/proc` X server matching `display_id` is used; never fall
/// back to the host `XAUTHORITY` environment variable or host X server discovery.
pub fn resolve_for_display(display_id: &str) -> Option<String> {
    if let Some(display_num) = parse_virtual_display_num(display_id) {
        if let Some(auth) = virtual_screen_xauth_path(display_num) {
            return Some(auth);
        }
        return discover_xauth_for_display_from_proc(display_id);
    }
    if let Some(auth) = discover_xauth_for_display_from_proc(display_id) {
        return Some(auth);
    }
    if let Ok(existing) = std::env::var("XAUTHORITY") {
        let trimmed = existing.trim();
        if !trimmed.is_empty() && std::path::Path::new(trimmed).exists() {
            return Some(trimmed.to_owned());
        }
    }
    discover_xauth_from_proc()
}

fn discover_xauth_for_display_from_proc(display_id: &str) -> Option<String> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_dir = entry.path();
        let comm = std::fs::read_to_string(pid_dir.join("comm")).unwrap_or_default();
        match comm.trim() {
            "Xvfb" | "Xwayland" | "Xorg" | "X" => {}
            _ => continue,
        }
        let cmdline = match std::fs::read(pid_dir.join("cmdline")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        let has_display = args
            .iter()
            .any(|arg| std::str::from_utf8(arg).ok() == Some(display_id));
        if !has_display {
            continue;
        }
        for pair in args.windows(2) {
            if pair[0] == b"-auth" {
                if let Ok(path) = std::str::from_utf8(pair[1]) {
                    if !path.is_empty() && std::path::Path::new(path).exists() {
                        return Some(path.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// Scan `/proc` for an X server process (`Xwayland`, `Xorg`, or `X`) and return
/// the existing file named by its `-auth <file>` argument, if any.
fn discover_xauth_from_proc() -> Option<String> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_dir = entry.path();
        // `comm` is the (possibly truncated) executable name + trailing newline.
        let comm = std::fs::read_to_string(pid_dir.join("comm")).unwrap_or_default();
        match comm.trim() {
            "Xwayland" | "Xorg" | "X" => {}
            _ => continue,
        }
        // `cmdline` is NUL-separated argv. Find `-auth` and take the next arg.
        let cmdline = match std::fs::read(pid_dir.join("cmdline")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        for pair in args.windows(2) {
            if pair[0] == b"-auth" {
                if let Ok(path) = std::str::from_utf8(pair[1]) {
                    if !path.is_empty() && std::path::Path::new(path).exists() {
                        return Some(path.to_owned());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn virtual_display_xauth_never_falls_back_to_host_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let host_xauth = dir.path().join("host_Xauthority");
        std::fs::write(&host_xauth, b"host-cookie").unwrap();

        let prev_home = std::env::var_os("CUA_YCWANG_HOME");
        let prev_xauth = std::env::var_os("XAUTHORITY");
        std::env::set_var("CUA_YCWANG_HOME", dir.path());
        std::env::set_var("XAUTHORITY", &host_xauth);

        let resolved = resolve_for_display(":198");

        match prev_home {
            Some(v) => std::env::set_var("CUA_YCWANG_HOME", v),
            None => std::env::remove_var("CUA_YCWANG_HOME"),
        }
        match prev_xauth {
            Some(v) => std::env::set_var("XAUTHORITY", v),
            None => std::env::remove_var("XAUTHORITY"),
        }

        assert_eq!(resolved, None);
    }

    #[test]
    fn virtual_display_prefers_dedicated_virtual_screen_xauthority() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let host_xauth = dir.path().join("host_Xauthority");
        std::fs::write(&host_xauth, b"host-cookie").unwrap();
        let virtual_dir = dir.path().join("virtual_screens").join("display_198");
        std::fs::create_dir_all(&virtual_dir).unwrap();
        let virtual_xauth = virtual_dir.join("Xauthority");
        std::fs::write(&virtual_xauth, b"virtual-cookie").unwrap();

        let prev_home = std::env::var_os("CUA_YCWANG_HOME");
        let prev_xauth = std::env::var_os("XAUTHORITY");
        std::env::set_var("CUA_YCWANG_HOME", dir.path());
        std::env::set_var("XAUTHORITY", &host_xauth);

        let resolved = resolve_for_display(":198");

        match prev_home {
            Some(v) => std::env::set_var("CUA_YCWANG_HOME", v),
            None => std::env::remove_var("CUA_YCWANG_HOME"),
        }
        match prev_xauth {
            Some(v) => std::env::set_var("XAUTHORITY", v),
            None => std::env::remove_var("XAUTHORITY"),
        }

        assert_eq!(resolved.as_deref(), Some(virtual_xauth.to_string_lossy().as_ref()));
    }
}
