// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Multi-screen X11 connection pool (`X11ScreenPool`) and per-display context.
//!
//! Resolves X11 connection, `XAUTHORITY` cookie, and session D-Bus address
//! explicitly per [`DisplayTarget`] without mutating process-global
//! `DISPLAY`, `XAUTHORITY`, or `DBUS_SESSION_BUS_ADDRESS` environment variables.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use x11rb::connection::Connection as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::rust_connection::{DefaultStream, RustConnection};

/// Target X11 display: either the session's primary display or an explicit
/// virtual X11 display (such as `":99"` or `":99.0"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DisplayTarget {
    Primary,
    Virtual(String),
}

impl DisplayTarget {
    /// Parse an optional `display_id` string into a [`DisplayTarget`].
    /// `None` or `"primary"` maps to [`DisplayTarget::Primary`]; valid X11
    /// display strings (`^:\d+(\.\d+)?$`) map to [`DisplayTarget::Virtual`].
    pub fn from_display_id(display_id: Option<&str>) -> Result<Self> {
        match display_id {
            None | Some("primary") => Ok(Self::Primary),
            Some(id) if cua_driver_core::action_target::is_valid_display_id(id) => {
                Ok(Self::Virtual(id.to_owned()))
            }
            Some(other) => Err(anyhow!(
                "invalid display_id '{other}': expected 'primary' or an X11 display like ':99'"
            )),
        }
    }

    /// Resolve the concrete `DISPLAY` string for this target.
    pub fn resolve_display_string(&self) -> Result<String> {
        match self {
            Self::Primary => std::env::var("DISPLAY")
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("DISPLAY is not set for Primary target")),
            Self::Virtual(d) => Ok(d.clone()),
        }
    }
}

/// Cached MIT-SHM probe state for a display connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmSessionInfo {
    pub supported: bool,
    pub major_version: u16,
    pub minor_version: u16,
}

/// Per-display X11 connection and resolved isolation metadata.
pub struct X11ScreenContext {
    pub display_id: String,
    pub target: DisplayTarget,
    pub xauth_path: Option<PathBuf>,
    pub dbus_address: Option<String>,
    pub conn: Arc<RustConnection>,
    pub screen_num: usize,
    pub shm_session: Option<ShmSessionInfo>,
}

impl X11ScreenContext {
    /// Root window XID for `self.screen_num`.
    pub fn root_window(&self) -> u32 {
        self.conn.setup().roots[self.screen_num].root
    }

    /// Connect to `target` without mutating process-global environment variables.
    pub fn connect(target: &DisplayTarget) -> Result<Self> {
        Self::connect_with_explicit(target, None, None)
    }

    /// Connect to `target` using explicit `xauth_path` and `dbus_address` when
    /// known (e.g. from `VirtualScreenManager`), falling back to per-display
    /// `/proc` discovery only when omitted.
    pub fn connect_with_explicit(
        target: &DisplayTarget,
        explicit_xauth: Option<&Path>,
        explicit_dbus: Option<&str>,
    ) -> Result<Self> {
        let display_id = target.resolve_display_string()?;
        let xauth_path = explicit_xauth
            .map(Path::to_path_buf)
            .or_else(|| crate::xauth::resolve_for_display(&display_id).map(PathBuf::from));
        let dbus_address = explicit_dbus
            .map(ToOwned::to_owned)
            .or_else(|| crate::session_bus::resolve_for_display(&display_id));

        let (conn, screen_num) =
            connect_explicit(&display_id, xauth_path.as_deref()).with_context(|| {
                format!(
                    "failed to connect to X11 display '{display_id}' (xauth={})",
                    xauth_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<none>".to_owned())
                )
            })?;

        let shm_session = probe_shm(&conn);

        Ok(Self {
            display_id,
            target: target.clone(),
            xauth_path,
            dbus_address,
            conn: Arc::new(conn),
            screen_num,
            shm_session,
        })
    }
}

fn probe_shm(conn: &RustConnection) -> Option<ShmSessionInfo> {
    let reply = conn.shm_query_version().ok()?.reply().ok()?;
    Some(ShmSessionInfo {
        supported: true,
        major_version: reply.major_version,
        minor_version: reply.minor_version,
    })
}

/// Connect to `display_id` using an explicit `xauth_path` (if provided) without
/// modifying `XAUTHORITY` or `DISPLAY` in the process environment.
fn connect_explicit(display_id: &str, xauth_path: Option<&Path>) -> Result<(RustConnection, usize)> {
    use x11rb::reexports::x11rb_protocol::parse_display;

    let parsed = parse_display::parse_display(Some(display_id))
        .map_err(|e| anyhow!("invalid X11 display '{display_id}': {e}"))?;
    let screen = usize::from(parsed.screen);

    if let Some(auth_file) = xauth_path {
        for addr in parsed.connect_instruction() {
            if let Ok((stream, (family, address))) = DefaultStream::connect(&addr) {
                if let Ok(Some((auth_name, auth_data))) =
                    read_xauth_entry(auth_file, family, &address, parsed.display)
                {
                    if let Ok(conn) = RustConnection::connect_to_stream_with_auth_info(
                        stream,
                        screen,
                        auth_name,
                        auth_data,
                    ) {
                        return Ok((conn, screen));
                    }
                }
            }
        }
    }

    let (conn, screen_num) = RustConnection::connect(Some(display_id))?;
    Ok((conn, screen_num))
}

fn read_be_u16(reader: &mut impl std::io::Read) -> std::io::Result<Option<u16>> {
    let mut buf = [0u8; 2];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(Some(u16::from_be_bytes(buf))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_be_bytes(reader: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let len = read_be_u16(reader)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
    let mut buf = vec![0u8; usize::from(len)];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_xauth_entry(
    auth_file: &Path,
    family: x11rb::reexports::x11rb_protocol::xauth::Family,
    address: &[u8],
    display: u16,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let file = std::fs::File::open(auth_file)?;
    let mut reader = std::io::BufReader::new(file);
    let display_str = display.to_string();
    let display_bytes = display_str.as_bytes();

    while let Some(entry_family) = read_be_u16(&mut reader)? {
        let entry_addr = read_be_bytes(&mut reader)?;
        let entry_num = read_be_bytes(&mut reader)?;
        let entry_name = read_be_bytes(&mut reader)?;
        let entry_data = read_be_bytes(&mut reader)?;
        if x11rb::reexports::x11rb_protocol::xauth::Family::from(entry_family) == family
            && entry_addr == address
            && entry_num == display_bytes
        {
            return Ok(Some((entry_name, entry_data)));
        }
    }
    Ok(None)
}

/// Thread-safe cache of [`X11ScreenContext`] instances keyed by `display_id`.
#[derive(Default)]
pub struct X11ScreenPool {
    contexts: Mutex<HashMap<String, Arc<X11ScreenContext>>>,
}

impl X11ScreenPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a cached [`X11ScreenContext`] for `target`, or connect and cache it.
    pub fn get_or_connect(&self, target: &DisplayTarget) -> Result<Arc<X11ScreenContext>> {
        self.get_or_connect_explicit(target, None, None)
    }

    /// Return a cached [`X11ScreenContext`] for `target`, or connect using
    /// explicit `xauth_path` and `dbus_address` and cache it.
    pub fn get_or_connect_explicit(
        &self,
        target: &DisplayTarget,
        explicit_xauth: Option<&Path>,
        explicit_dbus: Option<&str>,
    ) -> Result<Arc<X11ScreenContext>> {
        let key = target.resolve_display_string()?;
        {
            let guard = self.contexts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ctx) = guard.get(&key) {
                return Ok(Arc::clone(ctx));
            }
        }

        let ctx = Arc::new(X11ScreenContext::connect_with_explicit(
            target,
            explicit_xauth,
            explicit_dbus,
        )?);
        let mut guard = self.contexts.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(key).or_insert_with(|| Arc::clone(&ctx));
        Ok(Arc::clone(entry))
    }

    /// Remove a cached context (e.g., after connection drop or display teardown).
    pub fn invalidate(&self, display_id: &str) {
        let mut guard = self.contexts.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(display_id);
    }

    /// List currently cached display IDs.
    pub fn cached_displays(&self) -> Vec<String> {
        let guard = self.contexts.lock().unwrap_or_else(|e| e.into_inner());
        guard.keys().cloned().collect()
    }
}

/// Process-wide shared [`X11ScreenPool`].
pub fn global_screen_pool() -> &'static X11ScreenPool {
    static POOL: OnceLock<X11ScreenPool> = OnceLock::new();
    POOL.get_or_init(X11ScreenPool::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_primary_and_virtual_display_targets() {
        assert_eq!(
            DisplayTarget::from_display_id(None).unwrap(),
            DisplayTarget::Primary
        );
        assert_eq!(
            DisplayTarget::from_display_id(Some("primary")).unwrap(),
            DisplayTarget::Primary
        );
        assert_eq!(
            DisplayTarget::from_display_id(Some(":99")).unwrap(),
            DisplayTarget::Virtual(":99".to_owned())
        );
        assert_eq!(
            DisplayTarget::from_display_id(Some(":99.0")).unwrap(),
            DisplayTarget::Virtual(":99.0".to_owned())
        );
        assert!(DisplayTarget::from_display_id(Some("secondary")).is_err());
        assert!(DisplayTarget::from_display_id(Some(":abc")).is_err());
    }

    #[test]
    fn virtual_display_resolves_without_reading_global_env() {
        let target = DisplayTarget::Virtual(":99".to_owned());
        assert_eq!(target.resolve_display_string().unwrap(), ":99");
    }

    #[test]
    fn pool_starts_empty_and_invalidate_is_safe() {
        let pool = X11ScreenPool::new();
        assert!(pool.cached_displays().is_empty());
        pool.invalidate(":99");
        assert!(pool.cached_displays().is_empty());
    }
}
