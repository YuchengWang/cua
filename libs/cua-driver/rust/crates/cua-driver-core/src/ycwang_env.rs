// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Dual-version isolation environment resolution for `cua-ycwang`.
//!
//! Keeps `cua-ycwang` configuration, runtime home, and state namespace
//! completely isolated from upstream `cua-driver` (`~/.cua-driver`) and
//! `cua-driver-local` (`~/.cua-driver-local`).
//!
//! Precedence:
//! 1. Explicit environment overrides (`CUA_YCWANG_CONFIG_DIR`, `CUA_YCWANG_HOME`,
//!    `CUA_DRIVER_STATE_NAMESPACE`)
//! 2. Executable identity (`cua-ycwang` / `cua-ycwang.exe`)
//! 3. Upstream default (`~/.cua-driver` / `cua-driver`)

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Environment variable overriding the `cua-ycwang` config directory.
/// Defaults to `~/.config/cua-ycwang` when `cua-ycwang` isolation is active.
pub const YCWANG_CONFIG_DIR_ENV: &str = "CUA_YCWANG_CONFIG_DIR";

/// Environment variable overriding the `cua-ycwang` runtime home directory.
/// Defaults to `~/.cua-ycwang` when `cua-ycwang` isolation is active.
pub const YCWANG_HOME_ENV: &str = "CUA_YCWANG_HOME";

/// Environment variable overriding the state namespace (socket, history, etc.).
pub const STATE_NAMESPACE_ENV: &str = "CUA_DRIVER_STATE_NAMESPACE";

/// Canonical CLI name, state namespace, and subdirectory for `cua-ycwang`.
pub const YCWANG_CLI_NAME: &str = "cua-ycwang";
pub const YCWANG_NAMESPACE: &str = "cua-ycwang";
pub const YCWANG_HOME_SUBDIR: &str = ".cua-ycwang";
pub const DEFAULT_NAMESPACE: &str = "cua-driver";
pub const DEFAULT_HOME_SUBDIR: &str = ".cua-driver";

/// Resolved environment snapshot for `cua-ycwang` isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YcwangEnv {
    pub is_isolated: bool,
    pub state_namespace: String,
    pub home_dir: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
}

impl YcwangEnv {
    /// Resolve the active environment from process env vars and `current_exe`.
    pub fn resolve() -> Self {
        let exe = std::env::current_exe().ok();
        Self::resolve_with(|k| std::env::var_os(k), exe.as_deref())
    }

    /// Pure resolution helper for deterministic unit testing.
    pub fn resolve_with<F>(get_env: F, exe_path: Option<&Path>) -> Self
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let ns_override = non_empty_env(&get_env, STATE_NAMESPACE_ENV);
        let config_dir_override = non_empty_env(&get_env, YCWANG_CONFIG_DIR_ENV).map(PathBuf::from);
        let home_override = non_empty_env(&get_env, YCWANG_HOME_ENV).map(PathBuf::from);
        let exe_is_ycwang = exe_path.is_some_and(is_ycwang_exe_path);

        let is_isolated = ns_override.as_deref() == Some(YCWANG_NAMESPACE)
            || config_dir_override.is_some()
            || home_override.is_some()
            || exe_is_ycwang;

        let state_namespace = if let Some(ns) = ns_override {
            ns
        } else if exe_is_ycwang || is_isolated {
            YCWANG_NAMESPACE.to_owned()
        } else {
            DEFAULT_NAMESPACE.to_owned()
        };

        let user_home = resolve_user_home_with(&get_env);

        let home_dir = if is_isolated {
            home_override.or_else(|| user_home.as_ref().map(|h| h.join(YCWANG_HOME_SUBDIR)))
        } else {
            user_home.as_ref().map(|h| h.join(DEFAULT_HOME_SUBDIR))
        };

        let config_dir = if is_isolated {
            config_dir_override.or_else(|| {
                user_home
                    .as_ref()
                    .map(|h| h.join(".config").join(YCWANG_NAMESPACE))
            })
        } else {
            user_home.as_ref().map(|h| h.join(DEFAULT_HOME_SUBDIR))
        };

        let config_file = config_dir.as_ref().map(|d| d.join("config.json"));

        Self {
            is_isolated,
            state_namespace,
            home_dir,
            config_dir,
            config_file,
        }
    }
}

fn non_empty_env<F>(get_env: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<OsString>,
{
    get_env(key)
        .and_then(|v| v.into_string().ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn resolve_user_home_with<F>(get_env: &F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    get_env("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| get_env("USERPROFILE").filter(|v| !v.is_empty()))
        .map(PathBuf::from)
}

/// Returns `true` if `path` has executable name `cua-ycwang` or `cua-ycwang.exe`.
pub fn is_ycwang_exe_path(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    file_name == YCWANG_CLI_NAME || file_name == format!("{YCWANG_CLI_NAME}.exe")
}

/// Returns `CUA_DRIVER_STATE_NAMESPACE` if set and non-empty.
pub fn resolve_state_namespace_from_env() -> Option<String> {
    non_empty_env(&|k| std::env::var_os(k), STATE_NAMESPACE_ENV)
}

/// Returns `true` when `cua-ycwang` isolation mode is active via env or executable name.
pub fn is_ycwang_active() -> bool {
    YcwangEnv::resolve().is_isolated
}

/// Resolve the `cua-ycwang` config directory (`$CUA_YCWANG_CONFIG_DIR` or `~/.config/cua-ycwang`).
pub fn resolve_ycwang_config_dir() -> Option<PathBuf> {
    let get_env = |k: &str| std::env::var_os(k);
    non_empty_env(&get_env, YCWANG_CONFIG_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| {
            resolve_user_home_with(&get_env).map(|h| h.join(".config").join(YCWANG_NAMESPACE))
        })
}

/// Alias for [`resolve_ycwang_config_dir`].
pub fn config_dir() -> Option<PathBuf> {
    resolve_ycwang_config_dir()
}

/// Resolve the `cua-ycwang` runtime home directory (`$CUA_YCWANG_HOME` or `~/.cua-ycwang`).
pub fn resolve_ycwang_home() -> Option<PathBuf> {
    let get_env = |k: &str| std::env::var_os(k);
    non_empty_env(&get_env, YCWANG_HOME_ENV)
        .map(PathBuf::from)
        .or_else(|| resolve_user_home_with(&get_env).map(|h| h.join(YCWANG_HOME_SUBDIR)))
}

/// Resolve the canonical `config.json` path for the active mode:
/// - Isolated (`cua-ycwang`): `$CUA_YCWANG_CONFIG_DIR/config.json` (default `~/.config/cua-ycwang/config.json`)
/// - Upstream default: `~/.cua-driver/config.json`
pub fn resolve_config_file() -> Option<PathBuf> {
    YcwangEnv::resolve().config_file
}

/// Resolve a named config file (e.g., `x11_profiles.json`, `policy.json`) in the
/// active config directory.
pub fn resolve_named_config_file(filename: &str) -> Option<PathBuf> {
    YcwangEnv::resolve()
        .config_dir
        .map(|dir| dir.join(filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_from<'a>(pairs: &[(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(*v)))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn upstream_default_preserves_legacy_cua_driver_paths() {
        let resolved = YcwangEnv::resolve_with(
            env_from(&[("HOME", "/home/alice")]),
            Some(Path::new("/usr/local/bin/cua-driver")),
        );
        assert!(!resolved.is_isolated);
        assert_eq!(resolved.state_namespace, "cua-driver");
        assert_eq!(
            resolved.home_dir,
            Some(PathBuf::from("/home/alice/.cua-driver"))
        );
        assert_eq!(
            resolved.config_dir,
            Some(PathBuf::from("/home/alice/.cua-driver"))
        );
        assert_eq!(
            resolved.config_file,
            Some(PathBuf::from("/home/alice/.cua-driver/config.json"))
        );
    }

    #[test]
    fn exe_name_cua_ycwang_activates_isolated_defaults() {
        let resolved = YcwangEnv::resolve_with(
            env_from(&[("HOME", "/home/alice")]),
            Some(Path::new("/usr/local/bin/cua-ycwang")),
        );
        assert!(resolved.is_isolated);
        assert_eq!(resolved.state_namespace, "cua-ycwang");
        assert_eq!(
            resolved.home_dir,
            Some(PathBuf::from("/home/alice/.cua-ycwang"))
        );
        assert_eq!(
            resolved.config_dir,
            Some(PathBuf::from("/home/alice/.config/cua-ycwang"))
        );
        assert_eq!(
            resolved.config_file,
            Some(PathBuf::from("/home/alice/.config/cua-ycwang/config.json"))
        );
    }

    #[test]
    fn env_overrides_take_precedence_over_defaults() {
        let resolved = YcwangEnv::resolve_with(
            env_from(&[
                ("HOME", "/home/alice"),
                ("CUA_YCWANG_CONFIG_DIR", "/tmp/custom-cfg"),
                ("CUA_YCWANG_HOME", "/tmp/custom-home"),
                ("CUA_DRIVER_STATE_NAMESPACE", "cua-ycwang-staging"),
            ]),
            Some(Path::new("/usr/local/bin/cua-driver")),
        );
        assert!(resolved.is_isolated);
        assert_eq!(resolved.state_namespace, "cua-ycwang-staging");
        assert_eq!(resolved.home_dir, Some(PathBuf::from("/tmp/custom-home")));
        assert_eq!(resolved.config_dir, Some(PathBuf::from("/tmp/custom-cfg")));
        assert_eq!(
            resolved.config_file,
            Some(PathBuf::from("/tmp/custom-cfg/config.json"))
        );
    }

    #[test]
    fn namespace_env_alone_triggers_isolation() {
        let resolved = YcwangEnv::resolve_with(
            env_from(&[
                ("HOME", "/home/alice"),
                ("CUA_DRIVER_STATE_NAMESPACE", "cua-ycwang"),
            ]),
            Some(Path::new("/usr/local/bin/cua-driver")),
        );
        assert!(resolved.is_isolated);
        assert_eq!(resolved.state_namespace, "cua-ycwang");
        assert_eq!(
            resolved.config_file,
            Some(PathBuf::from("/home/alice/.config/cua-ycwang/config.json"))
        );
    }

    #[test]
    fn empty_env_overrides_are_ignored() {
        let resolved = YcwangEnv::resolve_with(
            env_from(&[
                ("HOME", "/home/alice"),
                ("CUA_YCWANG_CONFIG_DIR", "   "),
                ("CUA_YCWANG_HOME", ""),
                ("CUA_DRIVER_STATE_NAMESPACE", ""),
            ]),
            Some(Path::new("/usr/local/bin/cua-driver")),
        );
        assert!(!resolved.is_isolated);
        assert_eq!(resolved.state_namespace, "cua-driver");
    }

    #[test]
    fn detects_ycwang_executable_names() {
        assert!(is_ycwang_exe_path(Path::new("/usr/local/bin/cua-ycwang")));
        assert!(is_ycwang_exe_path(Path::new("/dev/.cua-ycwang/cua-ycwang.exe")));
        assert!(!is_ycwang_exe_path(Path::new("/usr/local/bin/cua-driver")));
        assert!(!is_ycwang_exe_path(Path::new(
            "/usr/local/bin/cua-driver-local"
        )));
    }
}
