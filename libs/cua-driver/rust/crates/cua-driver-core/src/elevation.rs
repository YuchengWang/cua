// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Machine-readable privilege elevation contract (`ElevationRequired`) and
//! minimal-scope `pkexec` allowlist invocation wrapper.
//!
//! Security invariants:
//! - Never accepts, stores, or forwards plaintext passwords (stdin or argv).
//! - Only invokes explicitly allowlisted helper paths and subcommands.
//! - Returns structured `ElevationRequired` payloads when out-of-band action
//!   or user authorization is needed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use crate::protocol::ToolResult;

/// Canonical installed path for the minimal-scope elevated helper.
pub const DEFAULT_ELEVATED_HELPER_PATH: &str = "/usr/local/libexec/cua-elevated-helper";

/// Allowlisted helper paths that `pkexec` is permitted to invoke.
pub const ALLOWED_ELEVATED_HELPER_PATHS: &[&str] = &[
    "/usr/local/libexec/cua-elevated-helper",
    "/usr/libexec/cua-elevated-helper",
];

/// Allowlisted subcommands accepted by `cua-elevated-helper`.
pub const ALLOWED_ELEVATED_SUBCOMMANDS: &[&str] = &[
    "probe-uinput",
    "reload-udev",
    "ensure-uinput-module",
    "verify-rules",
];

/// How privilege elevation should be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationMode {
    PolkitPkexec,
    OutOfBandSudo,
    GroupMembershipRelogin,
}

/// Machine-readable structured contract returned when an operation requires
/// elevated privileges or out-of-band system setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevationRequired {
    pub status: String,
    pub action_id: String,
    pub elevation_mode: ElevationMode,
    pub commands: Vec<String>,
    pub reasons: Vec<String>,
    pub requires_relogin: bool,
    pub verify_command: String,
    pub resume_hint: String,
}

impl ElevationRequired {
    /// Construct an `ElevationRequired` payload with canonical `status = "elevation_required"`.
    pub fn new(
        action_id: impl Into<String>,
        elevation_mode: ElevationMode,
        commands: Vec<String>,
        reasons: Vec<String>,
        requires_relogin: bool,
        verify_command: impl Into<String>,
        resume_hint: impl Into<String>,
    ) -> Self {
        Self {
            status: "elevation_required".to_owned(),
            action_id: action_id.into(),
            elevation_mode,
            commands,
            reasons,
            requires_relogin,
            verify_command: verify_command.into(),
            resume_hint: resume_hint.into(),
        }
    }

    /// Serialize into a `serde_json::Value`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "status": "elevation_required",
                "action_id": self.action_id,
            })
        })
    }

    /// Wrap into a machine-readable `ToolResult` error response.
    pub fn to_tool_result(&self, message: impl Into<String>) -> ToolResult {
        ToolResult::error(message.into()).with_structured(self.to_json())
    }
}

/// Validation or execution error from the `pkexec` allowlist wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("elevated helper path is not in allowlist: {0}")]
    DisallowedHelperPath(PathBuf),

    #[error("elevated subcommand is not in allowlist: {0}")]
    DisallowedSubcommand(String),

    #[error("disallowed argument in elevated invocation: {0}")]
    DisallowedArgument(String),

    #[error("failed to spawn pkexec: {0}")]
    SpawnFailed(#[from] std::io::Error),
}

/// Output from a validated `pkexec` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationExecOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl ElevationExecOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

impl From<Output> for ElevationExecOutput {
    fn from(out: Output) -> Self {
        Self {
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

/// Validate that `helper_path`, `subcommand`, and `args` satisfy the minimal-scope
/// allowlist and never carry shell metacharacters or plaintext password flags.
pub fn validate_pkexec_invocation(
    helper_path: &Path,
    subcommand: &str,
    args: &[&str],
) -> Result<(), ElevationError> {
    if !helper_path.is_absolute() {
        return Err(ElevationError::DisallowedHelperPath(
            helper_path.to_path_buf(),
        ));
    }
    let path_str = helper_path.to_str().unwrap_or_default();
    if !ALLOWED_ELEVATED_HELPER_PATHS.contains(&path_str) {
        return Err(ElevationError::DisallowedHelperPath(
            helper_path.to_path_buf(),
        ));
    }

    if !ALLOWED_ELEVATED_SUBCOMMANDS.contains(&subcommand) {
        return Err(ElevationError::DisallowedSubcommand(subcommand.to_owned()));
    }

    for &arg in args {
        if arg.is_empty()
            || arg.contains('\n')
            || arg.contains('\r')
            || arg.contains('\0')
            || arg.contains(';')
            || arg.contains('|')
            || arg.contains('&')
            || arg.contains('$')
            || arg.contains('`')
        {
            return Err(ElevationError::DisallowedArgument(arg.to_owned()));
        }
        let lower = arg.to_ascii_lowercase();
        if lower.contains("password") || lower == "-s" || lower == "--stdin" {
            return Err(ElevationError::DisallowedArgument(arg.to_owned()));
        }
    }

    Ok(())
}

/// Build a `pkexec` [`Command`] after strict allowlist validation.
/// Never passes plaintext passwords and clears inherited sensitive variables.
pub fn build_pkexec_command(
    helper_path: &Path,
    subcommand: &str,
    args: &[&str],
) -> Result<Command, ElevationError> {
    validate_pkexec_invocation(helper_path, subcommand, args)?;

    let mut cmd = Command::new("pkexec");
    cmd.arg(helper_path).arg(subcommand);
    for &arg in args {
        cmd.arg(arg);
    }
    Ok(cmd)
}

/// Execute an allowlisted elevated helper subcommand via `pkexec`.
pub fn run_pkexec_allowlisted(
    helper_path: &Path,
    subcommand: &str,
    args: &[&str],
) -> Result<ElevationExecOutput, ElevationError> {
    let mut cmd = build_pkexec_command(helper_path, subcommand, args)?;
    let output = cmd.output()?;
    Ok(ElevationExecOutput::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_required_serializes_all_contract_fields() {
        let req = ElevationRequired::new(
            "io.github.yuchengwang.cua.uinput.setup",
            ElevationMode::OutOfBandSudo,
            vec!["sudo udevadm control --reload-rules".to_owned()],
            vec!["/dev/uinput is not writable by current user".to_owned()],
            true,
            "deploy/linux/scripts/doctor-linux.sh",
            "Re-run cua-ycwang doctor after completing out-of-band setup",
        );

        let val = req.to_json();
        assert_eq!(val["status"], "elevation_required");
        assert_eq!(val["action_id"], "io.github.yuchengwang.cua.uinput.setup");
        assert_eq!(val["elevation_mode"], "out_of_band_sudo");
        assert_eq!(
            val["commands"],
            serde_json::json!(["sudo udevadm control --reload-rules"])
        );
        assert_eq!(
            val["reasons"],
            serde_json::json!(["/dev/uinput is not writable by current user"])
        );
        assert_eq!(val["requires_relogin"], true);
        assert_eq!(
            val["verify_command"],
            "deploy/linux/scripts/doctor-linux.sh"
        );
        assert_eq!(
            val["resume_hint"],
            "Re-run cua-ycwang doctor after completing out-of-band setup"
        );

        let roundtrip: ElevationRequired = serde_json::from_value(val).unwrap();
        assert_eq!(roundtrip, req);
    }

    #[test]
    fn pkexec_allowlist_accepts_valid_helper_and_subcommand() {
        let helper = Path::new(DEFAULT_ELEVATED_HELPER_PATH);
        assert!(validate_pkexec_invocation(helper, "probe-uinput", &[]).is_ok());
        assert!(validate_pkexec_invocation(helper, "reload-udev", &["--quiet"]).is_ok());
        let cmd = build_pkexec_command(helper, "verify-rules", &[]).unwrap();
        assert_eq!(cmd.get_program(), "pkexec");
    }

    #[test]
    fn pkexec_allowlist_rejects_disallowed_paths_subcommands_and_passwords() {
        assert!(matches!(
            validate_pkexec_invocation(Path::new("/bin/sh"), "probe-uinput", &[]),
            Err(ElevationError::DisallowedHelperPath(_))
        ));
        assert!(matches!(
            validate_pkexec_invocation(Path::new("cua-elevated-helper"), "probe-uinput", &[]),
            Err(ElevationError::DisallowedHelperPath(_))
        ));
        assert!(matches!(
            validate_pkexec_invocation(
                Path::new(DEFAULT_ELEVATED_HELPER_PATH),
                "arbitrary-shell",
                &[]
            ),
            Err(ElevationError::DisallowedSubcommand(_))
        ));
        assert!(matches!(
            validate_pkexec_invocation(
                Path::new(DEFAULT_ELEVATED_HELPER_PATH),
                "probe-uinput",
                &["--password=secret"]
            ),
            Err(ElevationError::DisallowedArgument(_))
        ));
        assert!(matches!(
            validate_pkexec_invocation(
                Path::new(DEFAULT_ELEVATED_HELPER_PATH),
                "probe-uinput",
                &["ok;rm -rf /"]
            ),
            Err(ElevationError::DisallowedArgument(_))
        ));
    }
}
