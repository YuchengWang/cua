# Changelog — `YuchengWang/cua` (`feat/x11-virtual-desktop`)

> Self-maintained Linux X11 Virtual Screen & Dual-Version branch based on `trycua/cua` (`upstream/main` @ `2a15e141e2`, `cua-driver-rs-v0.57.0`).  
> 自维护 Linux X11 虚拟桌面与双版本隔离分支变更日志（基于 `trycua/cua`）。

---

## [Unreleased] — `feat/x11-virtual-desktop`

### Post-M5 Hotfix: Virtual `get_window_state` Contract & `xtest_type_text` Focus/Clipboard Hardening (`2026-11-22`, Landed)
- **Fixed / 修复**：
  - `platform-linux/src/tools/mcp_virtual_screen.rs`: Replaced ad-hoc JSON in `virtual_get_window_state` with `cua_driver_contract::WindowStateOutput` serialization (`build_virtual_window_state_output`), guaranteeing non-null `pid: u32` (falling back to caller `pid` or `0` when `_NET_WM_PID` is absent) and aligned `window_title`, `screenshot_width`/`screenshot_height`, `screenshot_mime_type`, `screenshot_frame_valid`, and `window_bounds` fields to eliminate `typed_output_mismatch`. Added contract unit tests.
  - `platform-linux/src/x11/virtual_input.rs` & `mcp_virtual_screen.rs`: Added `xtest_focus_window` (`_NET_ACTIVE_WINDOW` + `ConfigureWindow(Above)` + `SetInputFocus`) invoked by `virtual_type_text` when `window_id` or `pid` is provided, and hardened `xtest_type_text` non-ASCII clipboard paste timings (`45ms` selection-ownership settle before `Ctrl+V`, `80ms` paste-read settle before restoring previous clipboard).

### Milestone 5: Release Build, Isolated Installation & Full E2E Gate (`2026-11-22`, Landed)
- **Built & Installed / 编译与隔离安装**：
  - `cargo build --release -p cua-driver -p cursor-theme-cli` passed (exit 0).
  - Installed isolated binaries to `~/.cua-ycwang/packages/current/cua-ycwang` and `cua-cursor-theme`, symlinked `~/.local/bin/cua-ycwang`, and deployed `deploy/linux/user/` to `~/.config/cua-ycwang/` via `deploy-user-config.sh` (without touching `~/.local/bin/cua-driver`, `~/.cua-driver/`, or `~/.cache/cua-driver/`).
- **Verified / 全量验收**：
  - `CUA_YCWANG_CONFIG_DIR=~/.config/cua-ycwang CUA_YCWANG_HOME=~/.cua-ycwang ~/.local/bin/cua-ycwang doctor --json` returned `ok: true` with `elevation_required` (`io.github.yuchengwang.cua.uinput.setup`) when system rules are not yet installed.
  - Real Xorg E2E tests passed: `virtual_screen_m2_xorg` (4/4), `virtual_screen_m3_e2e_xorg` (2/2), `virtual_screen_m4_xorg` (2/2), and `cua-driver-core batch_tools` (69/69, `--test-threads=1`).
  - Security audits (`cua-security-auditor`) passed across M1–M4 (`0600` xauth/VNC passwords, `127.0.0.1` VNC, clipboard isolation, `screen_locked` guard, `elevate` allowlist).

### Milestone 4: Desktop Interaction Enhancements, `doctor --json` & `elevate` (`2026-11-22`, Landed)
- **Added / 新增**：
  - `libs/cua-driver/rust/crates/platform-linux/src/x11/virtual_input.rs`: `XTest`-based virtual screen input (`xtest_move_cursor`, `xtest_click`, `xtest_double_click`, `xtest_drag`, `xtest_scroll`, `xtest_press_key`, `xtest_hotkey`, `xtest_type_text` with non-ASCII `CLIPBOARD` save -> UTF-8 -> `Ctrl+V` -> restore).
  - `libs/cua-driver/rust/crates/platform-linux/src/tools/mcp_clipboard.rs`: `get_clipboard`, `set_clipboard`, and `sync_clipboard` tools (explicit-only cross-display sync, registered in `authorization.rs` / `tool.rs` with `clipboard.read` / `clipboard.write`).
  - `libs/cua-driver/rust/crates/platform-linux/src/x11/screen_guard.rs`: Primary display lock-screen & DPMS probe (`logind LockedHint` + `xset q`), returning `code: "screen_locked"` when locked without attempting unlock.
- **Changed / 变更**：
  - `platform-linux/src/x11/virtual_screen.rs`: Added `pending_displays` mutex reservation for concurrent `create()`, `/proc/{pid}/stat` `'Z'`/`'X'`/`'x'` check in `is_pid_alive()`, `extra_env` override protection (`DISPLAY`/`XAUTHORITY`/`DBUS_SESSION_BUS_ADDRESS`), and `PersistedRuntime.pid_atspi` tracking.
  - `platform-linux/src/x11/mod.rs`: Supplemented `list_windows_with_context` with `QueryTree` for `MapState::VIEWABLE` + `override_redirect == true` popups/tooltips.
  - `platform-linux/src/tools/{get_window_state,click,type_text,press_key,hotkey,scroll,drag}.rs`: Wired `resolve_virtual_display_from_args` -> `X11ScreenPool` + `XTest`.
  - `cua-driver/src/doctor.rs`, `cli.rs`, `main.rs`: Added X11/uinput/Polkit/SHA-256 probes outputting `elevation_required: ElevationRequired` in `doctor --json`, plus `elevate --action-id <id> [--json]` calling `elevation::run_pkexec_allowlisted`.
  - `cua-driver-core/src/batch_tools.rs`: Added `wait_for_stable_frame` and `on_error: "dismiss_modal_and_retry"` to `run_steps`.
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cursor-overlay -p cua-driver --all-targets -- -D warnings` passed.
  - `virtual_screen_m3_e2e_xorg`, `platform-linux --lib`, `cua-driver --bin cua-driver` (418 passed), `schema_consistency_test` (4 passed), and `cua-driver-core` all passed.

### Milestone 3: `VirtualScreenManager`, MCP Virtual Screen Tools & Self-Healing (`2026-11-22`, Landed)
- **Added / 新增**：
  - `libs/cua-driver/rust/crates/platform-linux/src/x11/virtual_screen.rs`: `VirtualScreenManager` scanning `:99..:199`, generating `0600` `Xauthority` cookies (`/dev/urandom`), launching `Xvfb` (`-auth`, `-nolisten tcp`, `-s 0 -dpms`, no `-ac`), `openbox`, optional isolated `dbus-daemon` + `at-spi-bus-launcher` + `autocutsel`, optional loopback `x11vnc` (`-localhost -viewonly -passwdfile`, `0600`), `runtime.json` (`0600`), and `reap_stale_runtime()` crash recovery.
  - `libs/cua-driver/rust/crates/platform-linux/src/tools/mcp_virtual_screen.rs`: MCP handlers for `create_virtual_screen`, `list_virtual_screens`, `destroy_virtual_screen`, and `launch_in_virtual_screen` (injecting `DISPLAY`, `XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS`, `_JAVA_AWT_WM_NONREPARENTING=1`, `GTK_IM_MODULE=xim`).
  - `libs/cua-driver/rust/crates/platform-linux/tests/virtual_screen_m2_xorg.rs`: Real `Xvfb` E2E tests for dual-display pool isolation and `XComposite` occluded-window capture (including `Pixmap` `visual=0` fix in `composite_capture.rs`).
- **Changed / 变更**：
  - `cua-driver-core/src/authorization.rs` & `tool.rs`: Classified virtual screen tools under `RiskClass::R3` with `display.virtual` capability.
  - `platform-linux/src/tools/{mod.rs,impl_.rs,get_desktop_state.rs,get_screen_size.rs,list_windows.rs}`: Wired `display_id` routing through `X11ScreenPool` and registered the 4 virtual screen MCP tools.
- **Verified / 已核验**：
  - M3 security audit (`cua-security-auditor`) passed across `virtual_screen.rs`, `mcp_virtual_screen.rs`, `authorization.rs`, `tool.rs`, and `reap_stale_runtime()` (`0600` xauth/VNC passwords, `127.0.0.1` VNC, no shell injection).

### Milestone 2: `X11ScreenPool` & `XComposite` Offscreen Capture (`2026-11-22`, Landed)
- **Added / 新增**：
  - `libs/cua-driver/rust/crates/platform-linux/src/x11/context.rs`: `DisplayTarget` (`Primary` / `Virtual(String)`), `X11ScreenContext`, and `X11ScreenPool` (`RwLock<HashMap<String, Arc<X11ScreenContext>>>`) with explicit `XAUTHORITY` resolution.
  - `libs/cua-driver/rust/crates/platform-linux/src/x11/composite_capture.rs`: `XComposite` offscreen capture (`CompositeCaptureOutcome::UnmappedFallback` on `IsUnmapped`, `CompositeRedirectWindow`, `CompositeNameWindowPixmap`, RAII `PixmapGuard` calling `free_pixmap` on drop).
- **Changed (Thin Hooks) / 变更（薄钩子）**：
  - `platform-linux/src/xauth.rs` & `session_bus.rs`: Added `resolve_for_display(display_id)` scanning `/proc` without mutating global `XAUTHORITY` / `DBUS_SESSION_BUS_ADDRESS`.
  - `platform-linux/src/desktop.rs`: Added `classify_for(display_id, ...)` returning `Desktop::X11` for virtual X11 displays without polluting global `DESKTOP` cache.
  - `platform-linux/src/capture.rs` & `x11/mod.rs`: Preserved original signatures as `Primary` wrappers and added `*_with_context` variants (`screenshot_window_bytes_with_context`, `screenshot_display_bytes_with_context`, `active_window_with_context`, `list_windows_with_context`, `window_exists_with_context`, `window_info_with_context`).
- **Verified / 已核验**：
  - `cargo clippy -p platform-linux -p cursor-overlay -p cua-driver --all-targets -- -D warnings` passed (exit 0).
  - `cargo test -p platform-linux -- --test-threads=4`, `cargo test -p cursor-overlay -- --test-threads=4`, `cargo test -p cua-driver --bin cua-driver -- --test-threads=4` (418 passed) all passed.

### Milestone 1: Namespace Isolation, Elevation Contract & `deploy/linux/` SSOT (`2026-11-22`, Landed)
- **Added / 新增**：
  - `libs/cua-driver/rust/crates/cua-driver-core/src/ycwang_env.rs`: `CUA_YCWANG_CONFIG_DIR` / `CUA_YCWANG_HOME` / `CUA_DRIVER_STATE_NAMESPACE` resolution.
  - `libs/cua-driver/rust/crates/cua-driver-core/src/elevation.rs`: `ElevationRequired`, `ElevationMode`, `validate_pkexec_invocation()`, `build_pkexec_command()`, `run_pkexec_allowlisted()`.
  - `deploy/linux/`: Full `user/` configs, `system/` (`99-cua-uinput.rules`, Polkit `.policy` & `.rules`, `cua-elevated-helper`), and `scripts/` (`deploy-user-config.sh`, `install-system-rules.sh`, `doctor-linux.sh`).
- **Changed / 变更**：
  - `cua-driver/src/bundle.rs`: Added `YCWANG_CLI_NAME`, `path_is_ycwang()`, `is_ycwang_installation()`.
  - `cua-driver-core/src/config_file.rs`: Delegated `default_config_path()` to `ycwang_env::resolve_config_file()`.
  - `cua-driver-core/src/action_target.rs`: Replaced `display_id != "primary"` check with `is_valid_display_id()`.
  - `cua-driver/src/history_runtime.rs` & `cursor-overlay/src/motion_defaults.rs`: Isolated remaining state/config paths for `cua-ycwang`.
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p cua-driver --all-targets -- -D warnings` passed.
  - `cargo test -p cua-driver-core -- --test-threads=4` & `cargo test -p cua-driver -- --test-threads=4` passed.

---

### Milestone 0: Repository Baseline & Bilingual Docs Gate (`2026-11-22`)
- **Added / 新增**：
  - Initialized bilingual architecture and permission documentation under `docs/`:
    - `docs/LINUX_X11_VIRTUAL_SCREEN_PLAN.md` & `docs/LINUX_X11_VIRTUAL_SCREEN_PLAN.zh.md`
    - `docs/LINUX_X11_PERMISSIONS.md` & `docs/LINUX_X11_PERMISSIONS.zh.md`
    - `docs/CHANGELOG_YCWANG.md`
  - Added `deploy/linux/scripts/check-docs-sync.sh` to enforce:
    - Bilingual heading symmetry (`##` / `###`) between `.md` and `.zh.md` pairs;
    - Mandatory doc + changelog updates whenever `libs/cua-driver/` or `deploy/linux/` changes are committed.
- **Verified / 已核验**：
  - `cargo check -p cua-driver` passed on `2a15e141e2` with Rust `1.97.1`.
  - All 15 X11/Xvfb/openbox/x11vnc/autocutsel/AT-SPI system dependencies verified installed.

---

---

### Target Release Tag
- `ycwang-x11-v0.57.0-m5` on `feat/x11-virtual-desktop` (pending final MCP JSON-RPC E2E & `git commit` by `cua-driver-dev`).
