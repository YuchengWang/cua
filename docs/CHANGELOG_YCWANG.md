# Changelog — `YuchengWang/cua` (`feat/x11-virtual-desktop`)

> Self-maintained Linux X11 Virtual Screen & Dual-Version branch based on `trycua/cua` (`upstream/main` @ `2a15e141e2`, `cua-driver-rs-v0.57.0`).  
> 自维护 Linux X11 虚拟桌面与双版本隔离分支变更日志（基于 `trycua/cua`）。

---

## [Unreleased] — `feat/x11-virtual-desktop`

### P0–P2 4-Tier Interaction & Capability Routing (`acquire_app_data`, Curated Overlay, `SafetyLevel` Gate & `Artifact` Actions) (`2026-11-22`, Landed)
- **Added / Changed**：
  - `cua-driver-core/src/app_recipe.rs`: Added `DataChannel`, `SafetyLevel`, `OutputSchema`, `CapabilitySpec`, `SafetyPolicy`, and optional `RecipeStep` metadata (`method`, `safety_level`, `latency_ms_est`, `fallback_method`) with full `#[serde(default)]` backward compatibility; upgraded `AppRecipeCache` to track `(source_path, modified_ns, file_len)` (and overlay stamp) for automatic disk invalidation/reload; added `merge_curated_overlay()` and updated `find_best_recipe_for_app()` / `find_best_recipe_with_path()` to merge `<app_id>.json` curated overlays onto version-pinned `<app_id>_v<ver>_<fp8>.json` base recipes while preserving base identity fields.
  - `platform-linux/src/app_inspector.rs`: Added `is_shell_only_atspi()` so `java_install4j` apps (TWS / Thinkorswim) exposing only top-level shell nodes remain `atspi_blind: true` (`visual_grounding_plus_hotkeys`) instead of being misclassified as `atspi_semantic`.
  - `platform-linux/src/tools/mcp_app_recipe.rs` (plus `tools/impl_.rs`, `cua-driver-core/src/authorization.rs`, `cua-driver-core/src/tool.rs`): Added `read_clipboard`, `set_clipboard`, and `verify_file_export` flow actions returning structured `artifacts[]` alongside `steps`; added `acquire_app_data` MCP tool (`R3` / `app.data.acquire`) with 4-tier capability routing, `screenshot_roi` cropping via `roi_norm`, automatic fallback, inline `format_artifacts_summary()` in MCP text output, and runtime `SafetyLevel` gate (`safety_gate_blocked` for `restricted`, `blocked_flows`, `blocked_shortcuts`, and `type_secret_from_env` defaulting to `auth_only`); enforced `SafetyLevel` gate (`allow_safety_level` default `"auth_only"`) in `run_app_recipe`.
  - `deploy/linux/user/app_recipes/{thinkorswim.json,tws.json}`: Upgraded with `capabilities` (`workspace_health`, `account_statement`, `probability_table`, `chart_visual` for Thinkorswim; `workspace_health`, `watchlist_snapshot`, `portfolio_export` for TWS), `safety_policy`, `"safety_level": "auth_only"` on `login_*` flows, `probability_table_cell` (`rel_x: 0.50, rel_y: 0.65`) + `clear_before: true` clipboard calibration, while preserving all existing `login_*`, `switch_*`, and `export_account_statement_csv` flows.
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cua-driver --all-targets -- -D warnings` passed.
  - `cargo test -p cua-driver-core --lib` (`1396 passed; 2 ignored`), `cargo test -p platform-linux --lib` (`1154 passed; 16 ignored`), and `cargo test -p cua-driver --test schema_consistency_test` (`4 passed`) all passed.
  - Live stdio MCP verification (`cua-ycwang mcp` on ephemeral `1920x1080` virtual screen) confirmed `login_live_from_env` under `allow_safety_level="read_only"` is rejected with `safety_gate_blocked` before step 0, `login_live_from_env` under `auth_only` succeeds (`11/11` steps), `acquire_app_data(account_statement)` hits Tier-1 `file_export` (`fallback_used: false`, `1993` bytes) with inline CSV preview, and `acquire_app_data(probability_table)` falls back cleanly to `screenshot_roi` (`1613x842`, `148240` bytes) with inline artifact summary.

### Out-of-Band `.env` Secret Typing (`type_secret_from_env`) for Thinkorswim & TWS (`2026-11-22`, Landed)
- **Added / 新增**：
  - `platform-linux/src/tools/mcp_type_secret.rs`: Added `type_secret_from_env` MCP tool (registered in `tools/mod.rs`, `tools/impl_.rs`, `cua-driver-core/src/authorization.rs` as `R2`, and `cua-driver-core/src/tool.rs` with `input.keyboard.type`), enforcing strict `CUA_YCWANG_` key-prefix validation (`validate_env_key()`), `.env` resolution (`env_file` > `CUA_YCWANG_ENV_FILE` > `./.env` > `~/.config/cua-ycwang/.env` > process env fallback), clean `.env` parsing (`export `, comments, first-`=` split, matching quotes), `zeroize::Zeroizing` memory handling, Swing-safe `xtest_type_text()` + optional `Return` synthesis, and zero-leak output (`Typed env secret (key=..., len=...) on <display_id>`).
  - `platform-linux/src/tools/mcp_app_recipe.rs`: Added `"action": "type_secret_from_env"` support in `execute_recipe_step()` for `run_app_recipe` `flows`.
  - `deploy/linux/user/app_recipes/{thinkorswim.json,tws.json}`: Added `login_from_env` / `login_live_from_env` / `login_paper_from_env` flow stubs (login-only; zero order-placement actions), `Logon to thinkorswim` bottom-bar toggle/input/continue anchors, `1920x1080` `Main@thinkorswim` tab/subtab anchors, and `tws.json` `.*(Interactive Brokers|Trader Workstation|Simulated Trading).*` title matching.
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cua-driver --all-targets -- -D warnings` passed.
  - `cargo test -p cua-driver-core --lib` (`1395 passed; 0 failed`) and `cargo test -p platform-linux --lib` (`1149 passed; 0 failed; 16 ignored`) passed.

### Thinkorswim & TWS Local-JSON Fast Execution, Non-Screenshot Verification & Launch Isolation (`2026-11-22`, Landed)
- **Changed / 变更**：
  - `platform-linux/src/x11/virtual_screen.rs`: Added `build_x11vnc_args()` including `-xkb` by default when `vnc_interactive=true` (so Remmina keyboard typing works on `Xvfb` out-of-the-box) and `-viewonly` otherwise; added `should_unset_dbus_for_launch()` in `launch_app()` to unset `DBUS_SESSION_BUS_ADDRESS` for `thinkorswim` / `jxbrowser` (or `CUA_UNSET_DBUS=1`) so direct launches avoid the 25s OSCrypt Libsecret hang + `SIGTRAP` 133.
  - `platform-linux/src/app_inspector.rs`: Added `/proc/<pid>/cwd` & `cmdline` `install4j` root resolution (`resolve_install4j_dir()`), `usergui/<ver>/tos-usergui-base-*.jar` version & SHA-256 detection (`find_highest_usergui_jar()`), `[build <num>]` window-title fallback (`parse_window_title_build()`), `# ... <ver>` varfile parsing, and differentiated `thinkorswim` (`java_install4j` + JxBrowser hints) vs `tws` metadata.
  - `cua-driver-core/src/app_recipe.rs` & `platform-linux/src/tools/mcp_app_recipe.rs`: Added `RecipeStep` & `AppRecipe::flows`, `resolve_relative_anchor_xy()`, and `find_best_recipe_for_app()` (ranking `java_install4j` / `electron` / `dotnet_avalonia` above `native_elf` `vunknown`); extended `run_app_recipe` with `flow` execution, `click_anchor`, `shortcut` / `hotkey`, and non-screenshot verification primitives (`verify_window_title_regex`, `verify_window_count_min`, `verify_log_pattern`, `verify_clipboard_nonempty`, `wait_for_stable_frame`).
  - `deploy/linux/user/app_recipes/{tws.json,thinkorswim.json}`: Seeded strictly read-only navigation & non-screenshot verification recipes (no order-submission actions).
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cua-driver --all-targets -- -D warnings` passed.
  - `cargo test -p cua-driver-core --lib` (`1396 passed; 0 failed; 3 ignored`) and `cargo test -p platform-linux --lib` (`1144 passed; 0 failed; 16 ignored`) passed.
  - Live MCP stdio E2E on virtual screen `:198` verified `-xkb` on `x11vnc`, direct `thinkorswim` launch without wrapper script (no 25s hang / SIGTRAP 133), live `inspect_app_flow` without `app_path` (`thinkorswim v1994.1.16`, `fp8=6f8008dc`, `java_install4j`), and `run_app_recipe` non-screenshot verification flow (`4/4` steps `ok: true`).

### P0–P2 Field-Feedback Hardening & Differentiated Recipe Generation (`2026-11-22`, Landed)
- **Changed / 变更**：
  - `x11/virtual_screen.rs` & `tools/mcp_virtual_screen.rs`: Added `vnc_interactive: Option<bool>` (default `false` retaining `-viewonly`; when `true`, removes `-viewonly` while keeping `-localhost -forever -shared -passwdfile <0600>`); aligned default virtual screen resolution to `1920x1080`.
  - `cua-driver-contract/src/windows.rs`, `tools/list_windows.rs`, `x11/mod.rs`: Added explicit `display_id` & `session` routing to `list_windows` (`explicit display_id > session > Primary`) and `QueryTree` `MapState::VIEWABLE` popup enumeration filtering `<= 1x1` `FocusProxy` windows.
  - `cua-driver-core/src/app_recipe.rs`, `platform-linux/src/app_inspector.rs`, `tools/mcp_app_recipe.rs`:
    - Added `tech_stack`, `atspi_blind`, `recommended_interaction`, and `launch_isolation_hints` to `AppRecipe`;
    - Fixed `atspi_blind` detection for `window_id`-only and `java_install4j` targets, plus 6x4-grid `visual_hotspots` mapped into `AppRecipe.relative_anchors`;
    - Populated differentiated non-empty recipes per stack: AT-SPI2 rich (`v2rayn_v7.25.1_ab9e208e.json`: `menus=22, anchors=30, atspi_semantic`), Electron (`vscode_v1.146.0_b0432bb8.json`: `shortcuts=10, menus=64, isolation=1`), and Java `install4j` (`ibkr_tws_v10.52.1d_ff4b4710.json`: `atspi_blind=true, visual_grounding_plus_hotkeys, shortcuts=2, anchors=3, isolation=1, modals=1`).
  - `deploy/linux/user/app_recipes/tws.json`: Added `-J-DjtsConfigDir=${CUA_YCWANG_HOME:-$HOME/.cua-ycwang}/jts` isolation guidance and `Warning` / `Trades` / `Watchlist` anchors.
- **Verified / 已核验**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cua-driver --all-targets -- -D warnings` passed.
  - `app_recipe` (3/3), `app_inspector` (4/4), `virtual_screen_m3_e2e_xorg` (2/2), `virtual_screen_m4_xorg` (2/2), and `schema_consistency_test` (4/4) all passed; Release binary updated at `~/.cua-ycwang/packages/current/cua-ycwang`.

### Hotfix: TWS Audit Fixes — Swing CJK `type_text`, Clipboard Routing Priority & Zombie Reaping (`2026-11-22`, Landed)
- **Fixed / 修复**：
  - `platform-linux/src/x11/virtual_input.rs`: Hardened `xtest_type_text()` and `xtest_hotkey()` for Java Swing / TWS mixed ASCII+CJK input (e.g. `"AUDIT_测试_123"`): added `release_stuck_modifiers()` via `QueryKeymap` before typing/pasting, `10ms` press/release separation in `xtest_hotkey()`, `75ms` `CLIPBOARD` Selection ownership settle before `Ctrl+V`, and `150ms` async Swing `SelectionRequest` settle before restoring prior clipboard.
  - `platform-linux/src/tools/mcp_clipboard.rs` & `platform-linux/src/x11/virtual_screen.rs`: Fixed `get_clipboard` / `set_clipboard` display routing priority to `explicit display_id (including "primary" / ":0.0") > session-bound virtual display > Primary`, and updated `resolve_display_for_session` so explicit `"primary"` does not fall back to a session virtual display. Added unit test `explicit_display_id_takes_priority_over_bound_session`.
  - `platform-linux/src/x11/virtual_screen.rs`: Tracked `launch_app()` spawned processes in `ManagedScreen::launched_children` (reaping exited processes on new launches), upgraded `terminate_children()` to reverse-order `SIGTERM` -> bounded `try_wait` -> `SIGKILL` -> bounded `waitpid(WNOHANG)` reaping, and added `reap_pid_with_timeout()` in `send_sigterm_then_kill()` to eliminate `<defunct>` zombie processes on `destroy_virtual_screen`.
- **Verified / 已核验**：
  - `cargo clippy -p platform-linux -p cua-driver --all-targets -- -D warnings`, `virtual_screen_m3_e2e_xorg` (with `/proc/<pid>` zero-zombie assertions), `virtual_screen_m4_xorg` (mixed `"AUDIT_测试_123"`), `platform-linux --lib`, release build & isolated install to `~/.cua-ycwang/packages/current/cua-ycwang`, and `check-docs-sync.sh` all passed.

### R1–R3: Versioned `AppRecipe`, Layered `inspect_app_flow` & Deterministic FSM Replay (`2026-11-22`, Landed)
- **Added / 新增**：
  - `libs/cua-driver/rust/crates/cua-driver-core/src/app_recipe.rs` (exported via `lib.rs`): `AppRecipe`, `VersionGate::verify()`, `RecipeState`, `RecipeTransition`, `AuthGate`, `ModalHandler`, `VerifyResult`, `AppRecipeCache` (`RwLock<HashMap<...>>`), and `sanitize_component()` enforcing `<app_id>_v<version>_<fp8>.json` immutability under `$CUA_YCWANG_CONFIG_DIR/app_recipes/`.
  - `libs/cua-driver/rust/crates/platform-linux/src/app_inspector.rs` (exported via `lib.rs`): `inspect_app_flow()` supporting Chrome `browser_exempt`, Java `install4j` (`response.varfile` + highest-version JAR `META-INF/MANIFEST.MF`), `.NET / Avalonia` (`*.deps.json`), Electron / VS Code (`resources/app/package.json` + `keybindings.json`), `dpkg-query` / ELF fallback, and Tier 1 X11 `WM_CLASS` + AT-SPI2 `walk_tree()`.
  - `libs/cua-driver/rust/crates/platform-linux/src/tools/mcp_app_recipe.rs`: Registered `inspect_app_flow` (`R2` / `app.inspect`), `generate_app_recipe` (`R3` / `app.recipe.write`), and `run_app_recipe` (`R3` / `app.recipe.run`) in `authorization.rs`, `tool.rs`, `tools/mod.rs`, and `tools/impl_.rs`; enforced out-of-band `secret-tool` / `zenity --password` with `zeroize::Zeroizing` (`auth_step_completed`) and immediate CAPTCHA pause (`human_verification_required`).
- **Verified / 全量验收**：
  - `cargo clippy -p cua-driver-core -p platform-linux -p cua-driver --all-targets -- -D warnings` passed.
  - Unit & contract tests passed: `app_recipe` (3/3), `app_inspector` (4/4), `schema_consistency_test` (4/4).
  - Live stdio MCP (`cua-ycwang mcp`, 75 tools) verified across IBKR TWS (`10.52.1d`, `ff4b4710`), v2rayN (`7.25.1`, `ab9e208e`), VS Code (`1.146.0`), Google Chrome (`browser_exempt`), `VersionGate` `version_mismatch` block, hot-cache replay, and virtual-screen `human_verification_required` CAPTCHA pause.
  - Security audit (`cua-security-auditor`) passed across `app_recipe.rs`, `app_inspector.rs`, `mcp_app_recipe.rs`, `authorization.rs`, and `tool.rs`.

---

## [ycwang-x11-v0.57.0-m5] — `3e27a062ab` (`2026-11-22`)

### Docs: Fork Notice, License Compliance & Security Disclaimer in `README.md` (`2026-11-22`, Landed)
- **Added / 新增**：
  - `README.md`: Added top-level GFM `[!IMPORTANT]` Fork Notice (`YuchengWang/cua` — `cua-ycwang` X11 Edition) acknowledging upstream `trycua/cua` and its MIT / component licenses, summarizing X11 virtual desktop customizations with bilingual doc links (`LINUX_X11_VIRTUAL_SCREEN_PLAN*.md`, `LINUX_X11_PERMISSIONS*.md`, `CHANGELOG_YCWANG.md`), and stating security/input risk disclosures, no-plaintext-credentials rule, personal-use-only scope, and AS-IS / user-assumption-of-risk disclaimer.

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
  - Security audits passed across M1–M4 (`0600` xauth/VNC passwords, `127.0.0.1` VNC, clipboard isolation, `screen_locked` guard, `elevate` allowlist).

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
  - M3 security audit passed across `virtual_screen.rs`, `mcp_virtual_screen.rs`, `authorization.rs`, `tool.rs`, and `reap_stale_runtime()` (`0600` xauth/VNC passwords, `127.0.0.1` VNC, no shell injection).

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
- `ycwang-x11-v0.57.0-m5` on `feat/x11-virtual-desktop` (Maintainer: `Yucheng Wang <wfing123@gmail.com>`).
