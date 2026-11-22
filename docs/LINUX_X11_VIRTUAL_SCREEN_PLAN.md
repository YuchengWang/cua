# Linux X11 Virtual Screen & Dual-Version Architecture Plan (`YuchengWang/cua`)

> **Synced-With-Commit**: `2a15e141e2` (M1 ~ M5 Landed on `feat/x11-virtual-desktop`)  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **Branch**: `feat/x11-virtual-desktop`  
> **Chinese Mirror**: [LINUX_X11_VIRTUAL_SCREEN_PLAN.zh.md](./LINUX_X11_VIRTUAL_SCREEN_PLAN.zh.md)

---

## 1. Architecture Overview & Upstream Rebase Principles

### 1.1 Monorepo & Cargo Workspace Constraints
- `libs/cua-driver/rust/Cargo.toml` defines a 15-crate Cargo workspace (`0.57.0`, Rust `1.97.1`), where `crates/cua-driver/Cargo.toml` references `libs/cua/crates/cua-telemetry` and `cua-agent-setup` via relative paths.
- Therefore, `YuchengWang/cua` maintains a full fork of `trycua/cua`:
  - `main` strictly mirrors `upstream/main` (read-only).
  - `feat/x11-virtual-desktop` carries all X11 virtual screen, offscreen capture, namespace isolation, and permission enhancements.

### 1.2 Minimal-Conflict "New Module + Thin Hook" Principle
- **New standalone modules**:
  - `crates/cua-driver-core/src/{ycwang_env.rs,elevation.rs}`
  - `crates/platform-linux/src/x11/{context.rs,virtual_screen.rs,composite_capture.rs,virtual_input.rs,screen_guard.rs}`
  - `crates/platform-linux/src/tools/{mcp_virtual_screen.rs,mcp_clipboard.rs}`
- **Thin hooks in upstream files**:
  - `x11/mod.rs`, `capture.rs`, and `input/mod.rs` retain their original function signatures as thin wrappers over `pool.primary()`, while exposing `*_with_context(ctx: &X11ScreenContext, ...)` side-by-side.
  - `xauth.rs`, `session_bus.rs`, and `desktop.rs` retain primary desktop paths and add `resolve_for_display(target)` / `classify_for(target)`.

---

## 2. X11 Screen Pool & Multi-Display Routing

### 2.1 `DisplayTarget` & `X11ScreenContext`
- Defined in `platform-linux/src/x11/context.rs`:
  - `DisplayTarget::Primary` (host desktop, e.g. `:0.0`)
  - `DisplayTarget::Virtual(String)` (isolated virtual screen, e.g. `:99`, `:100`)
- `X11ScreenContext` holds `display_id`, `xauth_path`, `dbus_address`, `conn: Arc<RustConnection>`, `screen_num`, and `shm_session: Mutex<Option<XShmSession>>`.
- `X11ScreenPool` (`RwLock<HashMap<String, Arc<X11ScreenContext>>>`) lazily connects via `RustConnection::connect(Some(display_id))` with explicit `XAUTHORITY`, eliminating process-global `DISPLAY` mutation.

### 2.2 Contract & Session Routing Rules
- `cua-driver-core/src/action_target.rs` allows `display_id` values matching `"primary"` or `^:\d+(\.\d+)?$` (strictly rejecting shell/path injection characters).
- **Session binding + per-call override**: `start_session(display_id=":99")` binds subsequent session actions to `:99`, while individual tool calls (`screenshot`, `click`, `type_text`, `get_desktop_state`, `list_windows`, `get_window_state`, `get_screen_size`) may override `display_id`.
- Multi-agent isolation: Agent A on `:99` (e.g. IBKR TWS), Agent B on `:100` (e.g. Chrome), and human on `:0.0` experience zero focus stealing and zero input cross-talk.

---

## 3. Virtual Screen Lifecycle (`VirtualScreenManager`)

### 3.1 Allocation, Isolation & Subprocess Stack
- Implemented in `platform-linux/src/x11/virtual_screen.rs`:
  - Scans `/tmp/.X11-unix/X<n>` and `/tmp/.X<n>-lock` across `:99..:199` under mutex lock.
  - Generates isolated `mcookie` and `0600` `xauth` file under `~/.cache/cua-ycwang/xauth/<n>.auth` (never `-ac`, never `xhost +`).
  - Launches `Xvfb :<n> -screen 0 <W>x<H>x24 -auth <xauth_file> +extension COMPOSITE +extension XTEST +extension MIT-SHM -nolisten tcp -s 0 -dpms`.
  - Starts `openbox --config-file ~/.config/cua-ycwang/openbox/rc.xml` (`focusNew=yes`, animations disabled) and optional isolated `dbus-daemon --session --fork --print-address` + `at-spi-bus-launcher`.
  - Optional preview bridge: `x11vnc -display :<n> -auth <xauth_path> -localhost -rfbport <auto_port> -viewonly -passwdfile <vnc_pw_file>` (loopback `127.0.0.1` only, `0600` one-time password, never `-nopw`).

### 3.2 Lifecycle Cleanup & Stale Runtime Self-Healing
- Registers `SessionEndHook` (`cua-driver-core/src/session.rs`) for automatic `SIGTERM -> SIGKILL` cleanup on session end, idle TTL expiration, or daemon shutdown.
- `reap_stale_runtime()` inspects `/proc/<pid>/cmdline` on startup, cleaning dead `.pid`/`.sock` files, orphan `Xvfb`/`openbox` processes, and user-owned `/tmp/.X<n>-lock` files.

### 3.3 MCP Virtual Screen Tools
- `create_virtual_screen(width?, height?, dpi?, session?, enable_dbus?, enable_vnc?)`
- `list_virtual_screens()`
- `destroy_virtual_screen(display_id, force?)`
- `launch_in_virtual_screen(display_id, command, args?, env?)`

---

## 4. XComposite Offscreen Capture & Core Desktop Interactions

### 4.1 `XComposite` Offscreen Window Capture
- Implemented in `platform-linux/src/x11/composite_capture.rs` and wired ahead of `XShm` in `capture.rs`:
  - Checks `x11rb::protocol::composite` version (>= `0.2`).
  - Calls `composite::redirect_window(xid, Redirect::AUTOMATIC)` and `composite::name_window_pixmap(xid, pixmap_id)`.
  - Reads backing pixmap via `shm_get_image` / `get_image`, then calls `free_pixmap`.
  - Falls back to `XShm -> XGetImage -> import` when window state is `IsUnmapped`.

### 4.2 Five Core Desktop Interaction Enhancements
1. **Non-ASCII / Chinese Input**: Virtual screens initialize `setxkbmap us` and `GTK_IM_MODULE=xim`; `type_text` handles non-ASCII via save clipboard -> write `CLIPBOARD` -> `XTest Ctrl+V` (or `Ctrl+Shift+V` in terminals) -> restore clipboard, with AT-SPI `EditableText::set_text_contents` fallback.
2. **Clipboard Hosting & Cross-Display Isolation**: Launches `autocutsel -fork` and `autocutsel -selection PRIMARY -fork` per virtual screen; adds `get_clipboard` / `set_clipboard` / `sync_clipboard`; forbids implicit `:0.0 <-> :99` auto-sync.
3. **Primary Display DPMS & Lock-Screen Probe**: Probes `org.freedesktop.login1.Session.LockedHint` and `ScreenSaver.GetActive` before `:0.0` actions; returns `screen_locked` if locked (never attempts unlock), wakes DPMS via `DPMSForceLevel(DPMSModeOn)` only when unlocked.
4. **Java / TWS `OverrideRedirect` Menus**: Supplements `_NET_CLIENT_LIST_STACKING` with `XQueryTree(root)` for `MapState::VIEWABLE` + `override_redirect == true` windows; injects `_JAVA_AWT_WM_NONREPARENTING=1`.
5. **File Chooser & `run_steps` Recovery**: Standardizes `Ctrl+L -> clipboard_write -> Ctrl+V -> Return` for Chrome/GTK dialogs; adds `wait_for_stable_frame`, `on_error` (`retry` / `dismiss_modal_and_retry` / `abort`), and `expect` assertions.

---

## 5. Feature Verification Gate & Milestones

### 5.1 Feature Verification Gate Matrix
| Feature | Verification Command | Pass Criteria |
| :--- | :--- | :--- |
| Namespace Isolation (`bundle.rs` / `config_file.rs`) | `cargo test -p cua-driver -p cua-driver-core` & `cua-ycwang doctor --json` | `~/.cache/cua-ycwang/cua-ycwang.sock` isolated; `~/.cua-driver/` untouched |
| `XComposite` Offscreen Capture | `cargo test -p platform-linux composite` & occluded-window capture | Complete window image when occluded; clean fallback on `IsUnmapped` |
| `VirtualScreenManager` Lifecycle | `cargo test -p platform-linux virtual_screen` & `SIGKILL` recovery | `0600` xauth, `127.0.0.1` VNC, zero orphan processes/locks after cleanup |
| `X11ScreenPool` Concurrent Routing | `cargo test -p cua-driver-core action_target` & `:99`/`:100` stress | Invalid `display_id` rejected; `:0.0` focus/cursor zero drift |
| Chinese Clipboard & `OverrideRedirect` | `cargo test -p platform-linux` & TWS/Chrome menu E2E | Chinese text intact, clipboard restored, lock screen returns `screen_locked` |
| `elevation_required` & `pkexec` | `cua-ycwang doctor --json` & `./deploy/linux/scripts/doctor-linux.sh` | Structured `elevation_required` JSON; `root:root` copies verified by SHA-256 |
| `cua-ycwang` MCP & Upstream Regression | `cargo clippy --workspace --all-targets && cargo test` & `agy mcp list` | 100% upstream unit tests pass; single active MCP entry; instant rollback |

### 5.2 Milestone Execution Order (M1 ~ M5)
- **Milestone 1 (Serial Base — Landed & Verified)**: `bundle.rs` / `config_file.rs` / `action_target.rs` / `ycwang_env.rs` / `elevation.rs` / `history_runtime.rs` / `motion_defaults.rs`, `deploy/linux/` SSOT, and bilingual `docs/` skeleton (implemented & security audited).
- **Milestone 2 (Core Engine — Landed & Verified)**: `X11ScreenPool` (`context.rs`), `composite_capture.rs` (`PixmapGuard` + `CompositeCaptureOutcome::UnmappedFallback`), and thin hooks in `capture.rs` / `x11/mod.rs` / `xauth.rs` / `session_bus.rs` / `desktop.rs` (`cua-driver` 418 tests passed).
- **Milestone 3 (Lifecycle & MCP Exposure — Landed & Audited)**: `VirtualScreenManager` (`virtual_screen.rs`), `platform-linux/src/tools/mcp_virtual_screen.rs`, `authorization.rs` / `tool.rs` (`RiskClass::R3`), `get_desktop_state` / `get_screen_size` / `list_windows` routing, and `reap_stale_runtime()` (security audit PASS).
- **Milestone 4 (Interaction Enhancements & Elevation Loop — Landed)**: `virtual_input.rs` (`XTest` + Chinese clipboard save/restore), `mcp_clipboard.rs` (`get_clipboard`/`set_clipboard`/`sync_clipboard`), `screen_guard.rs` (`screen_locked` + DPMS probe), `OverrideRedirect` `QueryTree` enumeration, `run_steps` (`wait_for_stable_frame` + `dismiss_modal_and_retry`), `doctor --json`, and `elevate --action-id` (all unit + `schema_consistency_test` + `virtual_screen_m3_e2e_xorg` passed).
- **Milestone 5 (Integration, Docs Gate & Final Regression — Landed & Verified)**: Release build (`cua-driver` + `cursor-theme-cli`) installed to `~/.cua-ycwang/packages/current/cua-ycwang`, `~/.config/cua-ycwang/` deployed via `deploy-user-config.sh`, `doctor --json` verified with zero `~/.cua-driver/` pollution, M2/M3/M4 E2E suites (`4/4`, `2/2`, `2/2`) + `batch_tools` (`69/69`) passed, security audits PASS, and `check-docs-sync.sh` passed.
