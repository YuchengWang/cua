# Linux X11 System Dependencies, Permissions & Dual-Version Isolation Guide

> **Synced-With-Commit**: `2a15e141e2` (M1 ~ M5 Landed on `feat/x11-virtual-desktop`)  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **Chinese Mirror**: [LINUX_X11_PERMISSIONS.zh.md](./LINUX_X11_PERMISSIONS.zh.md)

---

## 1. System Dependencies Installation (L2 Out-of-Band)

### 1.1 Required APT Packages
Before compiling `cua-ycwang` or launching X11 virtual screens, install the headless X11 runtime, window manager, VNC preview bridge, clipboard daemon, and X11/AT-SPI development headers in an interactive terminal (never pass `sudo` passwords to AI chat or MCP):

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential pkg-config clang cmake \
  xvfb openbox x11-utils xdotool dbus-x11 \
  x11vnc autocutsel \
  libx11-dev libxcomposite-dev libxtst-dev libxfixes-dev \
  libxrandr-dev libxdamage-dev libxkbcommon-dev \
  libatspi2.0-dev libdbus-1-dev libudev-dev
```

- **Runtime utilities**: `xvfb` (headless X11 server), `openbox` (lightweight EWMH WM), `x11vnc` (loopback view-only preview), `autocutsel` (virtual display clipboard holder), `xdotool`, `dbus-x11`.
- **Build & extension headers**: `libxcomposite-dev` (offscreen capture), `libxtst-dev` (XTest input), `libxfixes-dev`, `libxrandr-dev`, `libxdamage-dev`, `libxkbcommon-dev`, `libatspi2.0-dev`, `libdbus-1-dev`, `libudev-dev`.

### 1.2 User-Space Rust Toolchain (L0)
Install `rustup` as the regular user (`ycwang`); `libs/cua-driver/rust/rust-toolchain.toml` automatically selects Rust `1.97.1`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

---

## 2. Manual User & Group Permission Setup (`/dev/uinput`, Polkit & Relogin)

### 2.1 `uinput` Group & udev Rule (`99-cua-uinput.rules`)
To allow passwordless `/dev/uinput` input injection without running `cua-ycwang` as `root`:

1. Create the `uinput` group and add your user:
   ```bash
   sudo groupadd -f uinput
   sudo usermod -aG input,uinput "$USER"
   ```
2. Install `/etc/udev/rules.d/99-cua-uinput.rules` (`0644 root:root`):
   ```text
   KERNEL=="uinput", GROUP="uinput", MODE="0660", OPTIONS+="static_node=uinput"
   ```
3. Reload udev rules:
   ```bash
   sudo udevadm control --reload-rules && sudo udevadm trigger /dev/uinput
   ```

### 2.2 Relogin Requirement & `XTest` Fallback
- **Relogin required**: Group membership changes (`input`, `uinput`) take effect only after a **new login session** (desktop logout/login or `newgrp uinput` in current shell).
- **Zero-interruption fallback**: If `requires_relogin: true` is detected before relogin, virtual screens (`:99+`) automatically fall back to `XTest` injection so automation continues uninterrupted.

### 2.3 Polkit Policy (`L1` / `L2`) & `cua-elevated-helper`
- `deploy/linux/system/polkit/io.github.yuchengwang.cua.policy` -> `/usr/share/polkit-1/actions/` (authorizes only `/usr/local/libexec/cua-ycwang/cua-elevated-helper` with `<allow_any>no</allow_any>`, `<allow_inactive>no</allow_inactive>`, `<allow_active>auth_admin_keep</allow_active>`).
- `deploy/linux/system/polkit/50-cua-ycwang-l1.rules` -> `/etc/polkit-1/rules.d/` (restricts `L1` user-unit checks to `subject.user == "ycwang" && subject.local && subject.active`).
- **Anti-tamper rule**: Files under `deploy/linux/system/` must be **copied** as `root:root` via `install -o root -g root` (never symlinked to user-writable directories) and verified via SHA-256 in `deploy/linux/scripts/doctor-linux.sh`.

---

## 3. Three-Tier Privilege Model (L0 / L1 / L2) & `elevation_required`

### 3.1 Privilege Matrix
| Tier | Authorization | Scope | Security Boundary |
| :--- | :--- | :--- | :--- |
| **L0** | Passwordless (user `ycwang`) | `Xvfb`/`openbox`/`dbus-daemon` lifecycle, SHM/Composite capture, AT-SPI, `XTest`/authorized `uinput`, clipboard, `~/.config/cua-ycwang` | Never `sudo`; `0600` xauth; no auto clipboard sync `:0.0 <-> :99` |
| **L1** | Scoped Polkit rule | `systemctl --user` for `cua-ycwang.service`, read-only diagnostics (`journalctl --user`, node checks) | No arbitrary shell or system-wide unit bypass |
| **L2** | Out-of-band `pkexec` prompt | `apt-get install`, `/etc/` udev/Polkit/helper installation, system `systemctl` | Password never passes through LLM, MCP args, or `cua-ycwang` memory |

### 3.2 Machine-Readable `elevation_required` Contract
- When dependencies or system rules are missing, `cua-ycwang doctor --json` (`crates/cua-driver/src/doctor.rs`) probes X11 dependencies, `/dev/uinput`, and `deploy/linux/system/` SHA-256 integrity, returning `elevation_required: ElevationRequired` (`status: "elevation_required"`, `action_id`, `elevation_mode` `"pkexec"` / `"tty_manual"`, `commands[]`, `reasons[]`, `requires_relogin`, `verify_command`, `resume_hint`).
- `cua-ycwang elevate --action-id <id> [--json]` (`crates/cua-driver/src/cli.rs` & `main.rs`) invokes `elevation::run_pkexec_allowlisted()` to trigger the native Polkit dialog (`pkexec` on `cua-elevated-helper`, never `pkexec bash -c`) and replays `verify_command` + `resume_hint`.

---

## 4. Configuration SSOT (`deploy/linux/`) & X11 Hardening

### 4.1 Directory Layout & Precedence
- **SSOT**: `/home/ycwang/work/cua/deploy/linux/user/*` symlinked to `CUA_YCWANG_CONFIG_DIR` (`~/.config/cua-ycwang/`).
- **Precedence (High -> Low)**: per-call MCP args > env vars (`CUA_YCWANG_CONFIG_DIR`, `CUA_YCWANG_HOME`, `CUA_X11_DISPLAY`) > `$CUA_YCWANG_CONFIG_DIR/config.json` > `bundle.rs` namespace defaults.

### 4.2 X11 & VNC Hardening Redlines
- Forbidden: `xhost +`, `Xvfb -ac`, `x11vnc -nopw`.
- Required: per-display `mcookie` + `0600` xauth file; `x11vnc` bound strictly to `127.0.0.1` with `-viewonly -passwdfile` (`0600` ephemeral password deleted on destroy).

---

## 5. Dual-Version Isolation (`cua-ycwang` vs `cua-driver`) & `agy mcp`

### 5.1 Isolated Paths & Namespace
- Official `cua-driver` remains untouched at `~/.local/bin/cua-driver`, `~/.cua-driver/`, and `~/.cache/cua-driver/`.
- Self-maintained `cua-ycwang` uses `~/.local/bin/cua-ycwang` -> `~/.cua-ycwang/packages/current/cua-ycwang` (with sibling `cua-cursor-theme`), `~/.cua-ycwang/cua-home`, and `~/.cache/cua-ycwang/cua-ycwang.sock`, with `ycwang_env.rs`, `history_runtime.rs`, and `cursor-overlay/src/motion_defaults.rs` isolating all state and config paths.

### 5.2 Mutual-Exclusion Switching via `agy mcp`
```bash
# Register once (keeping official cua-driver intact)
agy mcp add \
  --env CUA_DRIVER_RS_HOME=/home/ycwang/.cua-ycwang \
  --env CUA_HOME=/home/ycwang/.cua-ycwang/cua-home \
  cua-ycwang /home/ycwang/.local/bin/cua-ycwang mcp

# Switch to cua-ycwang
agy mcp disable cua-driver && agy mcp enable cua-ycwang

# Instant rollback to official cua-driver
agy mcp disable cua-ycwang && agy mcp enable cua-driver
```
> Never enable `cua-driver` and `cua-ycwang` simultaneously; doing so causes MCP tool name collisions and `:0.0` input/overlay races.
