# Linux X11 系统依赖、权限配置与双版本隔离手册

> **Synced-With-Commit**: `2a15e141e2`（M1 ~ M5 已落地于 `feat/x11-virtual-desktop`）  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **English Original**: [LINUX_X11_PERMISSIONS.md](./LINUX_X11_PERMISSIONS.md)

---

## 1. 系统依赖安装（L2 带外执行）

### 1.1 必需 APT 系统包
在编译 `cua-ycwang` 或启动 X11 虚拟桌面之前，请在独立交互终端中安装无头 X11 运行时、窗口管理器、VNC 旁路监看、剪贴板托管及 X11/AT-SPI 开发包（严禁在 AI 对话或 MCP 中传入 `sudo` 密码）：

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential pkg-config clang cmake \
  xvfb openbox x11-utils xdotool dbus-x11 \
  x11vnc autocutsel \
  libx11-dev libxcomposite-dev libxtst-dev libxfixes-dev \
  libxrandr-dev libxdamage-dev libxkbcommon-dev \
  libatspi2.0-dev libdbus-1-dev libudev-dev
```

- **运行时组件**：`xvfb`（无头 X11 虚拟屏）、`openbox`（轻量 EWMH 窗口管理器）、`x11vnc`（回环只读监看）、`autocutsel`（虚拟屏剪贴板托管）、`xdotool`、`dbus-x11`。
- **编译与扩展开发包**：`libxcomposite-dev`（离屏窗口捕捉）、`libxtst-dev`（XTest 输入注入）、`libxfixes-dev`、`libxrandr-dev`、`libxdamage-dev`、`libxkbcommon-dev`、`libatspi2.0-dev`、`libdbus-1-dev`、`libudev-dev`。

### 1.2 用户态 Rust 工具链（L0 免密）
以普通用户（`ycwang`）安装 `rustup`，`libs/cua-driver/rust/rust-toolchain.toml` 会自动同步 Rust `1.97.1`：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

---

## 2. 手动用户与组权限配置（`/dev/uinput`、Polkit 与重登说明）

### 2.1 `uinput` 组与 udev 规则（`99-cua-uinput.rules`）
为实现 `/dev/uinput` 永久免 `sudo` 注入且不以 `root` 运行 `cua-ycwang`：

1. 创建 `uinput` 组并将当前用户加入 `input`、`uinput` 组：
   ```bash
   sudo groupadd -f uinput
   sudo usermod -aG input,uinput "$USER"
   ```
2. 安装 `/etc/udev/rules.d/99-cua-uinput.rules`（`0644 root:root`）：
   ```text
   KERNEL=="uinput", GROUP="uinput", MODE="0660", OPTIONS+="static_node=uinput"
   ```
3. 重载 udev 规则：
   ```bash
   sudo udevadm control --reload-rules && sudo udevadm trigger /dev/uinput
   ```

### 2.2 重登生效说明与 `XTest` 自动降级
- **必须重新登录**：新增的组权限（`input`、`uinput`）仅在**新的登录会话**中生效（桌面注销重登，或当前终端临时 `newgrp uinput`）。
- **不断流降级**：若检测到 `requires_relogin: true`（尚未重登），虚拟屏（`:99+`）会自动降级使用 `XTest` 注入，不中断当前自动化任务。

### 2.3 Polkit 策略（`L1` / `L2`）与 `cua-elevated-helper`
- `deploy/linux/system/polkit/io.github.yuchengwang.cua.policy` -> `/usr/share/polkit-1/actions/`（仅授权 `/usr/local/libexec/cua-ycwang/cua-elevated-helper`，设置 `<allow_any>no</allow_any>`、`<allow_inactive>no</allow_inactive>`、`<allow_active>auth_admin_keep</allow_active>`）。
- `deploy/linux/system/polkit/50-cua-ycwang-l1.rules` -> `/etc/polkit-1/rules.d/`（将 `L1` 用户态服务检查严格限定为 `subject.user == "ycwang" && subject.local && subject.active`）。
- **防篡改红线**：`deploy/linux/system/` 下文件必须通过 `install -o root -g root` 拷贝安装（严禁软链到用户可写目录），并由 `deploy/linux/scripts/doctor-linux.sh` 校验 SHA-256。

---

## 3. 精细化三级权限模型（L0 / L1 / L2）与 `elevation_required`

### 3.1 权限分级矩阵
| 级别 | 授权模式 | 涵盖操作 | 安全边界 |
| :--- | :--- | :--- | :--- |
| **L0** | 日常全免密（用户 `ycwang`） | `Xvfb`/`openbox`/`dbus-daemon` 启停、SHM/Composite 截图、AT-SPI、`XTest`/已授权 `uinput`、剪贴板、`~/.config/cua-ycwang` | 严禁 `sudo`；`0600` xauth；禁止 `:0.0 <-> :99` 自动同步剪贴板 |
| **L1** | 受控局部特权（Polkit 白名单） | `systemctl --user` 管理 `cua-ycwang.service`、只读诊断（`journalctl --user`、节点核验） | 严禁放行任意 shell 或系统级单元 |
| **L2** | 带外 `pkexec` 弹窗 | `apt-get install`、安装 `/etc/` udev/Polkit/helper、系统级 `systemctl` | 密码绝对不经过 LLM、MCP 参数或 `cua-ycwang` 内存 |

### 3.2 机读 `elevation_required` 契约
- 缺失依赖或系统规则时，`cua-ycwang doctor --json`（`crates/cua-driver/src/doctor.rs`）探查 X11 依赖、`/dev/uinput` 与 `deploy/linux/system/` SHA-256 完整性，并输出 `elevation_required: ElevationRequired`（包含 `status: "elevation_required"`、`action_id`、`elevation_mode` `"pkexec"` / `"tty_manual"`、`commands[]`、`reasons[]`、`requires_relogin`、`verify_command` 与 `resume_hint`）。
- `cua-ycwang elevate --action-id <id> [--json]`（`crates/cua-driver/src/cli.rs` & `main.rs`）调用 `elevation::run_pkexec_allowlisted()` 拉起原生 Polkit 弹窗（仅授权 `cua-elevated-helper`，严禁 `pkexec bash -c`），完成后自动重放 `verify_command` 与 `resume_hint`。

---

## 4. 集中配置真源（`deploy/linux/`）与 X11 安全加固

### 4.1 目录布局与加载优先级
- **单一真源（SSOT）**：`/home/ycwang/work/cua/deploy/linux/user/*` 软链至 `CUA_YCWANG_CONFIG_DIR`（`~/.config/cua-ycwang/`）。
- **优先级（高 → 低）**：单次 MCP 参数 > 环境变量（`CUA_YCWANG_CONFIG_DIR`、`CUA_YCWANG_HOME`、`CUA_X11_DISPLAY`）> `$CUA_YCWANG_CONFIG_DIR/config.json` > `bundle.rs` 命名空间默认值。

### 4.2 X11 与 VNC 加固红线
- 严禁：`xhost +`、`Xvfb -ac`、`x11vnc -nopw`。
- 强制：每屏独立 `mcookie` + `0600` xauth 文件；`x11vnc` 仅监听 `127.0.0.1`，强制 `-passwdfile`（`0600` 一次性密码，销毁虚拟屏时同步删除），默认 `-viewonly`，仅当显式传入 `vnc_interactive=true` 时允许交互。

---

## 5. 双版本隔离（`cua-ycwang` vs `cua-driver`）与 `agy mcp` 切换

### 5.1 隔离路径与命名空间
- 官方 `cua-driver` 保持原位不动：`~/.local/bin/cua-driver`、`~/.cua-driver/`、`~/.cache/cua-driver/`。
- 自维护 `cua-ycwang` 独立运行于 `~/.local/bin/cua-ycwang` -> `~/.cua-ycwang/packages/current/cua-ycwang`（同级放置 `cua-cursor-theme`）、`~/.cua-ycwang/cua-home` 与 `~/.cache/cua-ycwang/cua-ycwang.sock`，并由 `ycwang_env.rs`、`history_runtime.rs` 与 `cursor-overlay/src/motion_defaults.rs` 完成全路径隔离。

### 5.2 通过 `agy mcp` 互斥切换
```bash
# 首次注册（保留官方 cua-driver 条目不动）
agy mcp add \
  --env CUA_DRIVER_RS_HOME=/home/ycwang/.cua-ycwang \
  --env CUA_HOME=/home/ycwang/.cua-ycwang/cua-home \
  cua-ycwang /home/ycwang/.local/bin/cua-ycwang mcp

# 切换至 cua-ycwang
agy mcp disable cua-driver && agy mcp enable cua-ycwang

# 秒级回滚至官方 cua-driver
agy mcp disable cua-ycwang && agy mcp enable cua-driver
```
> 严禁同时启用 `cua-driver` 与 `cua-ycwang`，否则会导致 MCP 工具重名冲突与 `:0.0` 输入/光标竞争。
