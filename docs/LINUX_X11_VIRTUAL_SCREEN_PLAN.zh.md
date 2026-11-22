# Linux X11 虚拟桌面与双版本架构方案（`YuchengWang/cua`）

> **Synced-With-Commit**: `2a15e141e2`（M1 ~ M5 已落地于 `feat/x11-virtual-desktop`）  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **Branch**: `feat/x11-virtual-desktop`  
> **English Original**: [LINUX_X11_VIRTUAL_SCREEN_PLAN.md](./LINUX_X11_VIRTUAL_SCREEN_PLAN.md)

---

## 1. 架构总览与上游 Rebase 原则

### 1.1 Monorepo 与 Cargo Workspace 约束
- `libs/cua-driver/rust/Cargo.toml` 定义了包含 15 个 crate 的 Cargo workspace（`0.57.0`，Rust `1.97.1`），其中 `crates/cua-driver/Cargo.toml` 通过相对路径引用了 `libs/cua/crates/cua-telemetry` 与 `cua-agent-setup`。
- 因此，`YuchengWang/cua` 必须完整 Fork `trycua/cua`：
  - `main` 严格只读镜像 `upstream/main`；
  - `feat/x11-virtual-desktop` 承载所有 X11 虚拟屏、离屏捕捉、命名空间隔离与权限增强改动。

### 1.2 冲突最小化“独立新增模块 + 薄钩子”原则
- **独立新增模块**：
  - `crates/cua-driver-core/src/{ycwang_env.rs,elevation.rs}`
  - `crates/platform-linux/src/x11/{context.rs,virtual_screen.rs,composite_capture.rs,virtual_input.rs,screen_guard.rs}`
  - `crates/platform-linux/src/tools/{mcp_virtual_screen.rs,mcp_clipboard.rs}`
- **上游文件薄钩子（Thin Hook）**：
  - `x11/mod.rs`、`capture.rs`、`input/mod.rs` 保留原有函数签名作为 `pool.primary()` 的薄包装，旁路新增 `*_with_context(ctx: &X11ScreenContext, ...)`。
  - `xauth.rs`、`session_bus.rs`、`desktop.rs` 保留主桌面路径，旁路新增 `resolve_for_display(target)` / `classify_for(target)`。

---

## 2. X11 连接池与多 DISPLAY 路由

### 2.1 `DisplayTarget` 与 `X11ScreenContext`
- 定义于 `platform-linux/src/x11/context.rs`：
  - `DisplayTarget::Primary`（宿主默认桌面，如 `:0.0`）
  - `DisplayTarget::Virtual(String)`（隔离虚拟屏，如 `:99`、`:100`）
- `X11ScreenContext` 持有 `display_id`、`xauth_path`、`dbus_address`、`conn: Arc<RustConnection>`、`screen_num` 与 `shm_session: Mutex<Option<XShmSession>>`。
- `X11ScreenPool`（`RwLock<HashMap<String, Arc<X11ScreenContext>>>`）通过 `RustConnection::connect(Some(display_id))` 配合显式 `XAUTHORITY` 懒加载复用长连接，彻底消除进程级 `DISPLAY` 环境变量竞争。

### 2.2 契约校验与会话路由规则
- `cua-driver-core/src/action_target.rs` 允许 `"primary"` 或匹配 `^:\d+(\.\d+)?$` 的合法 `display_id`（严格拦截注入字符）。
- **Session 绑定 + 单次覆盖**：`start_session(display_id=":99")` 将该会话后续动作默认路由至 `:99`；单次工具调用（`screenshot`、`click`、`type_text`、`get_desktop_state`、`list_windows`、`get_window_state`、`get_screen_size`）仍可显式覆盖 `display_id`。
- 多 Agent 隔离：Agent A 独占 `:99`（如 IBKR TWS）、Agent B 独占 `:100`（如 Chrome）、人类使用 `:0.0` 主桌面，三者零抢焦点、零输入串扰。

---

## 3. 虚拟桌面生命周期管理（`VirtualScreenManager`）

### 3.1 分配、隔离与子进程栈
- 实现于 `platform-linux/src/x11/virtual_screen.rs`：
  - 加锁扫描 `/tmp/.X11-unix/X<n>` 与 `/tmp/.X<n>-lock`（区间 `:99..:199`）原子分配空闲 `display_id`。
  - 生成独立 `mcookie` 与 `0600` 权限的 `xauth` 文件至 `~/.cache/cua-ycwang/xauth/<n>.auth`（严禁 `-ac` 与 `xhost +`）。
  - 启动 `Xvfb :<n> -screen 0 <W>x<H>x24 -auth <xauth_file> +extension COMPOSITE +extension XTEST +extension MIT-SHM -nolisten tcp -s 0 -dpms`。
  - 启动 `openbox --config-file ~/.config/cua-ycwang/openbox/rc.xml`（`focusNew=yes`、禁用动画）及可选独立 `dbus-daemon --session --fork --print-address` + `at-spi-bus-launcher`。
  - 可选旁路监看：`x11vnc -display :<n> -auth <xauth_path> -localhost -rfbport <auto_port> [-viewonly] -forever -shared -passwdfile <vnc_pw_file>`（仅监听 `127.0.0.1`、`0600` 一次性随机密码，默认 `-viewonly`，仅当 `vnc_interactive=true` 时移除 `-viewonly`，严禁 `-nopw`）。

### 3.2 生命周期清理与残留自愈
- 注册 `SessionEndHook`（`cua-driver-core/src/session.rs`），在会话结束、空闲 TTL 到期或 daemon 退出时执行 `SIGTERM -> SIGKILL` 回收子进程树。
- 启动入口执行 `reap_stale_runtime()` 校验 `/proc/<pid>/cmdline`，自动清理死进程残留的 `.pid`/`.sock`、孤儿 `Xvfb`/`openbox` 及当前用户属主的 `/tmp/.X<n>-lock`。

### 3.3 MCP 虚拟屏工具契约
- `create_virtual_screen(width?, height?, dpi?, session?, enable_dbus?, enable_vnc?, vnc_interactive?)`（默认 `1920x1080`）
- `list_virtual_screens()`
- `destroy_virtual_screen(display_id, force?)`
- `launch_in_virtual_screen(display_id, command, args?, env?)`
- `list_windows(display_id?, session?)`：严格按显式 `display_id` > `session` > `Primary` 路由，并在 `_NET_CLIENT_LIST` 之外补充 `QueryTree` `MapState::VIEWABLE` 弹窗枚举（过滤 `<= 1x1` 的 `FocusProxy` 窗口）。

---

## 4. XComposite 离屏截图与核心桌面交互增强

### 4.1 `XComposite` 离屏窗口捕捉
- 实现于 `platform-linux/src/x11/composite_capture.rs` 并接入 `capture.rs` 最前端：
  - 检测 `x11rb::protocol::composite` 版本（>= `0.2`）；
  - 调用 `composite::redirect_window(xid, Redirect::AUTOMATIC)` 与 `composite::name_window_pixmap(xid, pixmap_id)`；
  - 对离屏 `pixmap_id` 执行 `shm_get_image` / `get_image`，完成后调用 `free_pixmap`；
  - 窗口处于 `IsUnmapped` 时平滑降级至 `XShm -> XGetImage -> import`。

### 4.2 五项核心桌面交互补齐
1. **中文 / 非 ASCII 输入**：虚拟屏初始化 `setxkbmap us` 与 `GTK_IM_MODULE=xim`；`type_text` 遇非 ASCII 自动执行“暂存原剪贴板 → 写入 `CLIPBOARD` → `XTest Ctrl+V`（终端 `Ctrl+Shift+V`）→ 恢复原剪贴板”，不可粘贴控件回退 AT-SPI `EditableText::set_text_contents`。
2. **剪贴板托管与跨屏隔离**：每屏启动 `autocutsel -fork` 与 `-selection PRIMARY -fork`；新增 `get_clipboard` / `set_clipboard` / `sync_clipboard`；严禁 `:0.0 <-> :99` 默认自动双向同步。
3. **主屏 DPMS 与锁屏探针**：操作 `:0.0` 前探测 `org.freedesktop.login1.Session.LockedHint` 与 `ScreenSaver.GetActive`；已锁屏返回 `screen_locked` 拒绝操作（严禁尝试解锁），仅未锁屏且熄屏时调用 `DPMSForceLevel(DPMSModeOn)` 唤醒。
4. **Java / TWS `OverrideRedirect` 菜单**：在 `_NET_CLIENT_LIST_STACKING` 之外补充 `XQueryTree(root)` 枚举 `MapState::VIEWABLE` 且 `override_redirect == true` 窗口，注入 `_JAVA_AWT_WM_NONREPARENTING=1`。
5. **文件选择器与 `run_steps` 自恢复**：Chrome/GTK 文件框固化 `Ctrl+L -> clipboard_write -> Ctrl+V -> Return`；`run_steps` 支持 `wait_for_stable_frame`、`on_error`（`retry` / `dismiss_modal_and_retry` / `abort`）与 `expect` 断言。

---

## 5. 特性验证门禁与里程碑拆解

### 5.1 特性验证门禁矩阵
| 特性模块 | 验证命令 | 通过标准 |
| :--- | :--- | :--- |
| 命名空间隔离（`bundle.rs` / `config_file.rs`） | `cargo test -p cua-driver -p cua-driver-core` 与 `cua-ycwang doctor --json` | `~/.cache/cua-ycwang/cua-ycwang.sock` 独立生成；`~/.cua-driver/` 零变更 |
| `XComposite` 离屏截图 | `cargo test -p platform-linux composite` 与遮挡窗口实测 | 遮挡态返回完整目标窗口；`IsUnmapped` 平滑回退且无资源泄漏 |
| `VirtualScreenManager` 生命周期 | `cargo test -p platform-linux virtual_screen` 与 `SIGKILL` 恢复 | `0600` xauth、`127.0.0.1` VNC、销毁或重启后孤儿进程与锁文件归零 |
| `X11ScreenPool` 多屏并发路由 | `cargo test -p cua-driver-core action_target` 与 `:99`/`:100` 压测 | 非法 `display_id` 被拒；宿主 `:0.0` 焦点与光标零漂移 |
| 中文剪贴板与 `OverrideRedirect` | `cargo test -p platform-linux` 与 TWS/Chrome 菜单实测 | 中文完整输入且剪贴板恢复；锁屏返回 `screen_locked` |
| `elevation_required` 与 `pkexec` | `cua-ycwang doctor --json` 与 `./deploy/linux/scripts/doctor-linux.sh` | 标准 `elevation_required` JSON；`root:root` 系统文件 SHA-256 一致 |
| `cua-ycwang` MCP 与上游回归 | `cargo clippy --workspace --all-targets && cargo test` 与 `agy mcp list` | 上游单测 100% 通过；`agy mcp` 单条目互斥且支持秒级回滚 |

### 5.2 里程碑执行顺序（M1 ~ M5）
- **Milestone 1（串行底座 — 已落地并验证）**：`bundle.rs` / `config_file.rs` / `action_target.rs` / `ycwang_env.rs` / `elevation.rs` / `history_runtime.rs` / `motion_defaults.rs`、`deploy/linux/` SSOT 及双语 `docs/` 骨架（已完成实现与安全审计）。
- **Milestone 2（核心引擎 — 已落地并验证）**：`X11ScreenPool`（`context.rs`）、`composite_capture.rs`（`PixmapGuard` + `CompositeCaptureOutcome::UnmappedFallback`）及 `capture.rs` / `x11/mod.rs` / `xauth.rs` / `session_bus.rs` / `desktop.rs` 薄钩子（`cua-driver` 418 项单测通过）。
- **Milestone 3（生命周期与 MCP 暴露 — 已落地并审计通过）**：`VirtualScreenManager`（`virtual_screen.rs`）、`platform-linux/src/tools/mcp_virtual_screen.rs`、`authorization.rs` / `tool.rs`（`RiskClass::R3`）、`get_desktop_state` / `get_screen_size` / `list_windows` 路由及 `reap_stale_runtime()`（安全审计 PASS）。
- **Milestone 4（交互补齐与提权闭环 — 已落地）**：`virtual_input.rs`（`XTest` + 中文剪贴板暂存恢复）、`mcp_clipboard.rs`（`get_clipboard`/`set_clipboard`/`sync_clipboard`）、`screen_guard.rs`（`screen_locked` + DPMS 探针）、`OverrideRedirect` `QueryTree` 枚举、`run_steps`（`wait_for_stable_frame` + `dismiss_modal_and_retry`）、`doctor --json` 与 `elevate --action-id`（全部单测、`schema_consistency_test` 与 `virtual_screen_m3_e2e_xorg` 通过）。
- **Milestone 5（集成、文档门禁与全量回归 — 已落地并验收）**：Release 编译（`cua-driver` + `cursor-theme-cli`）安装至 `~/.cua-ycwang/packages/current/cua-ycwang`、`deploy-user-config.sh` 部署 `~/.config/cua-ycwang/`、`doctor --json` 实测零污染、M2/M3/M4 实机 E2E（`4/4`、`2/2`、`2/2`）与 `batch_tools`（`69/69`）全绿、安全审计全 PASS，且 `check-docs-sync.sh` 校验通过。
