# Linux X11 强版本化应用配方与分层实时解析方案（`YuchengWang/cua`）

> **Synced-With-Commit**: `3e27a062ab`（M1–M5 与 R1–R3 已落地并验收于 `feat/x11-virtual-desktop`）  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **Branch**: `feat/x11-virtual-desktop`  
> **English Original**: [LINUX_X11_RECIPE_AND_REVERSE_PLAN.md](./LINUX_X11_RECIPE_AND_REVERSE_PLAN.md)

---

## 1. 架构收敛与核心原则

### 1.1 拒绝重型逆向引擎单体耦合
- **严禁**将 Ghidra、JADX、IDA 或 Frida 引擎直接编译或打包进 `cua-ycwang` Rust 二进制中。
- `cua-ycwang` 专注于**有界本地运行时内省 + 强版本化状态机配方执行**；重型外部逆向 MCP（`jadx-ai-mcp`、`r2mcp`、`GhidraMCP`）保持在 Coordinator 层按需松耦合协同。

### 1.2 三项关键工程收敛
1. **Chrome 豁免收敛**：网页/Chrome 交互已由 `chrome_devtools` MCP 与 `cua-ycwang` `browser_*` 原语（`browser_prepare` 支持 `existing_profile` 或 `isolated_*`、`get_browser_state` 等）100% 覆盖，Chrome/Edge/Brave 常规网页流程**豁免逆向工程**。
2. **零/极低 Token 确定性回放**：将离线冷启动探测编译（`inspect_app_flow` + `generate_app_recipe` / `start_recording`）与在线确定性回放（`run_app_recipe` -> `run_steps` / `run_script`）彻底解耦。
3. **带外安全与人机交互红线**：凭据、2FA/OTP 与 `sudo` 密码绝对不进入 LLM 上下文、日志或截图；遇到 CAPTCHA / `"Verify you are human"` 门控立即暂停并返回 `human_verification_required`。

---

## 2. R1：强版本化 `AppRecipe` 底座与 `VersionGate`

### 2.1 不可变文件命名与存储
- 实现于 `crates/cua-driver-core/src/app_recipe.rs`（经 `lib.rs` 导出）。
- 存储目录：`$CUA_YCWANG_CONFIG_DIR/app_recipes/`（默认 `~/.config/cua-ycwang/app_recipes/`）。
- 文件命名契约：`<app_id>_v<version>_<fp8>.json`（如 `ibkr_tws_v10.30.1_a1b2c3d4.json`），其中 `<fp8>` 为主二进制 / 主 JAR / `package.json` 的 `fingerprint_sha256` 前 8 位十六进制字符。
- **不可变原则**：不同版本、不同发行构建的配方严格隔离，**绝不覆盖历史旧版配方**。

### 2.2 `AppRecipe` Schema 与 `VersionGate`
- 核心字段：`schema_version`、`app_id`、`app_version`、`version_source`（`dpkg` | `install4j` | `package_json` | `pe_or_elf`）、`fingerprint_sha256`、`generated_at`、`recipe_revision`、`fingerprint`（`wm_class`、`tech_stack`、`recommended_env`）、`introspection_strategy`、`verified_shortcuts`、`menu_topology`、`relative_anchors`、`modal_handlers`、`state_machine`（含 `auth_gate`/`ready_assertion` 的 `states` 与含 `post_assertions`/`timeout_ms` 的 `transitions`）。
- **`VersionGate::verify()`**：加载或运行任何配方前实时探测目标应用的 `app_version` 与 `<fp8>`；任一不匹配立即阻断旧配方执行，返回结构化 `version_mismatch` 错误并引导在隔离虚拟屏重建 `<app_id>_v<new_ver>_<new_fp8>.json`。

---

## 3. R2：分层本地实时应用流程解析器（`inspect_app_flow`）

### 3.1 分层内省与指纹探测
- 实现于 `crates/platform-linux/src/app_inspector.rs`（经 `mcp_app_recipe.rs` 接入）。
- **Tier 1（零侵入实时层）**：
  - X11 窗口属性采集（`WM_CLASS`、`_NET_WM_PID`、`/proc/<pid>/exe`、`/proc/<pid>/cmdline`）。
  - AT-SPI2 全量控件/菜单树快照（Role、Name、AutomationId、边界坐标）。
  - Electron 探测：解析 `resources/app.asar` / `package.json`（`contributes.commands`、`contributes.menus`、`contributes.keybindings`）及用户 `keybindings.json`。
- **Tier 2（语言运行时与清单层）**：
  - Java（`install4j` / Swing）：定位 `.install4j/` 版本元数据、JAR `META-INF/MANIFEST.MF` 与轻量字节码/快捷键/窗口清单提取，无需启动重型反编译界面。
  - `.NET` / Avalonia：探测程序集元数据与 AT-SPI2 `AutomationPeer` 树深度。
- **Chrome 快速豁免**：识别到 Chrome/Chromium 目标时直接返回 `channel: "browser_exempt"`，引导路由至 `chrome_devtools` MCP 或 `cua-ycwang` `browser_*`。

---

## 4. R3：确定性状态机回放、编译与带外安全门控

### 4.1 `generate_app_recipe` 与 `run_app_recipe`
- **`generate_app_recipe`**：将 `inspect_app_flow` 探测结果或 `start_recording` / `stop_recording` 录制轨迹编译为强版本化的 `<app_id>_v<version>_<fp8>.json`，自动注入 `VersionGate` 元数据与 `modal_handlers`。
- **`run_app_recipe`**：
  1. 执行 `VersionGate` 校验；
  2. 命中进程内内存热缓存（`RwLock<HashMap<String, Arc<AppRecipe>>>`）；
  3. 将状态转移编译为 `run_steps` / `run_script`，利用 `MIT-SHM` ROI 区域像素差分、AT-SPI2 查询与 X11 窗口标题正则断言完成 `Fast-Path` 零 LLM 极速执行（仅在未知弹窗或断言超时时触发 `Slow-Path` 单次诊断）。

### 4.2 带外 `auth_gate` 与 `human_verification_required`
- **`auth_gate`**：状态机进入登录/2FA/`sudo` 门控时，拉起本地带外安全弹窗（`zenity --password` / GTK4）或读取 OS Keyring（`secret-tool` / `libsecret`），通过 `XTest` / AT-SPI2 瞬时直注并擦除内存，仅向 LLM 返回 `{"status": "auth_step_completed"}`（零明文进上下文）。
- **CAPTCHA 不可逾越红线**：一旦检测到 CAPTCHA / reCAPTCHA / hCaptcha / Cloudflare Turnstile / `"Verify you are human"` 门控，立即暂停流程并返回 `{"status": "human_verification_required"}` 交由人类在可见界面亲自完成。

---

## 5. R1–R3 开发契约与验收门禁

### 5.1 R1–R3 验收矩阵
| 里程碑 | 核心交付物 | 验证命令 | 通过标准 |
| :--- | :--- | :--- | :--- |
| **R1** | `cua-driver-core/src/app_recipe.rs`、`VersionGate`、`AppRecipeCache`、`<app_id>_v<version>_<fp8>.json` | `cargo test -p cua-driver-core app_recipe` | **PASS**（3/3）：Schema 序列化、路径防穿越、`VersionGate` `version_mismatch` 阻断 |
| **R2** | `platform-linux/src/app_inspector.rs`、`inspect_app_flow` MCP 工具 | `cargo test -p platform-linux app_inspector` 与实机 MCP 探测（TWS / v2rayN / VS Code / Chrome） | **PASS**（4/4 + 实机）：TWS `10.52.1d`、v2rayN `7.25.1`、VS Code `1.146.0`、Chrome `browser_exempt` |
| **R3** | `mcp_app_recipe.rs`（`generate_app_recipe`、`run_app_recipe`）、`auth_gate`、CAPTCHA 暂停 | `cargo test -p cua-driver --test schema_consistency_test`、`cargo clippy` 与实机 MCP E2E | **PASS**（4/4 + 实机）：热缓存回放、`zeroize` `auth_gate`、CAPTCHA `human_verification_required`、安全审计 PASS |

### 5.2 本地开发与提交纪律
- R1–R3 阶段所有开发与验证提交均保留在本地 `/home/ycwang/work/cua`（`feat/x11-virtual-desktop`），**严禁执行 `git push`**。
- 每个里程碑提交前必须通过 `cargo clippy -- -D warnings`、`cargo test` 与 `./deploy/linux/scripts/check-docs-sync.sh`。
