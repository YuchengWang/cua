# Linux X11 Versioned App Recipe & Layered Introspection Plan (`YuchengWang/cua`)

> **Synced-With-Commit**: `3e27a062ab` (M1–M5 & R1–R3 Landed and Verified on `feat/x11-virtual-desktop`)  
> **Upstream-Base**: `cua-driver-rs-v0.57.0` / `upstream/main`  
> **Branch**: `feat/x11-virtual-desktop`  
> **Chinese Mirror**: [LINUX_X11_RECIPE_AND_REVERSE_PLAN.zh.md](./LINUX_X11_RECIPE_AND_REVERSE_PLAN.zh.md)

---

## 1. Architecture Convergence & Core Principles

### 1.1 No Monolithic Reverse-Engine Coupling
- Heavy reverse-engineering engines (Ghidra, JADX, IDA, Frida) **must not** be compiled or embedded into the `cua-ycwang` Rust binary.
- Instead, `cua-ycwang` provides **bounded local runtime introspection + versioned FSM recipe execution**, while optional external reverse-engineering MCPs (`jadx-ai-mcp`, `r2mcp`, `GhidraMCP`) remain decoupled at the Coordinator layer.

### 1.2 Three Convergence Decisions
1. **Chrome Exemption**: Web/Chrome automation is fully covered by `chrome_devtools` MCP and `cua-ycwang` `browser_*` primitives (`browser_prepare` with `existing_profile` or `isolated_*`, `get_browser_state`, etc.). Chrome/Edge/Brave web flows are **exempt from reverse engineering**.
2. **Zero/Low-Token Deterministic Replay**: Separate offline cold-start discovery/compilation (`inspect_app_flow` + `generate_app_recipe` / `start_recording`) from online deterministic execution (`run_app_recipe` -> `run_steps` / `run_script`).
3. **Out-of-Band Security & HITL Boundaries**: Never pass credentials, 2FA/OTP, or `sudo` passwords through LLM prompts, logs, or screenshots; pause immediately on CAPTCHA / `"Verify you are human"` gates (`human_verification_required`).

---

## 2. R1: Strong-Versioned `AppRecipe` Foundation & `VersionGate`

### 2.1 Immutable File Naming & Storage
- Implemented in `crates/cua-driver-core/src/app_recipe.rs` (exported via `lib.rs`).
- Storage directory: `$CUA_YCWANG_CONFIG_DIR/app_recipes/` (default `~/.config/cua-ycwang/app_recipes/`).
- Filename contract: `<app_id>_v<version>_<fp8>.json` (e.g., `ibkr_tws_v10.30.1_a1b2c3d4.json`), where `<fp8>` is the first 8 hex characters of `fingerprint_sha256` (from main binary / main JAR / `package.json`).
- **Immutability rule**: Recipes for different versions or builds are strictly isolated and **never overwrite** prior versions.

### 2.2 `AppRecipe` Schema & `VersionGate`
- Core fields: `schema_version`, `app_id`, `app_version`, `version_source` (`dpkg` | `install4j` | `package_json` | `pe_or_elf`), `fingerprint_sha256`, `generated_at`, `recipe_revision`, `tech_stack`, `atspi_blind`, `recommended_interaction` (`atspi_semantic` | `visual_grounding_plus_hotkeys` | `cdp_browser`), `launch_isolation_hints`, `fingerprint` (`wm_class`, `tech_stack`, `recommended_env`), `introspection_strategy`, `verified_shortcuts`, `menu_topology`, `relative_anchors`, `modal_handlers`, `state_machine` (`states` with `auth_gate`/`ready_assertion`, `transitions` with `post_assertions`/`timeout_ms`).
- **`VersionGate::verify()`**: Probes live `app_version` and `<fp8>` before loading or running any recipe. On mismatch, blocks old recipe execution with structured `version_mismatch` error and recommends regenerating `<app_id>_v<new_ver>_<new_fp8>.json` inside an isolated virtual screen.

---

## 3. R2: Layered Real-Time App Flow Inspector (`inspect_app_flow`)

### 3.1 Tiered Introspection & Fingerprinting
- Implemented in `crates/platform-linux/src/app_inspector.rs` (wired via `mcp_app_recipe.rs`).
- **Tier 1 (Zero-Intrusion Live Layer)**:
  - X11 window properties (`WM_CLASS`, `_NET_WM_PID`, `/proc/<pid>/exe`, `/proc/<pid>/cmdline`).
  - AT-SPI2 full control/menu tree snapshot (role, name, automation ID, bounding box); when a running process exposes `0` interactive nodes, reports `atspi_blind: true`, `recommended_interaction: "visual_grounding_plus_hotkeys"`, `remediation_hints`, and `visual_hotspots` (6x4 grid edge-contrast normalized `[rel_x, rel_y, rel_w, rel_h]` hotspots mapped into `AppRecipe.relative_anchors`).
  - Electron detection: inspects `resources/app.asar` / `package.json` (`contributes.commands`, `contributes.menus`, `contributes.keybindings`) and user `keybindings.json`.
- **Tier 2 (Runtime & Bytecode Manifest Layer)**:
  - Java (`install4j` / Swing): locates `.install4j/` version metadata, JAR `META-INF/MANIFEST.MF`, and lightweight bytecode/shortcut/window-manifest extraction without launching heavy GUI decompilers.
  - `.NET` / Avalonia: probes assembly metadata and AT-SPI2 `AutomationPeer` tree depth.
- **Chrome Fast-Exemption**: Returns `channel: "browser_exempt"` when targeting Chrome/Chromium, routing callers directly to `chrome_devtools` MCP or `cua-ycwang` `browser_*`.

---

## 4. R3: Deterministic FSM Replay, Compilation & Out-of-Band Gates

### 4.1 `generate_app_recipe` & `run_app_recipe`
- **`generate_app_recipe`**: Compiles `inspect_app_flow` output or `start_recording` / `stop_recording` traces into validated `<app_id>_v<version>_<fp8>.json`, attaching `VersionGate` metadata and `modal_handlers`.
- **`run_app_recipe`**:
  1. Executes `VersionGate` check;
  2. Reads from in-memory hot cache (`RwLock<HashMap<String, Arc<AppRecipe>>>`);
  3. Compiles transitions into `run_steps` / `run_script` using `MIT-SHM` ROI pixel diffing, AT-SPI2 queries, and X11 title regex assertions (`Fast-Path` zero-LLM execution, falling back to `Slow-Path` single-step diagnosis only on unknown modal/timeout).

### 4.2 Out-of-Band `auth_gate` & `human_verification_required`
- **`auth_gate`**: When reaching a login/2FA/sudo state, triggers local out-of-band prompt (`zenity --password` / GTK4) or OS Keyring (`secret-tool` / `libsecret`), injects via `XTest` / AT-SPI2 with memory zeroing, and returns only `{"status": "auth_step_completed"}` (zero plaintext in LLM context).
- **CAPTCHA Redline**: Any detected CAPTCHA / reCAPTCHA / hCaptcha / Cloudflare Turnstile / `"Verify you are human"` gate immediately halts execution and returns `{"status": "human_verification_required"}` for manual user completion.

---

## 5. R1–R3 Development Contracts & Verification Gate

### 5.1 R1–R3 Acceptance Matrix
| Milestone | Core Deliverables | Verification Command | Pass Criteria |
| :--- | :--- | :--- | :--- |
| **R1** | `cua-driver-core/src/app_recipe.rs`, `VersionGate`, `AppRecipeCache`, `<app_id>_v<version>_<fp8>.json` | `cargo test -p cua-driver-core app_recipe` | **PASS** (3/3): Schema roundtrip, path sanitization, `VersionGate` `version_mismatch` block |
| **R2** | `platform-linux/src/app_inspector.rs`, `inspect_app_flow` MCP tool | `cargo test -p platform-linux app_inspector` & live MCP probe (TWS / v2rayN / VS Code / Chrome) | **PASS** (4/4 + live): TWS `10.52.1d`, v2rayN `7.25.1`, VS Code `1.146.0`, Chrome `browser_exempt` |
| **R3** | `mcp_app_recipe.rs` (`generate_app_recipe`, `run_app_recipe`), `auth_gate`, CAPTCHA halt | `cargo test -p cua-driver --test schema_consistency_test`, `cargo clippy`, & live MCP E2E | **PASS** (4/4 + live): Hot-cache replay, `zeroize` `auth_gate`, CAPTCHA `human_verification_required`, security audit PASS |

### 5.2 Local-Only Git Discipline
- All R1–R3 development and verification commits stay local on `feat/x11-virtual-desktop` (`/home/ycwang/work/cua`); **do not run `git push`** during this phase.
- Every milestone commit must pass `cargo clippy -- -D warnings`, `cargo test`, and `./deploy/linux/scripts/check-docs-sync.sh`.
