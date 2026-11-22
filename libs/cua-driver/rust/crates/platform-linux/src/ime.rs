// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! 轻量级输入法状态守卫（RAII）：在自动键入前将活跃中文输入法临时切回英文，
//! 并在作用域结束（Drop）时自动恢复原输入法状态。
//!
//! 任何检测或切换子命令失败、超时或未安装时均静默降级，绝不阻塞或打断主输入流程。

use std::cell::Cell;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const IME_CMD_TIMEOUT: Duration = Duration::from_millis(400);
const IME_POLL_INTERVAL: Duration = Duration::from_millis(5);
const IBUS_ENGLISH_ENGINE: &str = "xkb:us::eng";

thread_local! {
    /// 当前线程的 ImeGuard 嵌套深度，防止外层 flow 与内层键入函数重复探测或提前恢复。
    static IME_GUARD_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// 退出时需要执行的输入法恢复动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreAction {
    /// 无需恢复（已是英文状态、未检测到 IME 或处于嵌套守卫内）。
    None,
    /// 通过 `fcitx5-remote -o` 恢复 fcitx5 激活状态。
    Fcitx5Activate,
    /// 通过 `ibus engine <prev>` 恢复原 IBus 引擎。
    IbusEngine(String),
}

/// 抽象外部命令执行结果，便于单元测试注入 mock。
pub(crate) trait ImeCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
}

struct SystemImeRunner;

impl ImeCommandRunner for SystemImeRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        run_command_with_timeout(program, args, IME_CMD_TIMEOUT)
    }
}

/// 带短超时的子进程执行；超时、退出码非零或启动失败均返回 `None`。
fn run_command_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut stdout = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                return Some(stdout);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(IME_POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// 解析 `fcitx5-remote` 输出：`"2"` 表示当前已激活（中文等），返回 `true`。
pub(crate) fn parse_fcitx5_is_active(stdout: &str) -> bool {
    stdout.trim() == "2"
}

/// 解析 `ibus engine` 输出：非空且不以 `xkb:` 开头时返回需要恢复的原引擎名。
pub(crate) fn parse_ibus_engine_to_restore(stdout: &str) -> Option<String> {
    let engine = stdout.trim();
    if engine.is_empty() || engine.starts_with("xkb:") {
        return None;
    }
    Some(engine.to_owned())
}

/// RAII 输入法守卫：在获取时自动切回英文，Drop 时自动恢复原状态。
pub struct ImeGuard {
    restore: RestoreAction,
    counted_in_tls: bool,
    restore_fn: fn(&RestoreAction),
}

impl ImeGuard {
    /// 获取输入法守卫：
    /// 1. 若当前线程已持有外层 `ImeGuard`，直接返回空操作守卫；
    /// 2. 优先探测 `fcitx5-remote`，若为 `"2"` 则切至英文（`fcitx5-remote -c`）；
    /// 3. 否则探测 `ibus engine`，若非 `xkb:` 引擎则切至 `xkb:us::eng`。
    pub fn acquire() -> Self {
        let already_guarded = IME_GUARD_DEPTH.with(|depth| {
            let cur = depth.get();
            depth.set(cur.saturating_add(1));
            cur > 0
        });

        if already_guarded {
            return Self {
                restore: RestoreAction::None,
                counted_in_tls: true,
                restore_fn: apply_system_restore,
            };
        }

        let runner = SystemImeRunner;
        let restore = probe_and_switch_to_english(&runner);
        Self {
            restore,
            counted_in_tls: true,
            restore_fn: apply_system_restore,
        }
    }

    #[cfg(test)]
    pub(crate) fn acquire_with<R: ImeCommandRunner>(
        runner: &R,
        restore_fn: fn(&RestoreAction),
    ) -> Self {
        let restore = probe_and_switch_to_english(runner);
        Self {
            restore,
            counted_in_tls: false,
            restore_fn,
        }
    }
}

impl Drop for ImeGuard {
    fn drop(&mut self) {
        if self.counted_in_tls {
            IME_GUARD_DEPTH.with(|depth| {
                let cur = depth.get();
                depth.set(cur.saturating_sub(1));
            });
        }
        if self.restore != RestoreAction::None {
            (self.restore_fn)(&self.restore);
        }
    }
}

fn probe_and_switch_to_english<R: ImeCommandRunner>(runner: &R) -> RestoreAction {
    if let Some(fcitx_out) = runner.run("fcitx5-remote", &[]) {
        if parse_fcitx5_is_active(&fcitx_out) {
            let _ = runner.run("fcitx5-remote", &["-c"]);
            return RestoreAction::Fcitx5Activate;
        }
        // fcitx5 返回 "1" 表示本身已是英文非激活状态，无需再探测 IBus
        if fcitx_out.trim() == "1" {
            return RestoreAction::None;
        }
    }

    if let Some(ibus_out) = runner.run("ibus", &["engine"]) {
        if let Some(prev_engine) = parse_ibus_engine_to_restore(&ibus_out) {
            let _ = runner.run("ibus", &["engine", IBUS_ENGLISH_ENGINE]);
            return RestoreAction::IbusEngine(prev_engine);
        }
    }

    RestoreAction::None
}

fn apply_system_restore(action: &RestoreAction) {
    let runner = SystemImeRunner;
    apply_restore_with(&runner, action);
}

pub(crate) fn apply_restore_with<R: ImeCommandRunner>(runner: &R, action: &RestoreAction) {
    match action {
        RestoreAction::None => {}
        RestoreAction::Fcitx5Activate => {
            let _ = runner.run("fcitx5-remote", &["-o"]);
        }
        RestoreAction::IbusEngine(prev) => {
            let _ = runner.run("ibus", &["engine", prev]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockRunner {
        responses: Vec<(&'static str, Vec<&'static str>, Option<String>)>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl MockRunner {
        fn new(responses: Vec<(&'static str, Vec<&'static str>, Option<String>)>) -> Self {
            Self {
                responses,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn recorded_calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.borrow().clone()
        }
    }

    impl ImeCommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            self.calls.borrow_mut().push((
                program.to_owned(),
                args.iter().map(|s| (*s).to_owned()).collect(),
            ));
            for (p, a, resp) in &self.responses {
                if *p == program && a.as_slice() == args {
                    return resp.clone();
                }
            }
            None
        }
    }

    #[test]
    fn parse_ibus_engine_distinguishes_xkb_and_cjk_engines() {
        assert_eq!(parse_ibus_engine_to_restore(""), None);
        assert_eq!(parse_ibus_engine_to_restore("   \n"), None);
        assert_eq!(parse_ibus_engine_to_restore("xkb:us::eng\n"), None);
        assert_eq!(parse_ibus_engine_to_restore("xkb:cn::eng"), None);
        assert_eq!(
            parse_ibus_engine_to_restore("table:wubi-haifeng86\n"),
            Some("table:wubi-haifeng86".to_owned())
        );
        assert_eq!(
            parse_ibus_engine_to_restore("libpinyin"),
            Some("libpinyin".to_owned())
        );
    }

    #[test]
    fn parse_fcitx5_state_checks_active_code_2() {
        assert!(parse_fcitx5_is_active("2\n"));
        assert!(parse_fcitx5_is_active("2"));
        assert!(!parse_fcitx5_is_active("1\n"));
        assert!(!parse_fcitx5_is_active("0\n"));
        assert!(!parse_fcitx5_is_active(""));
    }

    #[test]
    fn fcitx5_active_switches_to_english_and_restores_on_drop() {
        thread_local! {
            static RESTORED: RefCell<Vec<RestoreAction>> = const { RefCell::new(Vec::new()) };
        }
        fn record_restore(action: &RestoreAction) {
            RESTORED.with(|r| r.borrow_mut().push(action.clone()));
        }

        let runner = MockRunner::new(vec![
            ("fcitx5-remote", vec![], Some("2\n".to_owned())),
            ("fcitx5-remote", vec!["-c"], Some(String::new())),
        ]);

        {
            let guard = ImeGuard::acquire_with(&runner, record_restore);
            assert_eq!(guard.restore, RestoreAction::Fcitx5Activate);
            assert_eq!(
                runner.recorded_calls(),
                vec![
                    ("fcitx5-remote".to_owned(), vec![]),
                    ("fcitx5-remote".to_owned(), vec!["-c".to_owned()]),
                ]
            );
            RESTORED.with(|r| assert!(r.borrow().is_empty()));
        }

        RESTORED.with(|r| {
            assert_eq!(*r.borrow(), vec![RestoreAction::Fcitx5Activate]);
            r.borrow_mut().clear();
        });

        let restore_runner = MockRunner::new(vec![("fcitx5-remote", vec!["-o"], Some(String::new()))]);
        apply_restore_with(&restore_runner, &RestoreAction::Fcitx5Activate);
        assert_eq!(
            restore_runner.recorded_calls(),
            vec![("fcitx5-remote".to_owned(), vec!["-o".to_owned()])]
        );
    }

    #[test]
    fn ibus_cjk_engine_switches_to_us_and_restores_previous_engine() {
        thread_local! {
            static RESTORED: RefCell<Vec<RestoreAction>> = const { RefCell::new(Vec::new()) };
        }
        fn record_restore(action: &RestoreAction) {
            RESTORED.with(|r| r.borrow_mut().push(action.clone()));
        }

        let runner = MockRunner::new(vec![
            ("fcitx5-remote", vec![], None),
            ("ibus", vec!["engine"], Some("table:wubi-haifeng86\n".to_owned())),
            ("ibus", vec!["engine", "xkb:us::eng"], Some(String::new())),
        ]);

        {
            let guard = ImeGuard::acquire_with(&runner, record_restore);
            assert_eq!(
                guard.restore,
                RestoreAction::IbusEngine("table:wubi-haifeng86".to_owned())
            );
            assert_eq!(
                runner.recorded_calls(),
                vec![
                    ("fcitx5-remote".to_owned(), vec![]),
                    ("ibus".to_owned(), vec!["engine".to_owned()]),
                    (
                        "ibus".to_owned(),
                        vec!["engine".to_owned(), "xkb:us::eng".to_owned()]
                    ),
                ]
            );
        }

        RESTORED.with(|r| {
            assert_eq!(
                *r.borrow(),
                vec![RestoreAction::IbusEngine("table:wubi-haifeng86".to_owned())]
            );
            r.borrow_mut().clear();
        });

        let restore_runner = MockRunner::new(vec![(
            "ibus",
            vec!["engine", "table:wubi-haifeng86"],
            Some(String::new()),
        )]);
        apply_restore_with(
            &restore_runner,
            &RestoreAction::IbusEngine("table:wubi-haifeng86".to_owned()),
        );
        assert_eq!(
            restore_runner.recorded_calls(),
            vec![(
                "ibus".to_owned(),
                vec!["engine".to_owned(), "table:wubi-haifeng86".to_owned()]
            )]
        );
    }

    #[test]
    fn english_or_missing_ime_is_noop() {
        fn noop_restore(_: &RestoreAction) {
            panic!("noop guard should never invoke restore");
        }

        let fcitx_inactive = MockRunner::new(vec![("fcitx5-remote", vec![], Some("1\n".to_owned()))]);
        let g1 = ImeGuard::acquire_with(&fcitx_inactive, noop_restore);
        assert_eq!(g1.restore, RestoreAction::None);
        drop(g1);

        let ibus_xkb = MockRunner::new(vec![
            ("fcitx5-remote", vec![], None),
            ("ibus", vec!["engine"], Some("xkb:us::eng\n".to_owned())),
        ]);
        let g2 = ImeGuard::acquire_with(&ibus_xkb, noop_restore);
        assert_eq!(g2.restore, RestoreAction::None);
        drop(g2);

        let no_ime = MockRunner::new(vec![]);
        let g3 = ImeGuard::acquire_with(&no_ime, noop_restore);
        assert_eq!(g3.restore, RestoreAction::None);
        drop(g3);
    }

    #[test]
    fn nested_tls_guard_tracks_depth_without_panic() {
        let d0 = IME_GUARD_DEPTH.with(Cell::get);
        {
            let _outer = ImeGuard {
                restore: RestoreAction::None,
                counted_in_tls: true,
                restore_fn: |_| {},
            };
            IME_GUARD_DEPTH.with(|d| d.set(d.get() + 1));
            assert_eq!(IME_GUARD_DEPTH.with(Cell::get), d0 + 1);
            let _inner = ImeGuard::acquire();
            assert_eq!(IME_GUARD_DEPTH.with(Cell::get), d0 + 2);
            assert_eq!(_inner.restore, RestoreAction::None);
        }
        assert_eq!(IME_GUARD_DEPTH.with(Cell::get), d0);
    }
}
