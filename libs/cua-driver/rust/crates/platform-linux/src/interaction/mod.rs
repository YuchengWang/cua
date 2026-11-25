// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! The layer every Linux compositor adapter shares: the lock, identity,
//! delivery, freshness, reach, motion and restore rules in [`policy`], the one
//! foreground transaction entry point, the deadline rule, the focus
//! read-back loop and the settle loop. Wayland adapters supply mechanical
//! save, focus and restore steps to the one transaction; X11 supplies
//! activate and report steps. Adapters measure geometry; niri's output and
//! placement limits stay in its pointer gate.

use std::any::Any;
use std::time::{Duration, Instant};

use anyhow::Result;
use cua_driver_core::batch_foreground::{self, BatchForegroundContext, BatchForegroundHandle};

use crate::desktop::{Compositor, Desktop};
use crate::input::{FocusGuardReport, ForegroundOptions, ForegroundReport};

pub mod facts;
pub mod policy;

/// Refuse an operation of `scope` the session lock does not admit.
/// `focused` is the target's exact focus, read back right before dispatch.
pub fn admit_lock(scope: policy::Scope, focused: facts::Fact<bool>) -> Result<()> {
    let facts = facts::Facts {
        locked: facts::locked(),
        focused,
    };
    policy::lock(scope, &facts)
}

/// Whether a foreground transaction gives focus back once its body ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreMode {
    RestorePrevious,
    /// The body activates the target itself and leaves it focused.
    LeaveFocused,
}

/// What each kind of foreground action does with the focus it took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForegroundPolicy {
    /// `type_text`.
    pub typing: RestoreMode,
    /// `press_key` and `hotkey`.
    pub key: RestoreMode,
    /// `click`.
    pub click: RestoreMode,
    /// `double_click`, `scroll` and `drag`.
    pub gesture: RestoreMode,
    /// `right_click` and `set_value`, whose input opens a menu or popup that
    /// giving focus back would close. The X11 restore detects that popup and
    /// keeps the target focused; the Wayland adapters cannot.
    pub menu: RestoreMode,
    /// The browser setup and consent flows, which act for the driver rather
    /// than the agent.
    pub setup: RestoreMode,
}

/// The one table of foreground restore rules. XWayland takes the X11 input
/// routes, so it reads the X11 row. Pass a niri claim through
/// [`Desktop::attested`] first.
pub fn foreground_policy(desktop: Desktop) -> ForegroundPolicy {
    use RestoreMode::{LeaveFocused as Leave, RestorePrevious as Restore};
    match desktop {
        // niri restores the prior focus after gestures, as after clicks.
        Desktop::Wayland(Compositor::Niri) => ForegroundPolicy {
            typing: Restore,
            key: Restore,
            click: Restore,
            gesture: Restore,
            menu: Leave,
            setup: Restore,
        },
        // On X11 every foreground action gives the active window back. Input
        // that opens a menu still leaves it open: the restore sees the menu's
        // popup and keeps the target focused.
        Desktop::X11 | Desktop::XWayland(_) => ForegroundPolicy {
            typing: Restore,
            key: Restore,
            click: Restore,
            gesture: Restore,
            menu: Restore,
            setup: Restore,
        },
        // The Wayland adapters do not detect a menu and would close it.
        Desktop::Wayland(_) => ForegroundPolicy {
            typing: Restore,
            key: Restore,
            click: Restore,
            gesture: Leave,
            menu: Leave,
            setup: Restore,
        },
    }
}

/// This session's [`foreground_policy`].
pub fn session_policy() -> ForegroundPolicy {
    foreground_policy(crate::desktop::desktop().attested())
}

/// Run `body` with the exact `pid`/`window_id` pair focused. On Wayland a
/// compositor adapter confirms the pair and restores the prior focus
/// afterwards; global input is refused when no adapter can confirm it. On
/// X11 [`with_x11_foreground`] activates the window and restores the prior
/// focus afterwards. [`RestoreMode::LeaveFocused`] runs `body` as it is: it
/// activates the target itself and leaves it focused.
pub fn with_target_foreground<T>(
    pid: u32,
    window_id: u64,
    mode: RestoreMode,
    body: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use crate::wayland::{bind_foreground_target, kwin_helper, niri, shell_helper, sway_ipc};
    if let RestoreMode::LeaveFocused = mode {
        if let Some(batch) = batch_foreground::current() {
            if let Some(existing) = batch.take_active() {
                let mut guard = BatchReinsertGuard {
                    batch: &batch,
                    handle: Some(downcast_linux_batch_handle(existing)),
                };
                if guard.handle.as_ref().is_some_and(|h| match h {
                    LinuxBatchHandle::X11(st) => st.xid != window_id,
                    LinuxBatchHandle::Wayland(st) => st.pid != pid || st.window_id != window_id,
                }) {
                    if let Some(old) = guard.handle.take() {
                        Box::new(old).finish()?;
                    }
                } else if let Some(ref mut h) = guard.handle {
                    match h {
                        LinuxBatchHandle::X11(st) => st.mode = RestoreMode::LeaveFocused,
                        LinuxBatchHandle::Wayland(st) => st.mode = RestoreMode::LeaveFocused,
                    }
                }
                drop(guard);
            }
        }
        admit_lock(
            policy::Scope::TargetBoundInput,
            facts::Fact::Unknown("the body activates the target itself".into()),
        )?;
        return body();
    }
    if crate::desktop::desktop() == Desktop::X11 {
        return with_x11_foreground(window_id, ForegroundOptions::pointer(), mode, body)
            .map(|(value, _report)| value);
    }
    let body = || {
        let focused = if niri::is_session() {
            match niri::keyboard_focus() {
                Ok(focused) => facts::Fact::Known(focused == Some(window_id)),
                Err(error) => facts::Fact::Unknown(format!("{error:#}")),
            }
        } else {
            facts::Fact::Known(true)
        };
        admit_lock(policy::Scope::WindowInput, focused)?;
        body()
    };
    let _target_guard = bind_foreground_target(pid, window_id);
    let confirm = || operation_deadline(FOCUS_CONFIRM_CAP);
    if niri::is_session() {
        return transaction_with_batch(
            (pid, window_id),
            mode,
            &mut niri::ipc(),
            |_| niri::keyboard_focus().map(|focused| focused == Some(window_id)),
            |ipc| niri::save_focus(ipc, pid, window_id),
            |ipc, saved| niri::focus_saved(ipc, saved, niri::FOCUS_CONFIRM_TIMEOUT),
            |ipc| {
                if let Some(saved) = niri::save_focus(ipc, pid, window_id)? {
                    niri::focus_saved(ipc, &saved, niri::FOCUS_CONFIRM_TIMEOUT)?;
                }
                Ok(())
            },
            body,
            niri::restore_saved,
            |saved, cleanup| niri::restore_saved(&mut niri::ipc(), saved, cleanup),
        );
    }
    if let Some(window) = sway_ipc::window_for_id(window_id) {
        policy::identity(
            &(pid, window_id),
            &facts::Fact::Known(Some((window.pid, window.id))),
        )?;
        return transaction_with_batch(
            (pid, window_id),
            mode,
            &mut (),
            |()| {
                let prior = sway_ipc::focused(confirm())?;
                Ok(policy::focused(
                    &(pid, window_id),
                    &facts::Fact::Known(prior),
                ))
            },
            |()| {
                let prior = sway_ipc::focused(confirm())?;
                if policy::focused(&(pid, window_id), &facts::Fact::Known(prior)) {
                    return Ok(None);
                }
                Ok(Some(prior))
            },
            |(), _| sway_ipc::focus(pid, window_id, confirm()),
            |()| sway_ipc::focus(pid, window_id, confirm()),
            body,
            |(), prior, cleanup| {
                prior.map_or(Ok(()), |(pid, prior)| sway_ipc::focus(pid, prior, cleanup))
            },
            |prior, cleanup| {
                prior.map_or(Ok(()), |(pid, prior)| sway_ipc::focus(pid, prior, cleanup))
            },
        );
    }
    if kwin_helper::trusted_window_for_id(pid, window_id).is_some() {
        policy::delivery(&facts::Fact::Known(kwin_helper::available()))?;
    }
    if shell_helper::trusted_window_for_id(pid, window_id).is_some() {
        return transaction_with_batch(
            (pid, window_id),
            mode,
            &mut (),
            |()| {
                let prior = shell_helper::trusted_focus(confirm())?;
                Ok(policy::focused(
                    &(Some(pid), window_id),
                    &facts::Fact::Known(prior),
                ))
            },
            |()| {
                let prior = shell_helper::trusted_focus(confirm())?;
                if policy::focused(&(Some(pid), window_id), &facts::Fact::Known(prior)) {
                    return Ok(None);
                }
                policy::restore(facts::Fact::Known(
                    prior.and_then(|(pid, id)| pid.map(|pid| (pid, id))),
                ))
                .map(Some)
            },
            |(), _| shell_helper::trusted_focus_window(pid, window_id, confirm()),
            |()| shell_helper::trusted_focus_window(pid, window_id, confirm()),
            body,
            |(), (pid, prior), cleanup| shell_helper::trusted_focus_window(pid, prior, cleanup),
            |(pid, prior), cleanup| shell_helper::trusted_focus_window(pid, prior, cleanup),
        );
    }
    anyhow::bail!(
        "foreground_unavailable: no trusted Wayland compositor adapter can confirm exact target window {window_id} for pid {pid}; no global keyboard input was sent"
    )
}

enum LinuxBatchHandle {
    X11(X11BatchState),
    Wayland(WaylandBatchState),
}

impl LinuxBatchHandle {
    fn matches_x11(&self, xid: u64) -> bool {
        matches!(self, Self::X11(st) if st.xid == xid)
    }

    fn matches_wayland(&self, pid: u32, window_id: u64) -> bool {
        matches!(self, Self::Wayland(st) if st.pid == pid && st.window_id == window_id)
    }
}

impl BatchForegroundHandle for LinuxBatchHandle {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn finish(self: Box<Self>) -> Result<()> {
        match *self {
            Self::X11(st) => st.finish(),
            Self::Wayland(st) => st.finish(),
        }
    }
}

fn downcast_linux_batch_handle(mut handle: Box<dyn BatchForegroundHandle>) -> LinuxBatchHandle {
    let linux = handle
        .as_any_mut()
        .downcast_mut::<LinuxBatchHandle>()
        .expect("platform-linux only stores LinuxBatchHandle in BatchForegroundContext");
    std::mem::replace(
        linux,
        LinuxBatchHandle::Wayland(WaylandBatchState {
            pid: 0,
            window_id: 0,
            saved: None,
            restore_fn: |_, _| Ok(()),
            mode: RestoreMode::LeaveFocused,
            _lock: BatchTransactionGuard { owner: None },
        }),
    )
}

struct BatchReinsertGuard<'a> {
    batch: &'a BatchForegroundContext,
    handle: Option<LinuxBatchHandle>,
}

impl Drop for BatchReinsertGuard<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.batch.store_or_finish(Box::new(handle));
        }
    }
}

struct X11BatchState {
    xid: u64,
    target_pid: Option<u32>,
    prior: Option<Box<dyn Any + Send>>,
    restore_fn: fn(Box<dyn Any + Send>, Option<u32>, Instant) -> Option<FocusGuardReport>,
    last_delivered_at: Instant,
    mode: RestoreMode,
    _lock: BatchTransactionGuard,
}

impl X11BatchState {
    fn finish(mut self) -> Result<()> {
        let restored = match self.mode {
            RestoreMode::RestorePrevious => self
                .prior
                .take()
                .map(|prior| (self.restore_fn)(prior, self.target_pid, self.last_delivered_at)),
            RestoreMode::LeaveFocused => None,
        };
        let outcome = evaluate_x11_restore(restored);
        drop(self._lock);
        if let Some(why) = outcome.unrestored {
            anyhow::bail!("the input was sent, but the prior focus could not be restored: {why}");
        }
        Ok(())
    }
}

struct WaylandBatchState {
    pid: u32,
    window_id: u64,
    saved: Option<Box<dyn Any + Send>>,
    restore_fn: fn(Box<dyn Any + Send>, Instant) -> Result<()>,
    mode: RestoreMode,
    _lock: BatchTransactionGuard,
}

impl WaylandBatchState {
    fn finish(mut self) -> Result<()> {
        let result = match self.mode {
            RestoreMode::RestorePrevious => self
                .saved
                .take()
                .map_or(Ok(()), |saved| (self.restore_fn)(saved, Instant::now() + CLEANUP_CAP)),
            RestoreMode::LeaveFocused => Ok(()),
        };
        drop(self._lock);
        result.map_err(|error| {
            error.context("the input was sent, but the prior focus could not be restored")
        })
    }
}

struct X11RestoreOutcome {
    menu_open: Option<u32>,
    unrestored: Option<String>,
}

fn evaluate_x11_restore(restored: Option<Option<FocusGuardReport>>) -> X11RestoreOutcome {
    // Judged on whether the focus came back, not on the background guard's
    // outcome order: a focused new dialog of the target is not a restore.
    // Only a prior window the body closed leaves nothing to restore, and a
    // menu the body opened keeps the focus, since giving it back would
    // close the menu.
    let kept = |r: &FocusGuardReport| r.changed && !r.restored && r.closed_window.is_none();
    let menu_open = restored
        .as_ref()
        .and_then(|r| r.as_ref().filter(|r| kept(r))?.grab_held_by);
    let unrestored = restored.and_then(|r| match r {
        None => Some("the display could not be opened".to_owned()),
        Some(r) if kept(&r) && r.grab_held_by.is_none() => {
            Some(format!("not_restored ({})", r.changes.join(", ")))
        }
        Some(_) => None,
    });
    X11RestoreOutcome {
        menu_open,
        unrestored,
    }
}

trait X11ForegroundOps {
    type Prior: Send + 'static;
    type Activated;

    fn capture_prior(&self) -> Option<Self::Prior>;
    fn prior_has_previous(prior: &Self::Prior) -> bool;
    fn target_pid(&self, xid: u64, opts: ForegroundOptions) -> Option<u32>;
    fn activate(&self, xid: u64, opts: ForegroundOptions) -> Result<Self::Activated>;
    fn verify_active(&self, xid: u64, opts: ForegroundOptions) -> Result<Option<Self::Activated>>;
    fn admit_window_input(&self) -> Result<()> {
        admit_lock(policy::Scope::WindowInput, facts::Fact::Known(true))
    }
    fn report(&self, activated: Self::Activated) -> ForegroundReport;
    fn restore(
        prior: Self::Prior,
        target_pid: Option<u32>,
        delivered_at: Instant,
    ) -> Option<FocusGuardReport>;
}

struct RealX11Ops;

impl X11ForegroundOps for RealX11Ops {
    type Prior = crate::input::focus_guard::FocusSnapshot;
    type Activated = crate::input::foreground::Activated;

    fn capture_prior(&self) -> Option<Self::Prior> {
        crate::input::focus_guard::FocusSnapshot::capture()
    }

    fn prior_has_previous(prior: &Self::Prior) -> bool {
        prior.previous_focus_window().is_some()
    }

    fn target_pid(&self, xid: u64, opts: ForegroundOptions) -> Option<u32> {
        crate::x11::window_pid(xid).or(opts.target_pid)
    }

    fn activate(&self, xid: u64, opts: ForegroundOptions) -> Result<Self::Activated> {
        crate::input::foreground::activate(xid, opts)
    }

    fn verify_active(&self, xid: u64, opts: ForegroundOptions) -> Result<Option<Self::Activated>> {
        crate::input::foreground::verify_active_for_batch(xid, opts)
    }

    fn report(&self, activated: Self::Activated) -> ForegroundReport {
        activated.report()
    }

    fn restore(
        prior: Self::Prior,
        target_pid: Option<u32>,
        delivered_at: Instant,
    ) -> Option<FocusGuardReport> {
        prior.restore_after_foreground(target_pid, delivered_at)
    }
}

fn restore_x11_boxed<O: X11ForegroundOps>(
    prior: Box<dyn Any + Send>,
    target_pid: Option<u32>,
    delivered_at: Instant,
) -> Option<FocusGuardReport> {
    let prior = *prior
        .downcast::<O::Prior>()
        .expect("X11BatchState prior type mismatch");
    O::restore(prior, target_pid, delivered_at)
}

/// The X11 foreground transaction (`delivery_mode:"foreground"`): activate
/// `xid` and read back that it holds the active window and input focus,
/// admit the lock for window input, run `body`, then report where focus and
/// the target process's windows ended up. [`RestoreMode::RestorePrevious`]
/// then gives the focus back to the window that held it before, even when
/// activation or the body failed, since focus may have moved either way,
/// unless the body opened a menu: the target then keeps the focus and the
/// report names the menu ([`ForegroundReport::menu_open`]).
/// [`RestoreMode::LeaveFocused`] leaves the target active.
pub fn with_x11_foreground<T>(
    xid: u64,
    opts: ForegroundOptions,
    mode: RestoreMode,
    body: impl FnOnce() -> Result<T>,
) -> Result<(T, ForegroundReport)> {
    with_x11_foreground_with_ops(&RealX11Ops, xid, opts, mode, body)
}

fn with_x11_foreground_with_ops<O: X11ForegroundOps, T>(
    ops: &O,
    xid: u64,
    opts: ForegroundOptions,
    mode: RestoreMode,
    body: impl FnOnce() -> Result<T>,
) -> Result<(T, ForegroundReport)> {
    if let Some(batch) = batch_foreground::current() {
        return with_x11_foreground_batched(ops, &batch, xid, opts, mode, body);
    }
    let (_transaction, prior) = match mode {
        RestoreMode::RestorePrevious => {
            let held = hold_transaction()?;
            let Some(prior) = ops.capture_prior() else {
                anyhow::bail!(
                    "{}: the prior X11 focus could not be read, so nothing was focused",
                    crate::input::foreground::CODE_UNAVAILABLE
                );
            };
            // No window held the focus before: there is nothing to give back.
            (Some(held), O::prior_has_previous(&prior).then_some(prior))
        }
        RestoreMode::LeaveFocused => (None, None),
    };
    // Read before the body, which may close the target.
    let target_pid = prior.as_ref().and_then(|_| ops.target_pid(xid, opts));
    let mut delivered_at = None;
    let ran = ops.activate(xid, opts).and_then(|activated| {
        ops.admit_window_input()?;
        let value = body()?;
        delivered_at = Some(Instant::now());
        Ok((value, ops.report(activated)))
    });
    let delivered_at = delivered_at.unwrap_or_else(Instant::now);
    let restored = prior.map(|prior| O::restore(prior, target_pid, delivered_at));
    let X11RestoreOutcome {
        menu_open,
        unrestored,
    } = evaluate_x11_restore(restored);
    let ran = ran.map(|(value, report)| {
        (
            value,
            ForegroundReport {
                menu_open,
                ..report
            },
        )
    });
    match (ran, unrestored) {
        (ran, None) => ran,
        (Ok(_), Some(why)) => {
            anyhow::bail!("the input was sent, but the prior focus could not be restored: {why}")
        }
        (Err(error), Some(why)) => {
            let note = format!("{error}; the prior focus also could not be restored: {why}");
            Err(error.context(note))
        }
    }
}

fn with_x11_foreground_batched<O: X11ForegroundOps, T>(
    ops: &O,
    batch: &BatchForegroundContext,
    xid: u64,
    opts: ForegroundOptions,
    mode: RestoreMode,
    body: impl FnOnce() -> Result<T>,
) -> Result<(T, ForegroundReport)> {
    if let Some(existing) = batch.take_active() {
        let existing = downcast_linux_batch_handle(existing);
        if existing.matches_x11(xid) {
            let LinuxBatchHandle::X11(mut st) = existing else {
                unreachable!()
            };
            st.target_pid = st.target_pid.or(opts.target_pid).or_else(|| ops.target_pid(xid, opts));
            if mode == RestoreMode::LeaveFocused {
                st.mode = RestoreMode::LeaveFocused;
            }
            let mut guard = BatchReinsertGuard {
                batch,
                handle: Some(LinuxBatchHandle::X11(st)),
            };
            let target_pid = match guard.handle.as_ref() {
                Some(LinuxBatchHandle::X11(st)) => st.target_pid,
                _ => None,
            };
            let check_opts = match target_pid {
                Some(pid) if opts.target_pid.is_none() => opts.for_pid(pid),
                _ => opts,
            };
            let activated = match ops.verify_active(xid, check_opts)? {
                Some(already) => already,
                None => ops.activate(xid, check_opts)?,
            };
            ops.admit_window_input()?;
            let value = body()?;
            let delivered_at = Instant::now();
            if let Some(LinuxBatchHandle::X11(ref mut st)) = guard.handle {
                st.last_delivered_at = delivered_at;
            }
            let report = ops.report(activated);
            if let Some(handle) = guard.handle.take() {
                batch.store_or_finish(Box::new(handle))?;
            }
            return Ok((value, report));
        }
        // Different target window: finalize the previous target first.
        Box::new(existing).finish()?;
    }

    // First foreground step for `xid` in this batch.
    let lock = hold_batch_transaction(batch.id())?;
    let prior = match mode {
        RestoreMode::RestorePrevious => {
            let Some(prior) = ops.capture_prior() else {
                anyhow::bail!(
                    "{}: the prior X11 focus could not be read, so nothing was focused",
                    crate::input::foreground::CODE_UNAVAILABLE
                );
            };
            O::prior_has_previous(&prior).then_some(prior)
        }
        RestoreMode::LeaveFocused => None,
    };
    let target_pid = ops.target_pid(xid, opts);
    let activated = match ops.activate(xid, opts) {
        Ok(activated) => activated,
        Err(error) => {
            let restored = prior.map(|p| O::restore(p, target_pid, Instant::now()));
            drop(lock);
            let X11RestoreOutcome { unrestored, .. } = evaluate_x11_restore(restored);
            return match unrestored {
                None => Err(error),
                Some(why) => {
                    let note =
                        format!("{error}; the prior focus also could not be restored: {why}");
                    Err(error.context(note))
                }
            };
        }
    };
    let mut guard = BatchReinsertGuard {
        batch,
        handle: Some(LinuxBatchHandle::X11(X11BatchState {
            xid,
            target_pid,
            prior: prior.map(|p| Box::new(p) as Box<dyn Any + Send>),
            restore_fn: restore_x11_boxed::<O>,
            last_delivered_at: Instant::now(),
            mode,
            _lock: lock,
        })),
    };
    ops.admit_window_input()?;
    let value = body()?;
    let delivered_at = Instant::now();
    if let Some(LinuxBatchHandle::X11(ref mut st)) = guard.handle {
        st.last_delivered_at = delivered_at;
    }
    let report = ops.report(activated);
    if let Some(handle) = guard.handle.take() {
        batch.store_or_finish(Box::new(handle))?;
    }
    Ok((value, report))
}

/// How long a compositor may take to apply and report a focus change.
const FOCUS_CONFIRM_CAP: Duration = Duration::from_millis(500);

/// The one foreground transaction every adapter runs: save the prior focus,
/// focus the target and read it back, run `body`, then restore the saved
/// focus within [`CLEANUP_CAP`]. `save` returns `None` when the target
/// already has focus, which runs `body` with nothing to restore. Once
/// `focus` was asked, focus may have moved even when the adapter could not
/// confirm it, so the restore runs either way. One transaction runs at a
/// time: a worker whose call timed out still gives focus back late, and a
/// retry on the same window would read that window as the prior focus and
/// lose it to the late restore.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn transaction<A, S, T>(
    adapter: &mut A,
    save: impl FnOnce(&mut A) -> Result<Option<S>>,
    focus: impl FnOnce(&mut A, &S) -> Result<()>,
    body: impl FnOnce() -> Result<T>,
    restore: impl FnOnce(&mut A, S, Instant) -> Result<()>,
) -> Result<T> {
    let _transaction = hold_transaction()?;
    let Some(saved) = save(adapter)? else {
        return body();
    };
    let result = focus(adapter, &saved).and_then(|()| body());
    let cleanup = Instant::now() + CLEANUP_CAP;
    match (result, restore(adapter, saved, cleanup)) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        // The body sent its input: say so, so the caller does not repeat it.
        (Ok(_), Err(error)) => {
            Err(error.context("the input was sent, but the prior focus could not be restored"))
        }
        (Err(error), Err(restore)) => {
            let note = format!("{error}; the prior focus also could not be restored: {restore:#}");
            Err(error.context(note))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn transaction_with_batch<A, S: Send + 'static, T>(
    target: (u32, u64),
    mode: RestoreMode,
    adapter: &mut A,
    is_focused: impl FnOnce(&mut A) -> Result<bool>,
    save: impl FnOnce(&mut A) -> Result<Option<S>>,
    focus: impl FnOnce(&mut A, &S) -> Result<()>,
    refocus: impl FnOnce(&mut A) -> Result<()>,
    body: impl FnOnce() -> Result<T>,
    restore_now: impl FnOnce(&mut A, S, Instant) -> Result<()>,
    restore_later: fn(S, Instant) -> Result<()>,
) -> Result<T> {
    let Some(batch) = batch_foreground::current() else {
        return transaction(adapter, save, focus, body, restore_now);
    };
    if let Some(existing) = batch.take_active() {
        let existing = downcast_linux_batch_handle(existing);
        if existing.matches_wayland(target.0, target.1) {
            let LinuxBatchHandle::Wayland(mut st) = existing else {
                unreachable!()
            };
            if mode == RestoreMode::LeaveFocused {
                st.mode = RestoreMode::LeaveFocused;
            }
            let mut guard = BatchReinsertGuard {
                batch: &batch,
                handle: Some(LinuxBatchHandle::Wayland(st)),
            };
            if !is_focused(adapter)? {
                refocus(adapter)?;
            }
            let value = body()?;
            if let Some(handle) = guard.handle.take() {
                batch.store_or_finish(Box::new(handle))?;
            }
            return Ok(value);
        }
        Box::new(existing).finish()?;
    }

    let lock = hold_batch_transaction(batch.id())?;
    let saved = save(adapter)?;
    if let Some(ref saved_ref) = saved {
        if let Err(error) = focus(adapter, saved_ref) {
            let cleanup = Instant::now() + CLEANUP_CAP;
            let restore_res = saved.map_or(Ok(()), |s| restore_now(adapter, s, cleanup));
            drop(lock);
            return match restore_res {
                Ok(()) => Err(error),
                Err(restore_err) => {
                    let note = format!(
                        "{error}; the prior focus also could not be restored: {restore_err:#}"
                    );
                    Err(error.context(note))
                }
            };
        }
    }
    let restore_fn = |boxed: Box<dyn Any + Send>, cleanup: Instant| -> Result<()> {
        let (restore_later, saved) = *boxed
            .downcast::<(fn(S, Instant) -> Result<()>, S)>()
            .expect("WaylandBatchState saved type mismatch");
        restore_later(saved, cleanup)
    };
    let mut guard = BatchReinsertGuard {
        batch: &batch,
        handle: Some(LinuxBatchHandle::Wayland(WaylandBatchState {
            pid: target.0,
            window_id: target.1,
            saved: saved.map(|s| Box::new((restore_later, s)) as Box<dyn Any + Send>),
            restore_fn,
            mode,
            _lock: lock,
        })),
    };
    let value = body()?;
    if let Some(handle) = guard.handle.take() {
        batch.store_or_finish(Box::new(handle))?;
    }
    Ok(value)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransactionOwner {
    Thread(std::thread::ThreadId),
    Batch(u64),
}

/// One foreground transaction runs at a time across threads (or across steps
/// belonging to one active batch).
static TRANSACTION: std::sync::Mutex<Option<TransactionOwner>> = std::sync::Mutex::new(None);

std::thread_local! {
    /// Whether this thread already holds the transaction. A body that opens
    /// another foreground transaction — the libei fallback of
    /// [`crate::wayland::click_focused`] re-enters the guard after a blocking
    /// portal readiness wait — runs inside the one it already holds, so it
    /// must not wait for the mutex its own thread took.
    static HOLDS_TRANSACTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn lock_transaction_slot() -> std::sync::MutexGuard<'static, Option<TransactionOwner>> {
    TRANSACTION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn release_transaction_owner(expected: Option<TransactionOwner>) {
    let Some(expected) = expected else {
        return;
    };
    let mut slot = lock_transaction_slot();
    if *slot == Some(expected) {
        *slot = None;
    }
}

fn acquire_transaction_slot(desired: TransactionOwner) -> Result<bool> {
    loop {
        {
            let mut slot = lock_transaction_slot();
            match *slot {
                None => {
                    *slot = Some(desired);
                    return Ok(true);
                }
                Some(existing) if existing == desired => return Ok(false),
                Some(TransactionOwner::Thread(tid)) if tid == std::thread::current().id() => {
                    return Ok(false);
                }
                Some(_) => {}
            }
        }
        crate::input::action::admit(|| ())?;
        pause(POLL);
    }
}

/// Wait for any other foreground transaction to give focus back, then hold
/// this one until it does. The holder's waits are bounded, and a caller
/// whose own call ends stops waiting.
fn hold_transaction() -> Result<HeldTransaction> {
    let already_held = HOLDS_TRANSACTION
        .try_with(std::cell::Cell::get)
        .unwrap_or(false);
    if already_held {
        // The outer transaction already holds focus for its body, so this one
        // takes no lock and its drop must not release the outer one.
        return Ok(HeldTransaction { release: None });
    }
    if let Some(batch) = batch_foreground::current() {
        let slot = lock_transaction_slot();
        if *slot == Some(TransactionOwner::Batch(batch.id())) {
            return Ok(HeldTransaction { release: None });
        }
    }
    let owner = TransactionOwner::Thread(std::thread::current().id());
    let acquired = acquire_transaction_slot(owner)?;
    if acquired {
        let _ = HOLDS_TRANSACTION.try_with(|held| held.set(true));
    }
    Ok(HeldTransaction {
        release: acquired.then_some(owner),
    })
}

fn hold_batch_transaction(batch_id: u64) -> Result<BatchTransactionGuard> {
    let owner = TransactionOwner::Batch(batch_id);
    let acquired = acquire_transaction_slot(owner)?;
    Ok(BatchTransactionGuard {
        owner: acquired.then_some(owner),
    })
}

struct BatchTransactionGuard {
    owner: Option<TransactionOwner>,
}

impl Drop for BatchTransactionGuard {
    fn drop(&mut self) {
        release_transaction_owner(self.owner.take());
    }
}

/// The foreground transaction this thread holds. Only the outermost
/// transaction locks [`TRANSACTION`]; a nested one holds nothing and releases
/// nothing, so the outer transaction still runs last.
struct HeldTransaction {
    release: Option<TransactionOwner>,
}

impl Drop for HeldTransaction {
    fn drop(&mut self) {
        let released = self.release.take();
        if matches!(released, Some(TransactionOwner::Thread(_))) {
            let _ = HOLDS_TRANSACTION.try_with(|held| held.set(false));
        }
        release_transaction_owner(released);
    }
}

/// The one budget every cleanup gets once its action is over, even past
/// the action's deadline: held inputs are released first, then focus is
/// restored, all within this cap from the start of cleanup.
pub const CLEANUP_CAP: Duration = Duration::from_millis(500);

const POLL: Duration = Duration::from_millis(10);
const SETTLE_READS: usize = 5;
const SETTLE_INTERVAL: Duration = Duration::from_millis(30);
const SETTLE_CAP: Duration = Duration::from_secs(1);

/// The deadline of an operation capped at `cap`, never past the deadline of
/// the action bound to this thread. Cleanup that must outlive the action
/// (releases, focus restore) takes `Instant::now() + cap` instead.
pub fn operation_deadline(cap: Duration) -> Instant {
    let capped = Instant::now() + cap;
    crate::input::action::current().map_or(capped, |action| capped.min(action.deadline()))
}

/// Sleep for `cap`, never past the deadline of the action bound to this
/// thread. Input pacing waits here, so a call out of time stops waiting.
pub fn pause(cap: Duration) {
    std::thread::sleep(operation_deadline(cap).saturating_duration_since(Instant::now()));
}

/// Read `confirmed` back until it holds or `deadline` passes. The callback
/// receives the same absolute deadline for its own round trips.
/// A compositor that accepts a request has not applied it: only the
/// read-back says it did.
pub fn confirm<E>(
    deadline: Instant,
    mut confirmed: impl FnMut(Instant) -> Result<bool, E>,
) -> Result<bool, E> {
    while Instant::now() < deadline {
        if confirmed(deadline)? {
            return Ok(Instant::now() < deadline);
        }
        std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Ok(false)
}

/// Read `observe` until two consecutive reads agree on `key`, a few reads a
/// fixed interval apart. Callbacks receive the action-capped deadline and
/// must bound their round trips by it; late results refuse with `unsettled`.
/// Agreeing reads do not prove an animation finished.
pub fn settled<T, K: PartialEq, E>(
    mut observe: impl FnMut(Instant) -> Result<T, E>,
    key: impl Fn(&T) -> K,
    unsettled: impl FnOnce() -> E,
) -> Result<T, E> {
    let deadline = operation_deadline(SETTLE_CAP);
    if Instant::now() >= deadline {
        return Err(unsettled());
    }
    let mut last = observe(deadline)?;
    for _ in 1..SETTLE_READS {
        if Instant::now() + SETTLE_INTERVAL > deadline {
            break;
        }
        std::thread::sleep(SETTLE_INTERVAL);
        if Instant::now() >= deadline {
            break;
        }
        let next = observe(deadline)?;
        if Instant::now() < deadline
            && policy::settled(&key(&last), &facts::Fact::Known(key(&next)))
        {
            return Ok(next);
        }
        last = next;
    }
    Err(unsettled())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::action::{bind, Action};

    #[test]
    fn the_operation_deadline_never_passes_the_bound_action() {
        let unbound = operation_deadline(Duration::from_secs(5));
        assert!(unbound > Instant::now() + Duration::from_secs(4));
        let action = Action::new(Duration::from_millis(20));
        let _bound = bind(action.clone());
        assert!(operation_deadline(Duration::from_secs(5)) <= action.deadline());
    }

    #[test]
    fn x11_restores_every_action_and_wayland_all_but_menus_and_gestures_off_niri() {
        let compositors = [
            Compositor::Injected,
            Compositor::Hyprland,
            Compositor::Niri,
            Compositor::Other,
        ];
        let x11 = std::iter::once(Desktop::X11).chain(compositors.map(Desktop::XWayland));
        for desktop in x11 {
            let policy = foreground_policy(desktop);
            let modes = [
                policy.typing,
                policy.key,
                policy.click,
                policy.gesture,
                policy.menu,
                policy.setup,
            ];
            for mode in modes {
                assert_eq!(mode, RestoreMode::RestorePrevious, "{desktop:?}");
            }
        }
        for desktop in compositors.map(Desktop::Wayland) {
            let policy = foreground_policy(desktop);
            for restored in [policy.typing, policy.key, policy.click, policy.setup] {
                assert_eq!(restored, RestoreMode::RestorePrevious, "{desktop:?}");
            }
            assert_eq!(policy.menu, RestoreMode::LeaveFocused, "{desktop:?}");
            let gesture = if desktop == Desktop::Wayland(Compositor::Niri) {
                RestoreMode::RestorePrevious
            } else {
                RestoreMode::LeaveFocused
            };
            assert_eq!(policy.gesture, gesture, "{desktop:?}");
        }
    }

    #[test]
    fn leave_focused_runs_the_body_without_a_compositor_transaction() {
        let ran = with_target_foreground(1, 2, RestoreMode::LeaveFocused, || Ok("sent"));
        assert_eq!(ran.unwrap(), "sent");
    }

    #[test]
    fn confirm_reads_back_until_it_holds_and_never_starts_past_the_deadline() {
        let mut reads = 0;
        let deadline = Instant::now() + Duration::from_secs(1);
        let held = confirm(deadline, |received| {
            assert_eq!(received, deadline);
            reads += 1;
            Ok::<_, ()>(reads == 3)
        });
        assert_eq!((held, reads), (Ok(true), 3));
        let mut reads = 0;
        let expired = confirm(Instant::now(), |_| {
            reads += 1;
            Ok::<_, ()>(false)
        });
        assert_eq!((expired, reads), (Ok(false), 0));
        assert_eq!(
            confirm(Instant::now() + Duration::from_secs(1), |_| Err::<bool, _>(
                "unknown"
            )),
            Err("unknown")
        );
    }

    #[test]
    fn a_late_focus_read_back_does_not_confirm_delivery() {
        let deadline = Instant::now() + Duration::from_millis(10);
        assert_eq!(
            confirm(deadline, |received| {
                assert_eq!(received, deadline);
                std::thread::sleep(Duration::from_millis(20));
                Ok::<_, ()>(true)
            }),
            Ok(false)
        );
    }

    #[test]
    fn settle_stops_at_the_action_deadline() {
        let _bound = bind(Action::new(Duration::ZERO));
        let mut reads = 0;
        let moving = settled(
            |_| {
                reads += 1;
                Ok::<_, &str>(reads)
            },
            |read| *read,
            || "unsettled",
        );
        assert_eq!((moving, reads), (Err("unsettled"), 0));
    }

    static TEST_TX_SERIALIZE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn a_nested_transaction_runs_inside_the_one_its_thread_holds() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        // A GNOME click reaches `click_focused`'s libei fallback from inside
        // the foreground guard it already holds and re-enters it there. The
        // action is bound only around the nested call, as the outer caller's
        // is: binding it around the outer transaction instead would let a
        // slower test holding the process-wide lock fail this one.
        let sent = transaction(
            &mut (),
            |()| Ok(Some("prior")),
            |(), _| Ok(()),
            || {
                let _bound = bind(Action::new(Duration::from_millis(200)));
                transaction(
                    &mut (),
                    |()| Ok(Some("prior")),
                    |(), _| Ok(()),
                    || Ok("click sent"),
                    |(), _, _| Ok(()),
                )
            },
            |(), _, _| Ok(()),
        );
        assert_eq!(sent.unwrap(), "click sent");
    }

    #[test]
    fn only_the_outermost_transaction_locks_and_its_drop_releases_it() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let outer = hold_transaction().unwrap();
        assert!(outer.release.is_some());
        // This thread already holds the transaction, so the nested hold never
        // waits on another thread. The action bounds it anyway: a hold that
        // waited for its own lock fails here instead of hanging the suite.
        let _bound = bind(Action::new(Duration::from_millis(200)));
        drop(hold_transaction().unwrap());
        assert!(
            outer.release.is_some(),
            "a nested hold released the outer transaction"
        );
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            let held = hold_transaction();
            entered.send(held.is_ok()).unwrap();
        });
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "a second thread entered the transaction its holder still holds"
        );
        drop(outer);
        assert!(entered_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        other.join().unwrap();
    }

    #[test]
    fn settle_returns_the_first_of_two_agreeing_reads() {
        let mut reads = 0;
        let settling = settled(
            |_| {
                reads += 1;
                Ok::<_, &str>(reads.min(2))
            },
            |read| *read,
            || "unsettled",
        );
        assert_eq!(settling, Ok(2));
    }

    #[derive(Clone)]
    struct FakeX11Ops {
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        prior_window: Option<u64>,
        pid: Option<u32>,
        verify_ok: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
        fail_activate: bool,
        restore_report: std::sync::Arc<std::sync::Mutex<Option<FocusGuardReport>>>,
    }

    impl FakeX11Ops {
        fn new(prior_window: Option<u64>, pid: Option<u32>) -> Self {
            Self {
                events: std::sync::Arc::default(),
                prior_window,
                pid,
                verify_ok: std::sync::Arc::default(),
                fail_activate: false,
                restore_report: std::sync::Arc::new(std::sync::Mutex::new(Some(
                    FocusGuardReport {
                        changed: true,
                        restored: true,
                        ..Default::default()
                    },
                ))),
            }
        }

        fn push(&self, event: impl Into<String>) {
            self.events.lock().unwrap().push(event.into());
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    struct FakePrior {
        window: Option<u64>,
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        restore_report: std::sync::Arc<std::sync::Mutex<Option<FocusGuardReport>>>,
    }

    struct FakeActivated {
        already_active: bool,
    }

    impl X11ForegroundOps for FakeX11Ops {
        type Prior = FakePrior;
        type Activated = FakeActivated;

        fn capture_prior(&self) -> Option<Self::Prior> {
            self.push(format!("capture_prior:{:?}", self.prior_window));
            Some(FakePrior {
                window: self.prior_window,
                events: self.events.clone(),
                restore_report: self.restore_report.clone(),
            })
        }

        fn prior_has_previous(prior: &Self::Prior) -> bool {
            prior.window.is_some()
        }

        fn target_pid(&self, _xid: u64, opts: ForegroundOptions) -> Option<u32> {
            self.pid.or(opts.target_pid)
        }

        fn activate(&self, xid: u64, _opts: ForegroundOptions) -> Result<Self::Activated> {
            self.push(format!("activate:{xid}"));
            if self.fail_activate {
                anyhow::bail!("foreground_unavailable: blocked");
            }
            Ok(FakeActivated {
                already_active: false,
            })
        }

        fn verify_active(&self, xid: u64, _opts: ForegroundOptions) -> Result<Option<Self::Activated>> {
            let ok = {
                let mut queue = self.verify_ok.lock().unwrap();
                if queue.is_empty() {
                    true
                } else {
                    queue.remove(0)
                }
            };
            self.push(format!("verify_active:{xid}:{ok}"));
            Ok(ok.then_some(FakeActivated {
                already_active: true,
            }))
        }

        fn admit_window_input(&self) -> Result<()> {
            self.push("admit_lock");
            Ok(())
        }

        fn report(&self, activated: Self::Activated) -> ForegroundReport {
            ForegroundReport {
                already_active: activated.already_active,
                retried_activation: false,
                confirm_ms: 1,
                focus_after: crate::input::FocusAfter::Target,
                window_change: None,
                window_change_owned: false,
                menu_open: None,
            }
        }

        fn restore(
            prior: Self::Prior,
            target_pid: Option<u32>,
            _delivered_at: Instant,
        ) -> Option<FocusGuardReport> {
            prior
                .events
                .lock()
                .unwrap()
                .push(format!("restore:{:?}:pid={target_pid:?}", prior.window));
            prior.restore_report.lock().unwrap().clone()
        }
    }

    #[test]
    fn x11_batch_activates_once_skips_mid_batch_activate_and_restore_and_finishes_once() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let ops = FakeX11Ops::new(Some(10), Some(4242));
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        let (_, r1) = with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || {
                ops.push("body:click");
                Ok(())
            },
        )
        .unwrap();
        assert!(!r1.already_active);

        let (_, r2) = with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::keyboard(),
            RestoreMode::RestorePrevious,
            || {
                ops.push("body:press_down");
                Ok(())
            },
        )
        .unwrap();
        assert!(r2.already_active);

        let (_, r3) = with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::keyboard(),
            RestoreMode::RestorePrevious,
            || {
                ops.push("body:press_return");
                Ok(())
            },
        )
        .unwrap();
        assert!(r3.already_active);

        // Prior focus must not have been restored yet before batch finish (e.g. during delay_ms or observe).
        assert!(
            !ops.events().iter().any(|e| e.starts_with("restore:")),
            "unexpected mid-batch restore: {:?}",
            ops.events()
        );

        batch.close().unwrap().finish().unwrap();

        assert_eq!(
            ops.events(),
            vec![
                "capture_prior:Some(10)",
                "activate:99",
                "admit_lock",
                "body:click",
                "verify_active:99:true",
                "admit_lock",
                "body:press_down",
                "verify_active:99:true",
                "admit_lock",
                "body:press_return",
                "restore:Some(10):pid=Some(4242)",
            ]
        );
    }

    #[test]
    fn x11_batch_reactivates_only_if_focus_moved_away_and_keeps_initial_prior() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let ops = FakeX11Ops::new(Some(10), Some(4242));
        *ops.verify_ok.lock().unwrap() = vec![false];
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || Ok(()),
        )
        .unwrap();

        with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::keyboard(),
            RestoreMode::RestorePrevious,
            || Ok(()),
        )
        .unwrap();

        batch.close().unwrap().finish().unwrap();

        assert_eq!(
            ops.events(),
            vec![
                "capture_prior:Some(10)",
                "activate:99",
                "admit_lock",
                "verify_active:99:false",
                "activate:99",
                "admit_lock",
                "restore:Some(10):pid=Some(4242)",
            ]
        );
    }

    #[test]
    fn x11_batch_keeps_focus_when_menu_or_popup_is_still_open_at_finish() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let ops = FakeX11Ops::new(Some(10), Some(4242));
        *ops.restore_report.lock().unwrap() = Some(FocusGuardReport {
            changed: true,
            restored: false,
            grab_held_by: Some(4242),
            ..Default::default()
        });
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || Ok(()),
        )
        .unwrap();

        // Simulate `observe` running while the batch handle is still open and holding focus.
        assert!(!ops.events().iter().any(|e| e.starts_with("restore:")));
        batch.close().unwrap().finish().unwrap();
        assert_eq!(
            ops.events().last().map(String::as_str),
            Some("restore:Some(10):pid=Some(4242)")
        );
    }

    #[test]
    fn x11_batch_switching_target_window_finalizes_first_before_activating_second() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let ops = FakeX11Ops::new(Some(10), Some(4242));
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || {
                ops.push("body:win99");
                Ok(())
            },
        )
        .unwrap();

        with_x11_foreground_with_ops(
            &ops,
            100,
            ForegroundOptions::keyboard(),
            RestoreMode::RestorePrevious,
            || {
                ops.push("body:win100");
                Ok(())
            },
        )
        .unwrap();

        batch.close().unwrap().finish().unwrap();

        assert_eq!(
            ops.events(),
            vec![
                "capture_prior:Some(10)",
                "activate:99",
                "admit_lock",
                "body:win99",
                "restore:Some(10):pid=Some(4242)",
                "capture_prior:Some(10)",
                "activate:100",
                "admit_lock",
                "body:win100",
                "restore:Some(10):pid=Some(4242)",
            ]
        );
    }

    #[test]
    fn x11_batch_activation_failure_restores_prior_and_releases_lock() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let mut ops = FakeX11Ops::new(Some(10), Some(4242));
        ops.fail_activate = true;
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        let err = with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || Ok(()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("blocked"));
        assert!(batch.close().is_none());
        // Transaction lock must be free afterwards.
        drop(hold_transaction().unwrap());
    }

    #[test]
    fn x11_batch_step_body_failure_still_restores_on_finish() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let ops = FakeX11Ops::new(Some(10), Some(4242));
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::pointer(),
            RestoreMode::RestorePrevious,
            || Ok(()),
        )
        .unwrap();

        let err = with_x11_foreground_with_ops(
            &ops,
            99,
            ForegroundOptions::keyboard(),
            RestoreMode::RestorePrevious,
            || -> Result<()> { anyhow::bail!("key failed") },
        )
        .unwrap_err();
        assert!(err.to_string().contains("key failed"));
        assert!(!ops.events().iter().any(|e| e.starts_with("restore:")));
        batch.close().unwrap().finish().unwrap();
        assert!(ops.events().iter().any(|e| e.starts_with("restore:")));
    }

    #[test]
    fn wayland_batch_transaction_focuses_and_restores_once_across_same_target_steps() {
        let _serial = TEST_TX_SERIALIZE.blocking_lock();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let batch = BatchForegroundContext::new();
        let _bound = batch_foreground::bind_blocking(Some(batch.clone()));

        let log_events = events.clone();
        let restore_later = |saved: (std::sync::Arc<std::sync::Mutex<Vec<String>>>, &'static str),
                             _cleanup: Instant|
         -> Result<()> {
            saved.0.lock().unwrap().push(format!("restore:{}", saved.1));
            Ok(())
        };

        transaction_with_batch(
            (7, 88),
            RestoreMode::RestorePrevious,
            &mut (),
            |()| Ok(true),
            |()| {
                log_events.lock().unwrap().push("save".into());
                Ok(Some((log_events.clone(), "prior")))
            },
            |(), _| {
                log_events.lock().unwrap().push("focus".into());
                Ok(())
            },
            |()| {
                log_events.lock().unwrap().push("refocus".into());
                Ok(())
            },
            || {
                log_events.lock().unwrap().push("body1".into());
                Ok(())
            },
            |(), _, _| unreachable!(),
            restore_later,
        )
        .unwrap();

        transaction_with_batch(
            (7, 88),
            RestoreMode::RestorePrevious,
            &mut (),
            |()| {
                log_events.lock().unwrap().push("is_focused:true".into());
                Ok(true)
            },
            |()| {
                log_events.lock().unwrap().push("save2".into());
                Ok(Some((log_events.clone(), "prior2")))
            },
            |(), _| {
                log_events.lock().unwrap().push("focus2".into());
                Ok(())
            },
            |()| {
                log_events.lock().unwrap().push("refocus2".into());
                Ok(())
            },
            || {
                log_events.lock().unwrap().push("body2".into());
                Ok(())
            },
            |(), _, _| unreachable!(),
            restore_later,
        )
        .unwrap();

        batch.close().unwrap().finish().unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "save",
                "focus",
                "body1",
                "is_focused:true",
                "body2",
                "restore:prior",
            ]
        );
    }

    #[tokio::test]
    async fn batch_transaction_holds_lock_across_async_spawn_blocking_steps_until_finish() {
        let _serial = TEST_TX_SERIALIZE.lock().await;
        let batch = BatchForegroundContext::new();
        let ops = FakeX11Ops::new(Some(10), Some(4242));

        batch_foreground::scope_context(batch.clone(), async {
            let ops1 = ops.clone();
            crate::input::action::spawn_blocking_bounded(
                "step1",
                Duration::from_secs(2),
                move || {
                    with_x11_foreground_with_ops(
                        &ops1,
                        99,
                        ForegroundOptions::pointer(),
                        RestoreMode::RestorePrevious,
                        || Ok(()),
                    )
                    .map(|_| ())
                },
            )
            .await
            .unwrap()
            .unwrap();

            // Unrelated thread must wait while the batch transaction holds TRANSACTION across delay_ms.
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let other = std::thread::spawn(move || {
                let held = hold_transaction();
                let _ = entered_tx.send(held.is_ok());
            });
            assert!(entered_rx.recv_timeout(Duration::from_millis(80)).is_err());

            tokio::time::sleep(Duration::from_millis(20)).await;

            let ops2 = ops.clone();
            crate::input::action::spawn_blocking_bounded(
                "step2",
                Duration::from_secs(2),
                move || {
                    with_x11_foreground_with_ops(
                        &ops2,
                        99,
                        ForegroundOptions::keyboard(),
                        RestoreMode::RestorePrevious,
                        || Ok(()),
                    )
                    .map(|_| ())
                },
            )
            .await
            .unwrap()
            .unwrap();

            assert!(!ops.events().iter().any(|e| e.starts_with("restore:")));
            batch.finish_async().await.unwrap();
            assert!(entered_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            other.join().unwrap();
        })
        .await;
    }
}
