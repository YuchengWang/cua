// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Batch-level foreground focus transaction scope for `run_steps`.
//!
//! When a `run_steps` batch executes multiple foreground actions (or an action
//! followed by `observe`/`expect`), keeping the platform foreground focus
//! transaction open across steps prevents intermediate steps from re-activating
//! the parent window or restoring prior focus between steps — which closes
//! transient `override-redirect` popups such as browser autofill menus — and
//! lets trailing `observe` (`get_window_state`) inspect the window before final
//! focus restoration.
//!
//! Platform crates implement [`BatchForegroundHandle`] and store it in the
//! task/thread-scoped [`BatchForegroundContext`] via [`current`] and
//! [`bind_blocking`]. Direct calls outside a batch see [`current`] == `None`
//! and keep single-step semantics unchanged.

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;

/// Platform-owned active foreground focus transaction held across steps in a
/// `run_steps` batch.
pub trait BatchForegroundHandle: Send {
    /// Downcast handle to the platform's concrete state type.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Finalize the transaction (restoring prior focus per the platform's
    /// restore rule unless a popup/menu keeps it focused) and release any
    /// process-wide transaction lock.
    fn finish(self: Box<Self>) -> Result<()>;
}

static NEXT_BATCH_ID: AtomicU64 = AtomicU64::new(1);

enum SlotState {
    Empty,
    Active(Box<dyn BatchForegroundHandle>),
    Closed,
}

fn lock_slot(slot: &Mutex<SlotState>) -> std::sync::MutexGuard<'_, SlotState> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shared handle slot for one `run_steps` invocation.
#[derive(Clone)]
pub struct BatchForegroundContext {
    id: u64,
    slot: Arc<Mutex<SlotState>>,
}

impl Default for BatchForegroundContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchForegroundContext {
    /// Create a fresh batch foreground context with a unique batch id.
    pub fn new() -> Self {
        Self {
            id: NEXT_BATCH_ID.fetch_add(1, Ordering::Relaxed),
            slot: Arc::new(Mutex::new(SlotState::Empty)),
        }
    }

    /// Unique identifier for this batch transaction scope.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Take the currently active handle out of the slot without closing the
    /// batch. The caller must return it via [`Self::store_or_finish`] (or
    /// finish it when switching to a different target).
    pub fn take_active(&self) -> Option<Box<dyn BatchForegroundHandle>> {
        let mut guard = lock_slot(&self.slot);
        match std::mem::replace(&mut *guard, SlotState::Empty) {
            SlotState::Active(handle) => Some(handle),
            SlotState::Empty => None,
            SlotState::Closed => {
                *guard = SlotState::Closed;
                None
            }
        }
    }

    /// Return `true` once [`Self::close`] has sealed this batch context.
    pub fn is_closed(&self) -> bool {
        matches!(*lock_slot(&self.slot), SlotState::Closed)
    }

    /// Store `handle` back into the slot, or finish it immediately if the batch
    /// was already closed (for example after a blocking worker timed out).
    pub fn store_or_finish(&self, handle: Box<dyn BatchForegroundHandle>) -> Result<()> {
        let displaced = {
            let mut guard = lock_slot(&self.slot);
            match &mut *guard {
                SlotState::Empty => {
                    *guard = SlotState::Active(handle);
                    return Ok(());
                }
                SlotState::Active(_) => {
                    let prev = std::mem::replace(&mut *guard, SlotState::Active(handle));
                    match prev {
                        SlotState::Active(existing) => Some(existing),
                        _ => None,
                    }
                }
                SlotState::Closed => {
                    drop(guard);
                    return handle.finish();
                }
            }
        };
        if let Some(existing) = displaced {
            existing.finish()?;
        }
        Ok(())
    }

    /// Seal the batch context and take any remaining active handle. Subsequent
    /// [`Self::store_or_finish`] calls will finish their handle immediately.
    pub fn close(&self) -> Option<Box<dyn BatchForegroundHandle>> {
        let mut guard = lock_slot(&self.slot);
        match std::mem::replace(&mut *guard, SlotState::Closed) {
            SlotState::Active(handle) => Some(handle),
            SlotState::Empty | SlotState::Closed => None,
        }
    }

    /// Close the batch context and run any pending [`BatchForegroundHandle::finish`]
    /// on Tokio's blocking pool so the async executor is never stalled on X11 or
    /// Wayland IPC.
    pub async fn finish_async(&self) -> Result<()> {
        let Some(handle) = self.close() else {
            return Ok(());
        };
        match tokio::task::spawn_blocking(move || handle.finish()).await {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!("batch foreground cleanup failed: {error}")),
        }
    }

    /// Create an RAII guard that ensures any still-active handle is finalized
    /// even if the `run_steps` future is dropped before reaching
    /// [`Self::finish_async`].
    pub fn abort_guard(&self) -> BatchAbortGuard {
        BatchAbortGuard { ctx: self.clone() }
    }
}

/// Drop guard that finalizes a leaked batch foreground handle on cancellation.
pub struct BatchAbortGuard {
    ctx: BatchForegroundContext,
}

impl Drop for BatchAbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.ctx.close() {
            let pending = Arc::new(Mutex::new(Some(handle)));
            let worker_pending = pending.clone();
            if std::thread::Builder::new()
                .name("cua-batch-fg-cleanup".into())
                .spawn(move || {
                    let taken = worker_pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(handle) = taken {
                        let _ = handle.finish();
                    }
                })
                .is_err()
            {
                let taken = pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(handle) = taken {
                    let _ = handle.finish();
                }
            }
        }
    }
}

tokio::task_local! {
    static TASK_CURRENT: BatchForegroundContext;
}

thread_local! {
    static THREAD_CURRENT: RefCell<Option<BatchForegroundContext>> = const { RefCell::new(None) };
}

/// Run `future` with `ctx` bound as the active batch foreground scope.
pub async fn scope_context<F: Future>(ctx: BatchForegroundContext, future: F) -> F::Output {
    TASK_CURRENT.scope(ctx, future).await
}

/// The active [`BatchForegroundContext`] on this async task or blocking thread,
/// if inside a batch foreground transaction scope.
pub fn current() -> Option<BatchForegroundContext> {
    TASK_CURRENT
        .try_with(Clone::clone)
        .ok()
        .or_else(|| THREAD_CURRENT.with(|cell| cell.borrow().clone()))
}

/// Restores the previous thread-local batch context when dropped.
pub struct BlockingBound(Option<BatchForegroundContext>);

impl Drop for BlockingBound {
    fn drop(&mut self) {
        let previous = self.0.take();
        let _ = THREAD_CURRENT.try_with(|cell| {
            *cell.borrow_mut() = previous;
        });
    }
}

/// Bind `ctx` on the current blocking thread for synchronous platform code,
/// restoring any previous binding on drop.
pub fn bind_blocking(ctx: Option<BatchForegroundContext>) -> BlockingBound {
    BlockingBound(
        THREAD_CURRENT
            .try_with(|cell| cell.replace(ctx))
            .ok()
            .flatten(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestHandle {
        finishes: Arc<AtomicUsize>,
        fail: bool,
    }

    impl BatchForegroundHandle for TestHandle {
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn finish(self: Box<Self>) -> Result<()> {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("restore failed")
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn scope_and_blocking_bind_propagate_and_restore() {
        assert!(current().is_none());
        let ctx = BatchForegroundContext::new();
        let finishes = Arc::new(AtomicUsize::new(0));

        scope_context(ctx.clone(), async {
            let captured = current().expect("task-local context");
            assert_eq!(captured.id(), ctx.id());
            let finishes_worker = finishes.clone();
            tokio::task::spawn_blocking(move || {
                let _bound = bind_blocking(Some(captured));
                let inner = current().expect("thread-local context");
                inner
                    .store_or_finish(Box::new(TestHandle {
                        finishes: finishes_worker,
                        fail: false,
                    }))
                    .unwrap();
            })
            .await
            .unwrap();
            assert_eq!(finishes.load(Ordering::SeqCst), 0);
        })
        .await;

        assert!(current().is_none());
        ctx.finish_async().await.unwrap();
        assert_eq!(finishes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn store_after_close_finishes_immediately() {
        let ctx = BatchForegroundContext::new();
        assert!(ctx.close().is_none());
        assert!(ctx.is_closed());
        let finishes = Arc::new(AtomicUsize::new(0));
        ctx.store_or_finish(Box::new(TestHandle {
            finishes: finishes.clone(),
            fail: false,
        }))
        .unwrap();
        assert_eq!(finishes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abort_guard_finishes_on_drop_and_is_noop_after_close() {
        let finishes = Arc::new(AtomicUsize::new(0));
        {
            let ctx = BatchForegroundContext::new();
            let _guard = ctx.abort_guard();
            ctx.store_or_finish(Box::new(TestHandle {
                finishes: finishes.clone(),
                fail: false,
            }))
            .unwrap();
        }
        // Wait briefly for the detached cleanup thread on drop.
        for _ in 0..50 {
            if finishes.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(finishes.load(Ordering::SeqCst), 1);
    }
}
