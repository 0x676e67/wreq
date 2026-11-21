//! Periodic idle expiration for pooled connections.
//!
//! Follows the split proposed in <https://github.com/hyperium/hyper/issues/3948>:
//! protocol pools expose retention hooks, while a single outer watcher owns the runtime
//! timer and drives sweeps across the whole [`Map`](super::map::Map).
//!
//! [`Expire`] holds only a weak reference to its target so it never keeps the pool alive;
//! dropping the last pool handle closes the shutdown channel to cancel any pending sleep.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};

use tokio::sync::watch;

use crate::rt::{BoxSleep, DynRuntime, Timer as _};

/// Retains reusable state owned by an expiration target.
///
/// Implementations move rejected services out of their locks before dropping
/// them. The returned interval determines when the watcher next inspects the pool.
pub(super) trait Retain: Send + Sync + 'static {
    /// Removes expired state and returns the next required inspection interval.
    fn retain(&self, now: Instant) -> Option<Duration>;

    /// Returns the next interval when retained state currently needs inspection.
    fn next(&self) -> Option<Duration>;
}

/// Drives at most one periodic expiration watcher for a weakly referenced pool.
///
/// Stays dormant until [`Expire::schedule`] is called after retained state appears, then
/// sweeps via [`Retain`] until no reusable state remains or the pool is dropped.
pub(super) struct Expire<T> {
    /// Weak reference to the pool swept on each tick.
    target: Weak<T>,
    /// Claimed on first poll by the active watcher so duplicate spawns exit early.
    running: Arc<AtomicBool>,
    /// Dropping this sender wakes and stops a sleeping watcher immediately.
    shutdown: watch::Sender<()>,
    /// Runtime providing the timer and task executor for the watcher.
    runtime: DynRuntime,
}

impl<T> Expire<T> {
    /// Creates an expiration component around `target`.
    #[must_use]
    pub(super) fn new(target: Weak<T>, runtime: DynRuntime) -> Self {
        let (shutdown, _) = watch::channel(());

        Self {
            target,
            running: Arc::new(AtomicBool::new(false)),
            shutdown,
            runtime,
        }
    }

    /// Reads the selected runtime clock.
    #[must_use]
    pub(super) fn now(&self) -> Instant {
        self.runtime.now()
    }

    /// Returns whether the expiration watcher is active.
    #[must_use]
    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

impl<T> Expire<T>
where
    T: Retain,
{
    /// Starts the watcher when proactive expiration is configured.
    ///
    /// Before stopping, the watcher releases its running flag and uses [`Retain::next`]
    /// to check for newly retained connections. A zero interval disables the watcher.
    pub(super) fn schedule(&self, interval: Option<Duration>) {
        let Some(interval) = interval.filter(|interval| *interval != Duration::ZERO) else {
            return;
        };
        let Some(deadline) = self.runtime.now().checked_add(interval) else {
            return;
        };
        if self.running.load(Ordering::Acquire) {
            return;
        }

        let target = self.target.clone();
        let mut running = Running {
            flag: self.running.clone(),
            owned: false,
        };
        let runtime = self.runtime.clone();
        let mut shutdown = self.shutdown.subscribe();

        // Claim on first poll so a task queued on a paused runtime cannot block a
        // watcher from starting on another runtime.
        self.runtime.execute(Box::pin(async move {
            if !running.claim() {
                return;
            }
            let mut sleep = runtime.sleep_until(deadline);

            loop {
                if !wait_for_tick(&mut sleep, &mut shutdown).await {
                    return;
                }
                let Some(target) = target.upgrade() else {
                    return;
                };

                let now = runtime.now();
                if let Some(deadline) = target
                    .retain(now)
                    .filter(|next| *next != Duration::ZERO)
                    .and_then(|next| runtime.now().checked_add(next))
                {
                    sleep.reset(deadline);
                    continue;
                }

                running.release();
                if let Some(deadline) = target
                    .next()
                    .filter(|next| *next != Duration::ZERO)
                    .and_then(|next| runtime.now().checked_add(next))
                    && running.claim()
                {
                    sleep.reset(deadline);
                    continue;
                }
                return;
            }
        }));
    }
}

/// Watcher ownership of [`Expire::running`], cleared when the task stops.
///
/// Dropping the task without completion, for example during runtime shutdown,
/// must still let a later [`Expire::schedule`] start a replacement watcher.
struct Running {
    /// Shared flag synchronized with [`Expire::running`].
    flag: Arc<AtomicBool>,
    /// Whether this guard claimed `flag` and must clear it on drop.
    owned: bool,
}

// ===== impl Running =====

impl Running {
    /// Gives up ownership so another schedule can start a watcher.
    fn release(&mut self) {
        if std::mem::take(&mut self.owned) {
            self.flag.store(false, Ordering::Release);
        }
    }

    /// Takes ownership unless another watcher already holds it.
    #[must_use]
    fn claim(&mut self) -> bool {
        self.owned = self
            .flag
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        self.owned
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.release();
    }
}

/// Waits for the next expiration tick or target shutdown.
async fn wait_for_tick(sleep: &mut BoxSleep, shutdown: &mut watch::Receiver<()>) -> bool {
    let mut changed = std::pin::pin!(shutdown.changed());

    std::future::poll_fn(|cx| {
        if changed.as_mut().poll(cx).is_ready() {
            Poll::Ready(false)
        } else if Pin::new(&mut *sleep).poll(cx).is_ready() {
            Poll::Ready(true)
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Controllable retention target used to count watcher sweeps.
    struct TestTarget {
        /// Whether the target still reports retained state needing sweeps.
        retained: AtomicBool,
        /// Number of `retain` sweeps observed.
        checks: AtomicUsize,
    }

    impl Retain for TestTarget {
        fn retain(&self, _now: Instant) -> Option<Duration> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            self.next()
        }

        fn next(&self) -> Option<Duration> {
            self.retained
                .load(Ordering::SeqCst)
                .then_some(Duration::from_millis(100))
        }
    }

    #[test]
    fn watcher_flag_resets_when_runtime_drops_task() {
        let target = Arc::new(TestTarget {
            retained: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let expire = runtime.block_on(async {
            let expire = Expire::new(
                Arc::downgrade(&target),
                DynRuntime::new(crate::rt::tokio::TokioRuntime),
            );
            expire.schedule(Some(Duration::from_mins(1)));
            assert!(!expire.is_running());
            tokio::task::yield_now().await;
            expire
        });
        assert!(expire.is_running());

        // Runtime shutdown drops the sleeping watcher; a later schedule must start again.
        drop(runtime);
        assert!(!expire.is_running());
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_is_single_stops_and_observes_shutdown() {
        let target = Arc::new(TestTarget {
            retained: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
        });
        let expire = Expire::new(
            Arc::downgrade(&target),
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
        );

        expire.schedule(Some(Duration::from_millis(100)));
        expire.schedule(Some(Duration::from_millis(1)));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(target.checks.load(Ordering::SeqCst), 1);

        target.retained.store(false, Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(target.checks.load(Ordering::SeqCst), 2);
        assert!(!expire.is_running());

        target.retained.store(true, Ordering::SeqCst);
        expire.schedule(Some(Duration::from_millis(100)));
        tokio::task::yield_now().await;
        let watcher = Arc::downgrade(&expire.running);
        drop(expire);
        tokio::task::yield_now().await;
        assert!(watcher.upgrade().is_none());

        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(target.checks.load(Ordering::SeqCst), 2);
    }
}
