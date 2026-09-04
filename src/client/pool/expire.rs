//! Drives periodic expiration for a retained pool service.
//!
//! The component follows the boundary proposed in
//! <https://github.com/hyperium/hyper/issues/3948>: protocol pools expose a
//! retention operation, while one outer watcher owns the timer and decides when
//! to inspect them. wreq wraps the destination [`Map`](super::map::Map), keeping
//! one watcher for the whole client instead of one task per destination.
//!
//! [`Expire`] holds only a weak reference to the inspected pool. The task cannot
//! extend the pool lifetime, and dropping the final pool handle closes the
//! shutdown channel so a long sleep ends immediately.

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
use wreq_proto::rt::{Executor as _, Sleep, Timer as _};

use crate::rt::{Executor, Timer};

/// Inspects retained state owned by an expiration target.
///
/// Implementations move rejected services out of their locks before dropping
/// them. Returning the next interval keeps expiration policy outside the task
/// driver and allows future policies to choose a different inspection cadence.
pub(super) trait Inspect: Send + Sync + 'static {
    /// Removes expired state and returns the next required inspection interval.
    fn retain(&self, now: Instant) -> Option<Duration>;

    /// Returns the next interval when retained state currently needs inspection.
    fn next(&self) -> Option<Duration>;
}

/// Runs one expiration watcher for a weakly owned pool target.
///
/// `Expire` remains dormant until its owner observes retained state and calls
/// [`Expire::schedule`]. At most one task runs at a time. The task repeatedly
/// asks [`Inspect`] to filter the wrapped pool, then stops once no reusable state
/// remains.
pub(super) struct Expire<T> {
    /// Pool inspected on each expiration tick.
    target: Weak<T>,

    /// Prevents concurrent watcher tasks for the same pool.
    running: Arc<AtomicBool>,

    /// Closes the watcher when this component is dropped.
    shutdown: watch::Sender<()>,

    /// Runtime used to execute the watcher.
    executor: Executor,

    /// Clock and sleep provider used by expiration checks.
    timer: Timer,
}

impl<T> Expire<T> {
    /// Creates an expiration component around `target`.
    ///
    /// An unavailable timer disables proactive checks. Callers may still use
    /// [`Expire::now`] for checkout-time expiration.
    pub(super) fn new(target: Weak<T>, executor: Executor, timer: Timer) -> Self {
        let (shutdown, _) = watch::channel(());

        Self {
            target,
            running: Arc::new(AtomicBool::new(false)),
            shutdown,
            executor,
            timer,
        }
    }

    /// Reads the configured clock, falling back to [`Instant::now`].
    pub(super) fn now(&self) -> Instant {
        if self.timer.is_empty() {
            Instant::now()
        } else {
            self.timer.now()
        }
    }

    /// Returns whether the expiration watcher is active.
    #[cfg(test)]
    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

impl<T> Expire<T>
where
    T: Inspect,
{
    /// Starts the watcher when proactive expiration is configured.
    ///
    /// The final policy check closes the stop/start race without holding a pool
    /// lock while spawning or waking another task. A zero interval disables the
    /// watcher to prevent an accidental busy loop.
    pub(super) fn schedule(&self, interval: Option<Duration>) {
        if self.timer.is_empty() {
            return;
        }
        let Some(interval) = interval.filter(|interval| *interval != Duration::ZERO) else {
            return;
        };
        let Some(deadline) = self.timer.now().checked_add(interval) else {
            return;
        };
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let target = self.target.clone();
        let running = self.running.clone();
        let timer = self.timer.clone();
        let mut shutdown = self.shutdown.subscribe();

        self.executor.execute(async move {
            let mut sleep = timer.sleep_until(deadline);

            loop {
                if !wait_for_tick(&mut sleep, &mut shutdown).await {
                    return;
                }
                let Some(target) = target.upgrade() else {
                    return;
                };

                let now = timer.now();
                if let Some(deadline) = target
                    .retain(now)
                    .filter(|next| *next != Duration::ZERO)
                    .and_then(|next| timer.now().checked_add(next))
                {
                    timer.reset(&mut sleep, deadline);
                    continue;
                }

                running.store(false, Ordering::Release);
                if let Some(deadline) = target
                    .next()
                    .filter(|next| *next != Duration::ZERO)
                    .and_then(|next| timer.now().checked_add(next))
                    && running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    timer.reset(&mut sleep, deadline);
                    continue;
                }
                return;
            }
        });
    }
}

/// Waits for the next expiration tick or target shutdown.
async fn wait_for_tick(
    sleep: &mut Pin<Box<dyn Sleep>>,
    shutdown: &mut watch::Receiver<()>,
) -> bool {
    let mut changed = std::pin::pin!(shutdown.changed());

    std::future::poll_fn(|cx| {
        if changed.as_mut().poll(cx).is_ready() {
            Poll::Ready(false)
        } else if sleep.as_mut().poll(cx).is_ready() {
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

    /// Controllable retained state inspected by the watcher.
    struct TestTarget {
        /// Whether another expiration tick is required.
        retained: AtomicBool,

        /// Number of completed retention checks.
        checks: AtomicUsize,
    }

    impl Inspect for TestTarget {
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

    #[tokio::test(start_paused = true)]
    async fn watcher_is_single_stops_and_observes_shutdown() {
        let target = Arc::new(TestTarget {
            retained: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
        });
        let expire = Expire::new(
            Arc::downgrade(&target),
            Executor::default(),
            Timer::default(),
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
