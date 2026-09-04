//! Configures connection reuse behavior.
//!
//! [`PoolStrategy`] controls the race between reusing an existing connection
//! and starting a new one. It does not configure idle retention or cap active
//! connections. The selected strategy applies to every compatibility group
//! created by [`ClientBuilder`](crate::ClientBuilder).

use std::time::Duration;

/// Selects when the pool starts a new connection while reuse is unavailable.
///
/// This changes acquisition timing only. Idle timeouts and retention limits are
/// configured separately on [`ClientBuilder`](crate::ClientBuilder).
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use wreq::{Client, pool::PoolStrategy};
///
/// let _client = Client::builder()
///     .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_millis(50)));
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolStrategy {
    /// Starts a new connection as soon as no reusable connection is ready.
    ///
    /// Existing work can still win the resulting race. This is the default and
    /// favors low latency.
    #[default]
    Race,
    /// Gives existing pool state this long to become reusable before connecting.
    ///
    /// A cold compatibility group connects immediately. The delay applies only
    /// when idle, checked-out, or connecting state may become reusable. A zero
    /// duration behaves like [`PoolStrategy::Race`].
    ReuseFirst(Duration),
}
