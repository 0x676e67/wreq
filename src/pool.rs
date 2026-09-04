//! Configures connection reuse and physical connection limits.
//!
//! [`PoolStrategy`] controls whether a cache miss immediately starts a new
//! connection or briefly waits for an existing one. [`PoolLimits`] bounds the
//! physical connections owned by a client. These settings apply across every
//! connection group created by [`ClientBuilder`](crate::ClientBuilder).

use std::{num::NonZeroUsize, time::Duration};

/// Selects when the pool starts a new connection after a reuse miss.
///
/// The strategy changes connection acquisition only. It does not change how
/// long idle connections remain in the pool or how many are retained.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use wreq::{Client, pool::PoolStrategy};
///
/// let _builder = Client::builder()
///     .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_millis(50)));
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolStrategy {
    /// Immediately races connection reuse against a new connection.
    ///
    /// This is the default and favors low latency when no connection is
    /// immediately reusable.
    #[default]
    Race,
    /// Waits up to this duration for reuse before starting a new connection.
    ///
    /// An empty connection group still connects immediately. The delay is used
    /// only when the group already has idle, checked-out, or connecting state
    /// that may become reusable. A zero duration behaves like [`PoolStrategy::Race`].
    ReuseFirst(Duration),
}

/// Selects how per-scope connection limits are grouped.
///
/// This affects [`PoolLimitsBuilder::max_connections_per_scope`]. The global
/// limit is shared by the whole client regardless of this setting.
///
/// # Example
///
/// ```rust
/// use wreq::pool::{PoolLimitScope, PoolLimits};
///
/// let limits = PoolLimits::builder()
///     .max_connections_per_scope(8)
///     .scope(PoolLimitScope::OriginAndProtocol)
///     .build();
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolLimitScope {
    /// Groups connections by URI origin.
    ///
    /// Requests with the same scheme, host, and effective port share a limit.
    #[default]
    Origin,
    /// Groups connections by URI origin and requested protocol mode.
    ///
    /// Automatic, HTTP/1-only, and HTTP/2-only connections are counted in
    /// separate scopes for the same origin.
    OriginAndProtocol,
    /// Uses the complete connection compatibility group.
    ///
    /// This is the narrowest scope and includes connector settings that make
    /// two physical connections incompatible for reuse.
    Group,
}

/// Limits the physical connections owned by one client.
///
/// A connection counts while it is being established, while it serves
/// requests, and while it remains idle. For multiplexed protocols such as
/// HTTP/2, one physical connection occupies one slot regardless of its active
/// stream count. These limits therefore do not cap logical request concurrency.
///
/// Use [`PoolLimits::builder`] to configure either limit. Passing `0` to a
/// limit method disables that limit.
///
/// # Examples
///
/// ```rust
/// use wreq::{Client, pool::{PoolLimitScope, PoolLimits}};
///
/// let limits = PoolLimits::builder()
///     .max_connections(64)
///     .max_connections_per_scope(8)
///     .scope(PoolLimitScope::Origin)
///     .build();
///
/// let _builder = Client::builder().pool_limits(limits);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
#[non_exhaustive]
pub struct PoolLimits {
    /// Maximum number of physical connections owned by the client.
    pub(crate) max_connections: Option<NonZeroUsize>,
    /// Maximum number of physical connections in one configured scope.
    pub(crate) max_connections_per_scope: Option<NonZeroUsize>,
    /// Grouping used by the per-scope limit.
    pub(crate) scope: PoolLimitScope,
}

/// Builds [`PoolLimits`] without exposing its internal representation.
///
/// The builder starts with both limits disabled and uses
/// [`PoolLimitScope::Origin`] for per-scope accounting. Setting either maximum
/// to `0` disables that limit; calling [`PoolLimitsBuilder::build`] performs no
/// allocation or runtime validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct PoolLimitsBuilder {
    /// Limits being configured.
    limits: PoolLimits,
}

impl PoolLimitsBuilder {
    /// Sets the maximum number of connections across the client.
    #[inline]
    pub const fn max_connections(mut self, max: usize) -> Self {
        self.limits.max_connections = NonZeroUsize::new(max);
        self
    }

    /// Sets the maximum number of connections in each configured scope.
    ///
    /// When the global limit is lower, it bounds every scope first.
    #[inline]
    pub const fn max_connections_per_scope(mut self, max: usize) -> Self {
        self.limits.max_connections_per_scope = NonZeroUsize::new(max);
        self
    }

    /// Sets how per-scope connection limits are grouped.
    #[inline]
    pub const fn scope(mut self, scope: PoolLimitScope) -> Self {
        self.limits.scope = scope;
        self
    }

    /// Builds the configured connection limits.
    #[inline]
    pub const fn build(self) -> PoolLimits {
        self.limits
    }
}

impl PoolLimits {
    /// Creates a builder with no connection limits.
    #[inline]
    pub const fn builder() -> PoolLimitsBuilder {
        PoolLimitsBuilder {
            limits: Self {
                max_connections: None,
                max_connections_per_scope: None,
                scope: PoolLimitScope::Origin,
            },
        }
    }

    /// Returns whether neither a global nor per-scope limit is configured.
    #[inline]
    pub(crate) const fn is_unlimited(self) -> bool {
        self.max_connections.is_none() && self.max_connections_per_scope.is_none()
    }
}
