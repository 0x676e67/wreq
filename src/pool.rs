//! Configures connection reuse and physical connection limits.
//!
//! These policies are applied by `ClientBuilder` and shared by every mapped
//! connection group owned by the client.

use std::{num::NonZeroUsize, time::Duration};

/// Selects when the pool starts a new connection after a reuse miss.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolStrategy {
    /// Immediately races connection reuse against a new connection.
    #[default]
    Race,
    /// Waits up to this duration for reuse before starting a new connection.
    ReuseFirst(Duration),
}

/// Selects how per-scope connection limits are grouped.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolLimitScope {
    /// Groups connections by URI origin.
    #[default]
    Origin,
    /// Groups connections by URI origin and requested protocol mode.
    OriginAndProtocol,
    /// Uses the complete connection compatibility group.
    Group,
}

/// Connection limits applied by the pool.
///
/// Limits include connections being established, in use, and idle.
///
/// A value of `0` removes the corresponding limit.
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

/// Builder for [`PoolLimits`].
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
