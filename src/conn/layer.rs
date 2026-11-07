//! Connection middleware shared by the client's transport stacks.
//!
//! [`proxy`] selects routes, establishes proxy tunnels and finishes target TLS for TCP and
//! Unix connections. [`timeout`] covers the whole attempt, including user middleware and
//! proxy setup.

pub(crate) mod proxy;
pub(crate) mod timeout;
