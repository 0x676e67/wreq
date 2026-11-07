//! Connection middleware shared by the client's transport stacks.
//!
//! [`proxy`] selects stream routes, establishes proxy tunnels for TCP, Unix and QUIC
//! connections, and finishes target TLS on streams. [`timeout`] bounds one connector call,
//! including user middleware and proxy setup.

pub(crate) mod proxy;
pub(crate) mod timeout;
