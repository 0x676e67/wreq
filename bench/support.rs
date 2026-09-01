//! Shared types and lifecycle helpers for the protocol benchmark targets.

mod case;
mod client;
mod runner;
mod runtime;
mod server;

pub use case::{BenchTarget, HttpVersion, ThreadMode, Tls};
pub(crate) use case::{BodyCase, BodyKind};
pub use runner::{bench, criterion};

/// Error type used while preparing or cleaning up a benchmark case.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Requests completed during one Criterion iteration.
///
/// This divides evenly across every configured concurrency level.
pub const NUM_REQUESTS: usize = 600;
