mod case;
mod client;
mod runner;
mod runtime;
mod server;

pub use case::{BenchTarget, HttpVersion, ThreadMode, Tls};
pub(crate) use case::{BodyCase, BodyKind};
pub use runner::{bench, criterion};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub const NUM_REQUESTS: usize = 600;
