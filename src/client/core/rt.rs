//! Runtime components
//!
//! The traits and types within this module are used to allow plugging in
//! runtime types. These include:
//!
//! - Executors
//! - Timers
//! - IO transports

pub mod bounds;
mod timer;
mod tokio;

pub use self::{
    timer::{ArcTimer, Sleep, Time, Timer},
    tokio::{TokioExecutor, TokioTimer},
};

/// An executor of futures.
///
/// This trait allows abstract over async runtimes. Implement this trait for your own type.
pub trait Executor<Fut> {
    /// Place the future into the executor to be run.
    fn execute(&self, fut: Fut);
}
