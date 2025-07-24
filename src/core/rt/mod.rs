//! Runtime components
//!
//! The traits and types within this module are used to allow plugging in
//! runtime types. These include:
//!
//! - Executors
//! - Timers
//! - IO transports

mod io;
mod timer;
pub mod tokio;

pub(crate) use self::io::{read, write_all};
pub use self::{
    io::{Read, ReadBuf, ReadBufCursor, Write},
    timer::{Sleep, Timer},
    tokio::{TokioExecutor, TokioIo},
};

/// An executor of futures.
///
/// This trait allows abstract over async runtimes. Implement this trait for your own type.
pub trait Executor<Fut> {
    /// Place the future into the executor to be run.
    fn execute(&self, fut: Fut);
}
