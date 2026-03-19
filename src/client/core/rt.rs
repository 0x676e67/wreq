//! Runtime components
//!
//! The traits and types within this module are used to allow plugging in
//! runtime types. These include:
//!
//! - Executors
//! - Timers
//! - IO transports

pub mod bounds;
#[cfg(feature = "compio")]
mod compio;
mod timer;
#[cfg(feature = "tokio")]
mod tokio;

<<<<<<< HEAD
#[cfg(feature = "compio")]
pub use {
    self::compio::{CompioExecutor, CompioIO, CompioTimer},
    ::compio::io::{AsyncRead, AsyncWrite},
=======
pub use self::{
    timer::{Sleep, Time, Timer},
    tokio::{TokioExecutor, TokioTimer},
>>>>>>> rt
};
#[cfg(feature = "tokio")]
pub use {
    self::tokio::{TokioExecutor, TokioTimer},
    ::tokio::io::{AsyncRead, AsyncWrite},
};

pub use self::timer::{Sleep, Time, Timer};

/// An executor of futures.
///
/// This trait allows abstract over async runtimes. Implement this trait for your own type.
pub trait Executor<Fut> {
    /// Place the future into the executor to be run.
    fn execute(&self, fut: Fut);
}
