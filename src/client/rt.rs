//! Runtime components — executor and timer implementations.
//!
//! At least one of `tokio-rt` or `compio-rt` must be enabled.

// Ensure at least one runtime is selected.
#[cfg(not(any(feature = "tokio-rt", feature = "compio-rt")))]
compile_error!("Either the `tokio-rt` or `compio-rt` feature must be enabled");

#[cfg(feature = "compio-rt")]
mod compio;
#[cfg(feature = "tokio-rt")]
mod tokio;

#[cfg(feature = "compio-rt")]
#[allow(unused_imports)]
pub(crate) use self::compio::{CompioExecutor, CompioTimer};
#[cfg(feature = "tokio-rt")]
pub(crate) use self::tokio::{TokioExecutor, TokioTimer};

/// The default executor type for the selected runtime.
/// When both features are enabled, tokio takes precedence.
#[cfg(feature = "tokio-rt")]
pub(crate) type DefaultExecutor = TokioExecutor;
#[cfg(all(feature = "compio-rt", not(feature = "tokio-rt")))]
pub(crate) type DefaultExecutor = CompioExecutor;

/// The default timer type for the selected runtime.
/// When both features are enabled, tokio takes precedence.
#[cfg(feature = "tokio-rt")]
pub(crate) type DefaultTimer = TokioTimer;
#[cfg(all(feature = "compio-rt", not(feature = "tokio-rt")))]
pub(crate) type DefaultTimer = CompioTimer;
