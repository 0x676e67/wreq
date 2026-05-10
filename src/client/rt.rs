//! Runtime components — executor and timer implementations.
//!
//! At least one of `tokio-rt` or `compio-rt` must be enabled.

// Ensure at least one runtime is selected.
#[cfg(not(any(feature = "tokio-rt", feature = "compio-rt")))]
compile_error!("Either the `tokio-rt` or `compio-rt` feature must be enabled");

/// The executor type for the selected runtime.
/// When both features are enabled, tokio takes precedence.
#[cfg(feature = "tokio-rt")]
pub(super) type RuntimeExecutor = wreq_rt::rt::tokio::TokioExecutor;
#[cfg(all(feature = "compio-rt", not(feature = "tokio-rt")))]
pub(super) type RuntimeExecutor = wreq_rt::rt::compio::CompioExecutor;

/// The timer type for the selected runtime.
/// When both features are enabled, tokio takes precedence.
#[cfg(feature = "tokio-rt")]
pub(super) type RuntimeTimer = wreq_rt::rt::tokio::TokioTimer;
#[cfg(all(feature = "compio-rt", not(feature = "tokio-rt")))]
pub(super) type RuntimeTimer = wreq_rt::rt::compio::CompioTimer;
