mod client;
pub use client::{Builder, Client, Error, ResponseFuture};

pub mod connect;
#[doc(hidden)]
// Publicly available, but just for legacy purposes. A better pool will be
// designed.
pub mod pool;
