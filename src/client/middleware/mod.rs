//! Middleware for the client.

#[cfg(feature = "cookies")]
pub mod cookie;
pub mod redirect;
pub mod timeout;
