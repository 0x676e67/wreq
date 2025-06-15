//! Middleware for the client.

#[cfg(feature = "cookies")]
pub mod cookie;
#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
pub mod decoder;
pub mod redirect;
pub mod retry;
pub mod timeout;
