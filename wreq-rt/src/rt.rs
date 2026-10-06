//! Runtime components — executor and timer implementations.
//!
//! Selects between tokio (`tokio-rt` feature) and compio (`compio` feature)
//! runtime backends.

#[cfg(feature = "compio-rt")]
pub mod compio;

#[cfg(feature = "tokio-rt")]
pub mod tokio;
