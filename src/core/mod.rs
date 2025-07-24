//! http client protocol implementation and low level utilities.

mod common;
mod error;

pub mod client;
pub mod ext;
pub mod rt;

pub use self::error::{Error, Result};
