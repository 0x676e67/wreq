//! HTTP Clientt protocol implementation and low level utilities.

mod dispatch;
mod error;
mod proto;

pub mod body;
pub mod common;
pub mod conn;
pub mod ext;
pub mod http1;
pub mod http2;
pub mod rt;
pub mod upgrade;

pub use self::error::{Error, Result};
