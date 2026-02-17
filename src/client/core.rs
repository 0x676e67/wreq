//! HTTP Client protocol implementation and low level utilities.

mod common;
mod error;
mod proto;

pub mod body;
pub mod conn;
pub mod dispatch;
pub mod rt;
pub mod upgrade;

pub use self::{
    error::{Error, Result},
    proto::{http1, http2},
};
