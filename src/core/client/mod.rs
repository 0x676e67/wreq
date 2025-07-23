//! HTTP Client implementation and lower-level connection management.

mod pool;
mod service;

pub(super) mod dispatch;

pub mod conn;
pub mod connect;
pub mod options;

pub(crate) use service::meta::{ConnectRequest, Extra, Identifier};
pub use service::{HttpClient, ResponseFuture, error::Error};
