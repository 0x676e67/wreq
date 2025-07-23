//! HTTP Client implementation and lower-level connection management.

mod pool;
mod service;

pub(super) mod dispatch;

pub mod conn;
pub mod connect;
pub mod options;

pub use self::service::{HttpClient, ResponseFuture, error::Error, ConnectRequest};
pub(crate) use self::service::meta::{ConnectMeta, Identifier};
