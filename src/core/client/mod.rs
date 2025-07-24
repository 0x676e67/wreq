//! HTTP Client implementation and lower-level connection management.

mod bounds;
mod pool;
mod proto;
mod service;

pub(super) mod dispatch;

pub mod body;
pub mod conn;
pub mod connect;
pub mod options;

pub(crate) use self::service::meta::{ConnectMeta, Identifier};
pub use self::service::{ConnectRequest, HttpClient, ResponseFuture, error::Error};
