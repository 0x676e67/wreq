//! HTTP Client implementation and lower-level connection management.

mod bounds;
mod dispatch;
mod pool;
mod proto;
mod service;

pub mod body;
pub mod conn;
pub mod connect;
pub mod options;
pub mod upgrade;

pub(crate) use self::service::{
    ConnectRequest, HttpClient, ResponseFuture,
    error::Error,
    extra::{ConnectExtra, Identifier},
};
