//! Core HTTP client protocol and utilities.
//!
//! Much of this codebase is adapted and refined from [hyper](https://github.com/hyperium/hyper),
//! aiming to match its performance and reliability for asynchronous HTTP/1 and HTTP/2.

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
