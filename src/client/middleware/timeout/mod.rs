//! Middleware for setting a timeout on the response.

mod body;
mod future;
mod layer;

pub use self::{
    body::TimeoutBody,
    layer::{ResponseBodyTimeout, ResponseBodyTimeoutLayer, Timeout, TimeoutLayer},
};
