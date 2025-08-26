mod emulation;
mod http;

mod request;
mod response;

pub(crate) mod layer;

pub mod body;
#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

pub use self::{
    body::Body,
    emulation::{Emulation, EmulationBuilder, EmulationFactory},
    http::{Client, ClientBuilder},
    request::{Request, RequestBuilder},
    response::Response,
};
pub use crate::core::client::{
    options::{http1, http2},
    upgrade::Upgraded,
};
