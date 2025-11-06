mod emulation;
mod request;
mod response;

pub mod body;
pub mod core;
pub mod http;
pub mod layer;
#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

pub use self::{
    body::Body,
    core::{
        options::{http1, http2},
        upgrade::Upgraded,
    },
    emulation::{Emulation, EmulationBuilder, EmulationFactory},
    http::{Client, ClientBuilder},
    request::{Request, RequestBuilder},
    response::Response,
};
