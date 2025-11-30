mod body;
mod core;
mod emulation;
mod http;
mod request;
mod response;

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
pub(crate) use self::{
    core::{Error as CoreError, connect, ext},
    http::{ConnectRequest, Identifier, client::error::Error},
};
