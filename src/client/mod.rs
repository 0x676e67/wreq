pub use self::{
    body::Body,
    config::{Http1Config, Http2Config},
    emulation::{EmulationProvider, EmulationProviderFactory},
    http::{Client, ClientBuilder, ClientUpdate},
    request::{Request, RequestBuilder},
    response::Response,
    upgrade::Upgraded,
};

pub mod body;
mod config;
pub mod decoder;
pub mod emulation;
pub mod http;
#[cfg(feature = "multipart")]
pub mod multipart;
pub(crate) mod request;
mod response;
mod upgrade;
#[cfg(feature = "websocket")]
pub mod websocket;
