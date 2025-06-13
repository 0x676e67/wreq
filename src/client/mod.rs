pub use self::{
    body::Body,
    client::{Client, ClientBuilder},
    emulation::{EmulationProvider, EmulationProviderFactory},
    request::{Request, RequestBuilder},
    response::Response,
    upgrade::Upgraded,
};

pub mod body;
#[allow(clippy::module_inception)]
mod client;
pub mod decoder;
mod emulation;
pub(crate) mod middleware;
#[cfg(feature = "multipart")]
pub mod multipart;
pub(crate) mod request;
mod response;
mod upgrade;
#[cfg(feature = "websocket")]
pub mod websocket;
