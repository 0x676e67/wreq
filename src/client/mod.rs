mod emulation;
mod http;
mod response;
mod upgrade;

pub(crate) mod layer;
pub(crate) mod request;

pub mod body;
#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

pub use self::{
    body::Body,
    emulation::{Emulation, EmulationFactory},
    http::{Client, ClientBuilder},
    request::{Request, RequestBuilder},
    response::Response,
    upgrade::Upgraded,
};
