pub use self::body::Body;
pub use self::config::{Http1Config, Http2Config};
pub use self::emulation::{EmulationProvider, EmulationProviderFactory};
pub use self::http::{Client, ClientBuilder, ClientMut};
pub use self::request::{Request, RequestBuilder};
pub use self::response::Response;
pub use self::upgrade::Upgraded;

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
