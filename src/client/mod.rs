pub use self::body::Body;
pub use self::client::{Client, ClientBuilder};
pub use self::emulation::{EmulationProvider, EmulationProviderFactory};
pub use self::request::{Request, RequestBuilder};
pub use self::response::Response;
pub use self::upgrade::Upgraded;

pub mod body;
#[allow(clippy::module_inception)]
mod client;
pub mod decoder;
mod emulation;
mod middleware;
#[cfg(feature = "multipart")]
pub mod multipart;
pub(crate) mod request;
mod response;
mod upgrade;
#[cfg(feature = "websocket")]
pub mod websocket;
