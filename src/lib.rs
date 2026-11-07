#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # wreq
//!
//! An ergonomic and modular Rust HTTP Client for high-fidelity protocol matching, featuring
//! customizable TLS, JA3/JA4, and HTTP/2 signature capabilities.
//!
//! - Plain bodies, [JSON](#json), [urlencoded](#forms), [multipart]
//! - HTTP Trailer
//! - Cookie Store
//! - [Redirect Policy](#redirect-policies)
//! - Original Header
//! - Rotating [Proxies](#proxies)
//! - [Tower](https://docs.rs/tower/latest/tower) Middleware
//! - [WebSocket](#websocket) Upgrade
//! - HTTPS via [BoringSSL](#tls)
//! - HTTP/2 over TLS Parity
//! - [Certificate Store (CAs & mTLS)](#certificate-store)
//!
//! Additional learning resources include:
//!
//! - [The Rust Cookbook](https://doc.rust-lang.org/stable/book/ch00-00-introduction.html)
//! - [Repository Examples](https://github.com/0x676e67/wreq/tree/main/examples)
//!
//! Construct a client with an explicit runtime, using `Client::builder(runtime)`
//! or `Client::builder_tokio()` / `Client::builder_compio()`. HTTP/3 needs a runtime
//! with UDP socket support: Tokio provides it, while Compio supports HTTP/1 and HTTP/2.
//!
//! ## Making a GET request
//!
//! ```rust
//! # #[cfg(feature = "tokio-rt")] {
//! use std::time::Duration;
//!
//! use wreq::{Client, rt::tokio::TokioRuntime};
//!
//! # async fn run() -> wreq::Result<()> {
//! let client = Client::new(TokioRuntime);
//! let body = client
//!     .get("https://www.rust-lang.org")
//!     .timeout(Duration::from_secs(30))
//!     .send()
//!     .await?
//!     .text()
//!     .await?;
//!
//! println!("body = {:?}", body);
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Reuse the [`Client`][client] for later requests to take advantage of
//! keep-alive connection pooling.
//!
//! ## Making POST requests (or setting request bodies)
//!
//! There are several ways you can set the body of a request. The basic one is
//! by using the `body()` method of a [`RequestBuilder`][builder]. This lets you set the
//! exact raw bytes of what the body should be. It accepts various types,
//! including `String` and `Vec<u8>`. If you wish to pass a custom
//! type, you can use the `wreq::Body` constructors.
//!
//! ```rust
//! # #[cfg(feature = "tokio-rt")] {
//! use wreq::{Client, rt::tokio::TokioRuntime};
//!
//! # use wreq::Error;
//! #
//! # async fn run() -> Result<(), Error> {
//! let client = Client::new(TokioRuntime);
//! let res = client
//!     .post("http://httpbin.org/post")
//!     .body("the exact body that is sent")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ### Forms
//!
//! It's very common to want to send form data in a request body. This can be
//! done with any type that can be serialized into form data.
//!
//! This can be an array of tuples, or a `HashMap`, or a custom type that
//! implements [`Serialize`][serde].
//!
//! The feature `form` is required.
//!
//! ```rust
//! # #[cfg(feature = "tokio-rt")] {
//! use wreq::{Client, rt::tokio::TokioRuntime};
//!
//! # use wreq::Error;
//! # #[cfg(feature = "form")]
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `foo=bar&baz=quux`
//! let params = [("foo", "bar"), ("baz", "quux")];
//! let client = Client::new(TokioRuntime);
//! let res = client
//!     .post("http://httpbin.org/post")
//!     .form(&params)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ### JSON
//!
//! There is also a `json` method helper on the [`RequestBuilder`][builder] that works in
//! a similar fashion the `form` method. It can take any value that can be
//! serialized into JSON. The feature `json` is required.
//!
//! ```rust
//! # #[cfg(feature = "tokio-rt")] {
//! use wreq::{Client, rt::tokio::TokioRuntime};
//!
//! # use wreq::Error;
//! # use std::collections::HashMap;
//! #
//! # #[cfg(feature = "json")]
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `{"lang":"rust","body":"json"}`
//! let mut map = HashMap::new();
//! map.insert("lang", "rust");
//! map.insert("body", "json");
//!
//! let client = Client::new(TokioRuntime);
//! let res = client
//!     .post("http://httpbin.org/post")
//!     .json(&map)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Websocket
//!
//! The `websocket` module provides a way to upgrade a connection to a websocket.
//! The `ws` feature is required.
//!
//! ```rust,no_run
//! use std::time::Duration;
//!
//! use http::Version;
//! # #[cfg(feature = "tokio-rt")]
//! use wreq::{Client, rt::tokio::TokioRuntime};
//!
//! # #[cfg(feature = "ws")]
//! use futures_util::{SinkExt, StreamExt, TryStreamExt};
//! # #[cfg(feature = "ws")]
//! use wreq::{header, ws::message::Message};
//!
//! # #[cfg(all(feature = "ws", feature = "tokio-rt"))]
//! #[tokio::main]
//! async fn main() -> wreq::Result<()> {
//!     let websocket = Client::builder(TokioRuntime)
//!         .connect_timeout(Duration::from_secs(10))
//!         .build()?
//!         .websocket("wss://echo.websocket.org")
//!         .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
//!         .send()
//!         .await?;
//!
//!     assert_eq!(websocket.version(), Version::HTTP_11);
//!
//!     let (mut tx, mut rx) = websocket.into_websocket().await?.split();
//!
//!     tokio::spawn(async move {
//!         for i in 1..11 {
//!             if let Err(err) = tx.send(Message::text(format!("Hello, World! {i}"))).await {
//!                 eprintln!("failed to send message: {err}");
//!             }
//!         }
//!     });
//!
//!     while let Some(message) = rx.try_next().await? {
//!         if let Message::Text(text) = message {
//!             println!("received: {text}");
//!         }
//!     }
//!
//!     Ok(())
//! }
//! # #[cfg(not(all(feature = "ws", feature = "tokio-rt")))]
//! # fn main() {}
//! ```
//!
//! ## Redirect Policies
//!
//! By default, the client does not handle HTTP redirects.
//! To customize this behavior, you can use [`redirect::Policy`][redirect] with ClientBuilder.
//!
//! ## Cookies
//!
//! The automatic storing and sending of session cookies can be enabled with
//! the [`cookie_store`][ClientBuilder::cookie_store] method on `ClientBuilder`.
//!
//! ## Proxies
//!
//! **NOTE**: System proxies are enabled by default.
//!
//! System proxies look in environment variables to set HTTP or HTTPS proxies.
//!
//! `HTTP_PROXY` or `http_proxy` provide HTTP proxies for HTTP connections while
//! `HTTPS_PROXY` or `https_proxy` provide HTTPS proxies for HTTPS connections.
//! `ALL_PROXY` or `all_proxy` provide proxies for both HTTP and HTTPS connections.
//! If both the all proxy and HTTP or HTTPS proxy variables are set the more specific
//! HTTP or HTTPS proxies take precedence.
//!
//! These can be overwritten by adding a [`Proxy`] to `ClientBuilder`
//! i.e. `let proxy = wreq::Proxy::http("https://secure.example")?;`
//! or disabled by calling `ClientBuilder::no_proxy()`.
//!
//! `socks` feature is required if you have configured socks proxy like this:
//!
//! ```bash
//! export https_proxy=socks5://127.0.0.1:1086
//! ```
//!
//! * `http://` is the scheme for http proxy
//! * `https://` is the scheme for https proxy
//! * `socks4://` is the scheme for socks4 proxy
//! * `socks4a://` is the scheme for socks4a proxy
//! * `socks5://` is the scheme for socks5 proxy
//! * `socks5h://` is the scheme for socks5h proxy
//! * `quic://` is the scheme for an HTTP/3 MASQUE proxy (requires `http3`)
//!  
//! ## TLS
//!
//! By default, clients will utilize BoringSSL transport layer security to connect to HTTPS targets.
//!
//! - Various parts of TLS can also be configured or even disabled on the `ClientBuilder`.
//! - These settings also apply to `https://` and `quic://` proxies.
//!
//! ## Certificate Store
//!
//! By default, wreq uses static Mozilla root certificates. The `chromium-roots`
//! feature can be used alone or combined with it; certificates shared by both bundles are loaded
//! once. Bundled roots ignore certificates installed on the host and update only with their
//! dependencies. Chromium-specific root metadata constraints are not applied. Disable both root
//! features to use BoringSSL's default verification paths, or provide a custom certificate store.
//!
//! Custom Certificate Store verification supports Root CA certificates, peer certificates, and
//! self-signed certificate SSL pinning.
//!
//! ## Optional Features
//!
//! The following are a list of [Cargo features][cargo-features] that can be
//! enabled or disabled:
//!
//! - **tokio-rt** *(enabled by default)*: Provides the Tokio runtime adapter.
//! - **compio-rt**: Provides the Compio runtime adapter for HTTP/1 and HTTP/2.
//! - **http2** *(enabled by default)*: Enables HTTP/2.
//! - **http3**: Enables HTTP/3 over QUIC with a runtime that supports it.
//! - **cookies**: Provides cookie session support.
//! - **gzip**: Provides response body gzip decompression.
//! - **brotli**: Provides response body brotli decompression.
//! - **zstd**: Provides response body zstd decompression.
//! - **deflate**: Provides response body deflate decompression.
//! - **query**: Provides query parameter serialization.
//! - **form**: Provides form data serialization.
//! - **json**: Provides serialization and deserialization for JSON bodies.
//! - **multipart**: Provides functionality for multipart forms.
//! - **charset**: Improved support for decoding text.
//! - **stream**: Adds support for `futures::Stream`.
//! - **socks**: Provides SOCKS5 and SOCKS4 proxy support.
//! - **ws**: Provides websocket support.
//! - **hickory-dns**: Uses the Hickory DNS resolver for the Tokio runtime. Requires `tokio-rt` and
//!   has no effect with `compio-rt`.
//! - **chromium-roots**: Loads static Chromium Root Store certificates.
//! - **webpki-roots** *(enabled by default)*: Loads static Mozilla root certificates.
//! - **system-proxy**: Enable system proxy support.
//! - **tracing**: Enable tracing logging support.
//! - **parking_lot**: Uses `parking_lot` for internal locks.
//! - **prefix-symbols**: Prefix BoringSSL symbols to avoid OpenSSL conflicts.
//!
//! [client]: ./struct.Client.html
//! [response]: ./struct.Response.html
//! [builder]: ./struct.RequestBuilder.html
//! [serde]: http://serde.rs
//! [redirect]: crate::redirect
//! [Proxy]: ./struct.Proxy.html
//! [cargo-features]: https://doc.rust-lang.org/stable/cargo/reference/manifest.html#the-features-section

#[macro_use]
mod trace;
#[macro_use]
mod ext;
#[macro_use]
mod config;
mod client;
mod conn;
mod error;
mod group;
mod into_uri;
mod proto;
mod proxy;
pub mod rt;
mod sync;
mod util;

#[cfg(feature = "cookies")]
pub mod cookie;
pub mod dns;
pub mod header;
pub mod redirect;
pub mod retry;
pub mod tls;

#[cfg(feature = "multipart")]
pub use self::client::multipart;
#[cfg(feature = "ws")]
pub use self::client::ws;
pub(crate) use self::proto::Protocol;
pub use self::{
    client::{
        Client, ClientBuilder,
        body::Body,
        emulate::{Emulation, EmulationBuilder, IntoEmulation, ProtocolConfig},
        pool::PoolStrategy,
        request::{Request, RequestBuilder},
        response::Response,
        upgrade::Upgraded,
    },
    error::{Error, Result},
    ext::{ResponseBuilderExt, ResponseExt},
    group::Group,
    into_uri::IntoUri,
    proxy::{NoProxy, Proxy},
};

pub mod http1 {
    //! HTTP/1 protocol implementation and utilities.

    pub use netty::http1::{Http1Options, Http1OptionsBuilder};
}

#[cfg(feature = "http2")]
#[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
pub mod http2 {
    //! HTTP/2 protocol implementation and utilities.

    pub use netty::http2::{
        HeadersDependency, HeadersPriority, Http2Options, Http2OptionsBuilder, Priorities,
        PrioritiesBuilder, Priority, PseudoId, PseudoOrder, Setting, SettingId, SettingsOrder,
        SettingsOrderBuilder, StreamDependency, StreamId,
    };
}

#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
pub mod http3 {
    //! HTTP/3 protocol options and utilities.

    pub use netty::http3::{
        Http3Options, Http3OptionsBuilder, Protocol, PseudoId, PseudoOrder, PseudoOrderBuilder,
        SettingId, SettingsOrder, SettingsOrderBuilder,
    };
}

#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
pub mod quic;

pub use http::{Method, StatusCode, Uri, Version};
#[cfg(unix)]
use libc as _;

fn _assert_impls() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_clone<T: Clone>() {}

    assert_send::<Client>();
    assert_sync::<Client>();
    assert_clone::<Client>();

    assert_send::<Request>();
    assert_send::<RequestBuilder>();
    #[cfg(feature = "ws")]
    assert_send::<ws::WebSocketRequestBuilder>();

    assert_send::<Response>();
    #[cfg(feature = "ws")]
    assert_send::<ws::WebSocketResponse>();
    #[cfg(feature = "ws")]
    assert_send::<ws::WebSocket>();

    assert_send::<Error>();
    assert_sync::<Error>();
}
