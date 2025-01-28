#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, deny(warnings))]

//! # rquest
//!
//! An ergonomic, all-in-one `TLS`, `JA3`/`JA4`, and `HTTP2` fingerprint `HTTP` Client  for spoofing any browser.
//!
//! - Plain bodies, [JSON](#json), [urlencoded](#forms), [multipart], [websocket](#websocket)
//! - Header Order
//! - Cookies Store
//! - [Redirect policy](#redirect-policies)
//! - Uses [BoringSSL](#tls)
//! - HTTP [Proxies](#proxies)
//! - Perfectly impersonate Chrome, Safari, and Firefox
//! - [Changelog](https://github.com/0x676e67/rquest/blob/main/CHANGELOG.md)
//!
//! Additional learning resources include:
//!
//! - [The Rust Cookbook](https://doc.rust-lang.org/stable/book/ch00-00-introduction.html)
//! - [Repository Examples](https://github.com/0x676e67/rquest/tree/main/examples)
//!
//! ## Impersonate
//!
//! The `impersonate` module provides a way to simulate various browser fingerprints.
//!
//! ```rust,no_run
//! use rquest::{Client, Impersonate};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), rquest::Error> {
//!     // Build a client to impersonate Firefox133
//!     let client = Client::builder()
//!         .impersonate(Impersonate::Firefox133)
//!         .build()?;
//!
//!     // Use the API you're already familiar with
//!     let resp = client.get("https://tls.peet.ws/api/all").send().await?;
//!     println!("{}", resp.text().await?);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Websocket
//!
//! The `websocket` module provides a way to upgrade a connection to a websocket.
//!
//! ```rust,no_run
//! use futures_util::{SinkExt, StreamExt, TryStreamExt};
//! use rquest::{Impersonate, Client, Message};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), rquest::Error> {
//!     // Build a client to impersonate Firefox133
//!     let websocket = Client::builder()
//!         .impersonate(Impersonate::Firefox133)
//!         .build()?
//!         .websocket("wss://echo.websocket.org")
//!         .send()
//!         .await?
//!         .into_websocket()
//!         .await?;
//!
//!     let (mut tx, mut rx) = websocket.split();
//!
//!     tokio::spawn(async move {
//!         for i in 1..11 {
//!             tx.send(Message::Text(format!("Hello, World! #{i}")))
//!                 .await
//!                 .unwrap();
//!         }
//!     });
//!
//!     while let Some(message) = rx.try_next().await? {
//!         match message {
//!             Message::Text(text) => println!("received: {text}"),
//!             _ => {}
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Making a GET request
//!
//! For a single request, you can use the [`get`][get] shortcut method.
//!
//! ```rust
//! # async fn run() -> Result<(), rquest::Error> {
//! let body = rquest::get("https://www.rust-lang.org")
//!     .await?
//!     .text()
//!     .await?;
//!
//! println!("body = {:?}", body);
//! # Ok(())
//! # }
//! ```
//!
//! **NOTE**: If you plan to perform multiple requests, it is best to create a
//! [`Client`][client] and reuse it, taking advantage of keep-alive connection
//! pooling.
//!
//! ## Making POST requests (or setting request bodies)
//!
//! There are several ways you can set the body of a request. The basic one is
//! by using the `body()` method of a [`RequestBuilder`][builder]. This lets you set the
//! exact raw bytes of what the body should be. It accepts various types,
//! including `String` and `Vec<u8>`. If you wish to pass a custom
//! type, you can use the `rquest::Body` constructors.
//!
//! ```rust
//! # use rquest::Error;
//! #
//! # async fn run() -> Result<(), Error> {
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .body("the exact body that is sent")
//!     .send()
//!     .await?;
//! # Ok(())
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
//! ```rust
//! # use rquest::Error;
//! #
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `foo=bar&baz=quux`
//! let params = [("foo", "bar"), ("baz", "quux")];
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .form(&params)
//!     .send()
//!     .await?;
//! # Ok(())
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
//! # use rquest::Error;
//! # use std::collections::HashMap;
//! #
//! # #[cfg(feature = "json")]
//! # async fn run() -> Result<(), Error> {
//! // This will POST a body of `{"lang":"rust","body":"json"}`
//! let mut map = HashMap::new();
//! map.insert("lang", "rust");
//! map.insert("body", "json");
//!
//! let client = rquest::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .json(&map)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
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
//! i.e. `let proxy = rquest::Proxy::http("https://secure.example")?;`
//! or disabled by calling `ClientBuilder::no_proxy()`.
//!
//! `socks` feature is required if you have configured socks proxy like this:
//!
//! ```bash
//! export https_proxy=socks5://127.0.0.1:1086
//! ```
//! ## TLS
//!
//! By default, clients will utilize BoringSSL transport layer security to connect to HTTPS targets.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.
//!
//! ## Optional Features
//!
//! The following are a list of [Cargo features][cargo-features] that can be
//! enabled or disabled:
//!
//! - **websocket**: Provides websocket support.
//! - **cookies**: Provides cookie session support.
//! - **gzip**: Provides response body gzip decompression.
//! - **brotli**: Provides response body brotli decompression.
//! - **zstd**: Provides response body zstd decompression.
//! - **deflate**: Provides response body deflate decompression.
//! - **json**: Provides serialization and deserialization for JSON bodies.
//! - **multipart**: Provides functionality for multipart forms.
//! - **stream**: Adds support for `futures::Stream`.
//! - **socks**: Provides SOCKS5 proxy support.
//! - **hickory-dns**: Enables a hickory-dns async resolver instead of default
//!   threadpool using `getaddrinfo`.
//!
//! [hyper]: http://hyper.rs
//! [client]: ./struct.Client.html
//! [response]: ./struct.Response.html
//! [get]: ./fn.get.html
//! [builder]: ./struct.RequestBuilder.html
//! [serde]: http://serde.rs
//! [redirect]: crate::redirect
//! [Proxy]: ./struct.Proxy.html
//! [preconfigured]: ./struct.ClientBuilder.html#method.use_preconfigured_tls
//! [cargo-features]: https://doc.rust-lang.org/stable/cargo/reference/manifest.html#the-features-section

#[cfg(feature = "hickory-dns")]
pub use hickory_resolver;
pub use http::header;
pub use http::Method;
pub use http::{StatusCode, Version};
pub use url::Url;

// universal mods
#[macro_use]
mod error;
mod into_url;
mod response;

pub use self::error::{Error, Result};
pub use self::into_url::IntoUrl;
pub use self::response::ResponseBuilderExt;

/// Macro to implement Debug for a type, skipping certain fields.
#[macro_export]
macro_rules! impl_debug {
    ($type:ty, { $($field_name:ident),* }) => {
        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut debug_struct = f.debug_struct(stringify!($type));
                $(
                    debug_struct.field(stringify!($field_name), &self.$field_name);
                )*
                debug_struct.finish()
            }
        }
    }
}

/// Macro to conditionally compile code for bindable devices.
#[macro_export]
macro_rules! cfg_bindable_device {
    ($($tt:tt)*) => {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        ))]
        $(
            $tt
        )*
    };
}

/// Macro to conditionally compile code for non-bindable devices.
#[macro_export]
macro_rules! cfg_non_bindable_device {
    ($($tt:tt)*) => {
        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        )))]
        $(
            $tt
        )*
    }
}

/// Shortcut method to quickly make a `GET` request.
///
/// See also the methods on the [`rquest::Response`](./struct.Response.html)
/// type.
///
/// **NOTE**: This function creates a new internal `Client` on each call,
/// and so should not be used if making many requests. Create a
/// [`Client`](./struct.Client.html) instead.
///
/// # Examples
///
/// ```rust
/// # async fn run() -> Result<(), rquest::Error> {
/// let body = rquest::get("https://www.rust-lang.org").await?
///     .text().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// This function fails if:
///
/// - native TLS backend cannot be initialized
/// - supplied `Url` cannot be parsed
/// - there was an error while sending request
/// - redirect limit was exhausted
pub async fn get<T: IntoUrl>(url: T) -> crate::Result<Response> {
    Client::builder().build()?.get(url).send().await
}

/// Opens a websocket at the specified URL.
///
/// This is a shorthand for creating a request, sending it, and turning the
/// response into a websocket.
#[cfg(feature = "websocket")]
pub async fn websocket<T: IntoUrl>(url: T) -> crate::Result<WebSocket> {
    Client::builder()
        .build()?
        .websocket(url)
        .send()
        .await?
        .into_websocket()
        .await
}

fn _assert_impls() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_clone<T: Clone>() {}

    assert_send::<Client>();
    assert_sync::<Client>();
    assert_clone::<Client>();

    assert_send::<Request>();
    assert_send::<RequestBuilder>();

    assert_send::<Response>();

    assert_send::<Error>();
    assert_sync::<Error>();
}

#[cfg(test)]
doc_comment::doctest!("../README.md");

#[cfg(feature = "multipart")]
pub use self::client::multipart;
#[cfg(feature = "websocket")]
pub use self::client::websocket::{
    CloseCode, CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketRequestBuilder,
    WebSocketResponse,
};
pub use self::client::{
    Body, Client, ClientBuilder, ClientMut, Request, RequestBuilder, Response, Upgraded,
};
pub use self::imp::{Impersonate, ImpersonateBuilder, ImpersonateOS, ImpersonateSettings};
pub use self::proxy::{NoProxy, Proxy};
pub use self::tls::{
    AlpnProtos, AlpsProtos, CertCompressionAlgorithm, RootCertStore, TlsInfo, TlsSettings,
    TlsVersion,
};
pub use self::util::client::{Dst, Http1Builder, Http2Builder};
pub use boring2::{
    ssl::{ExtensionType, SslCurve},
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};
pub use http2::Http2Settings;
pub use hyper2::{Priority, PseudoOrder, SettingsOrder, StreamDependency, StreamId};

mod client;
mod connect;
#[cfg(feature = "cookies")]
pub mod cookie;
pub mod dns;
mod proxy;
pub mod redirect;

mod http2;
mod imp;
mod tls;
mod util;
