//! WebSocket Upgrade

#[cfg(feature = "json")]
mod json;
mod message;

use std::{
    borrow::Cow,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version, header, uri::Scheme};
pub use message::{CloseCode, CloseFrame, Message, Utf8Bytes};
use serde::Serialize;
use tokio_tungstenite::tungstenite::{self, protocol};
use tungstenite::protocol::WebSocketConfig;

use crate::{
    Error, OriginalHeaders, RequestBuilder, Response, core::ext::Protocol, error, proxy::Proxy,
};

/// A WebSocket stream.
type WebSocketStream = tokio_tungstenite::WebSocketStream<crate::Upgraded>;

/// Wrapper for [`RequestBuilder`] that performs the
/// websocket handshake when sent.
#[derive(Debug)]
pub struct WebSocketRequestBuilder {
    inner: RequestBuilder,
    accept_key: Option<Cow<'static, str>>,
    protocols: Option<Vec<Cow<'static, str>>>,
    config: WebSocketConfig,
}

impl WebSocketRequestBuilder {
    /// Creates a new WebSocket request builder.
    pub fn new(inner: RequestBuilder) -> Self {
        Self {
            inner,
            accept_key: None,
            protocols: None,
            config: WebSocketConfig::default(),
        }
    }

    /// Sets a custom WebSocket accept key.
    ///
    /// This method allows you to set a custom WebSocket accept key for the connection.
    ///
    /// # Arguments
    ///
    /// * `key` - The custom WebSocket accept key to set.
    ///
    /// # Returns
    ///
    /// * `Self` - The modified instance with the custom WebSocket accept key.
    pub fn accept_key<K>(mut self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        self.accept_key = Some(key.into());
        self
    }

    /// Sets the websocket subprotocols to request.
    ///
    /// This method allows you to specify the subprotocols that the websocket client
    /// should request during the handshake. Subprotocols are used to define the type
    /// of communication expected over the websocket connection.
    ///
    /// # Arguments
    ///
    /// * `protocols` - A list of subprotocols, which can be converted into a `Cow<'static,
    ///   [String]>`.
    ///
    /// # Returns
    ///
    /// * `Self` - The modified instance with the updated subprotocols.
    ///
    /// # Example
    ///
    /// ```
    /// let request = WebSocketRequestBuilder::new(builder)
    ///     .protocols(["protocol1", "protocol2"])
    ///     .build();
    /// ```
    pub fn protocols<P>(mut self, protocols: P) -> Self
    where
        P: IntoIterator,
        P::Item: Into<Cow<'static, str>>,
    {
        let protocols = protocols.into_iter().map(Into::into).collect();
        self.protocols = Some(protocols);
        self
    }

    /// Sets the websocket max_frame_size configuration.
    pub fn max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.config.max_frame_size = Some(max_frame_size);
        self
    }

    /// Sets the websocket read_buffer_size configuration.
    pub fn read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.config.read_buffer_size = read_buffer_size;
        self
    }

    /// Sets the websocket write_buffer_size configuration.
    pub fn write_buffer_size(mut self, write_buffer_size: usize) -> Self {
        self.config.write_buffer_size = write_buffer_size;
        self
    }

    /// Sets the websocket max_write_buffer_size configuration.
    pub fn max_write_buffer_size(mut self, max_write_buffer_size: usize) -> Self {
        self.config.max_write_buffer_size = max_write_buffer_size;
        self
    }

    /// Sets the websocket max_message_size configuration.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.max_message_size = Some(max_message_size);
        self
    }

    /// Sets the websocket accept_unmasked_frames configuration.
    pub fn accept_unmasked_frames(mut self, accept_unmasked_frames: bool) -> Self {
        self.config.accept_unmasked_frames = accept_unmasked_frames;
        self
    }

    /// Configures the WebSocket connection to use HTTP/2.
    ///
    /// This method sets the HTTP version to HTTP/2 for the WebSocket connection.
    /// If the server does not support HTTP/2 WebSocket connections, the connection attempt will
    /// fail.
    ///
    /// # Returns
    ///
    /// * `Self` - The modified instance with the HTTP version set to HTTP/2.
    pub fn use_http2(mut self) -> Self {
        self.inner = self.inner.version(Version::HTTP_2);
        self
    }

    /// Add a `Header` to this Request.
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header(key, value);
        self
    }

    /// Add a `Header` to append to the request.
    pub fn header_append<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header_append(key, value);
        self
    }

    /// Add a set of Headers to the existing ones on this Request.
    ///
    /// The headers will be merged in to any already set.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    /// Set the original headers for this request.
    pub fn original_headers(mut self, original_headers: OriginalHeaders) -> Self {
        self.inner = self.inner.original_headers(original_headers);
        self
    }

    /// Enable HTTP authentication.
    pub fn auth<V>(mut self, value: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.auth(value);
        self
    }

    /// Enable HTTP basic authentication.
    pub fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: fmt::Display,
        P: fmt::Display,
    {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(mut self, token: T) -> Self
    where
        T: fmt::Display,
    {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    /// Modify the query string of the URL.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        self.inner = self.inner.query(query);
        self
    }

    /// Set the proxy for this request.
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.inner = self.inner.proxy(proxy);
        self
    }

    /// Set the local address for this request.
    pub fn local_address<V>(mut self, local_address: V) -> Self
    where
        V: Into<Option<IpAddr>>,
    {
        self.inner = self.inner.local_address(local_address);
        self
    }

    /// Set the local addresses for this request.
    pub fn local_addresses<V4, V6>(mut self, ipv4: V4, ipv6: V6) -> Self
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        self.inner = self.inner.local_addresses(ipv4, ipv6);
        self
    }

    /// Set the interface for this request.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        )))
    )]
    pub fn interface<I>(mut self, interface: I) -> Self
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        self.inner = self.inner.interface(interface);
        self
    }

    /// Sends the request and returns and [`WebSocketResponse`].
    pub async fn send(self) -> Result<WebSocketResponse, Error> {
        let (client, request) = self.inner.build_split();
        let mut request = request?;

        // Ensure the scheme is http or https
        let url = request.url_mut();
        let new_scheme = match url.scheme() {
            "ws" => Scheme::HTTP,
            "wss" => Scheme::HTTPS,
            _ => {
                return Err(error::url_bad_scheme(url.clone()));
            }
        };

        // Update the scheme
        url.set_scheme(new_scheme.as_str())
            .map_err(|_| error::url_bad_scheme(url.clone()))?;

        // Get the version of the request
        // If the version is not set, use the default version
        let version = request.version().cloned().unwrap_or(Version::HTTP_11);

        // Set the headers for the websocket handshake
        let headers = request.headers_mut();
        headers.insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );

        // Ensure the request is HTTP 1.1/HTTP 2
        let accept_key = match version {
            Version::HTTP_10 | Version::HTTP_11 => {
                // Generate a nonce if one wasn't provided
                let nonce = self
                    .accept_key
                    .unwrap_or_else(|| Cow::Owned(tungstenite::handshake::client::generate_key()));

                headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                headers.insert(header::SEC_WEBSOCKET_KEY, HeaderValue::from_str(&nonce)?);

                *request.method_mut() = Method::GET;
                *request.version_mut() = Some(Version::HTTP_11);
                Some(nonce)
            }
            Version::HTTP_2 => {
                *request.method_mut() = Method::CONNECT;
                *request.version_mut() = Some(Version::HTTP_2);
                request
                    .extensions_mut()
                    .insert(Protocol::from_static("websocket"));
                None
            }
            _ => {
                return Err(error::upgrade(format!(
                    "unsupported version: {:?}",
                    version
                )));
            }
        };

        // Set websocket subprotocols
        if let Some(ref protocols) = self.protocols {
            // Sets subprotocols
            if !protocols.is_empty() {
                let subprotocols = protocols
                    .iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<&str>>()
                    .join(", ");

                request
                    .headers_mut()
                    .insert(header::SEC_WEBSOCKET_PROTOCOL, subprotocols.parse()?);
            }
        }

        client
            .execute(request)
            .await
            .map(|inner| WebSocketResponse {
                inner,
                accept_key,
                protocols: self.protocols,
                config: self.config,
                version,
            })
    }
}

/// The server's response to the websocket upgrade request.
///
/// This implements `Deref<Target = Response>`, so you can access all the usual
/// information from the [`Response`].
#[derive(Debug)]
pub struct WebSocketResponse {
    inner: Response,
    accept_key: Option<Cow<'static, str>>,
    protocols: Option<Vec<Cow<'static, str>>>,
    config: WebSocketConfig,
    version: Version,
}

impl Deref for WebSocketResponse {
    type Target = Response;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for WebSocketResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl WebSocketResponse {
    /// Turns the response into a websocket. This checks if the websocket
    /// handshake was successful.
    pub async fn into_websocket(self) -> Result<WebSocket, Error> {
        let (inner, protocol) = {
            let status = self.inner.status();
            let headers = self.inner.headers();

            if !matches!(
                self.inner.version(),
                Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
            ) {
                return Err(error::upgrade(format!(
                    "unexpected version: {:?}",
                    self.inner.version()
                )));
            }

            match self.version {
                Version::HTTP_10 | Version::HTTP_11 => {
                    if status != StatusCode::SWITCHING_PROTOCOLS {
                        let body = self.inner.text().await?;
                        return Err(error::upgrade(format!("unexpected status code: {}", body)));
                    }

                    if !header_contains(self.inner.headers(), header::CONNECTION, "upgrade") {
                        return Err(error::upgrade("missing connection header"));
                    }

                    if !header_eq(self.inner.headers(), header::UPGRADE, "websocket") {
                        return Err(error::upgrade("invalid upgrade header"));
                    }

                    match self
                        .accept_key
                        .zip(headers.get(header::SEC_WEBSOCKET_ACCEPT))
                    {
                        Some((nonce, header)) => {
                            if !header.to_str().is_ok_and(|s| {
                                s == tungstenite::handshake::derive_accept_key(nonce.as_bytes())
                            }) {
                                return Err(error::upgrade(format!(
                                    "invalid accept key: {:?}",
                                    header
                                )));
                            }
                        }
                        None => {
                            return Err(error::upgrade("missing accept key"));
                        }
                    }
                }
                Version::HTTP_2 => {
                    if status != StatusCode::OK {
                        return Err(error::upgrade(format!(
                            "unexpected status code: {}",
                            status
                        )));
                    }
                }
                _ => {
                    return Err(error::upgrade(format!(
                        "unsupported version: {:?}",
                        self.version
                    )));
                }
            }

            let protocol = headers.get(header::SEC_WEBSOCKET_PROTOCOL).cloned();

            match (
                self.protocols.as_ref().is_none_or(|p| p.is_empty()),
                &protocol,
            ) {
                (true, None) => {
                    // we didn't request any protocols, so we don't expect one
                    // in return
                }
                (false, None) => {
                    // server didn't reply with a protocol
                    return Err(error::upgrade("missing protocol"));
                }
                (false, Some(protocol)) => {
                    if let Some((protocols, protocol)) = self.protocols.zip(protocol.to_str().ok())
                    {
                        if !protocols.contains(&Cow::Borrowed(protocol)) {
                            // the responded protocol is none which we requested
                            return Err(error::upgrade(format!("invalid protocol: {}", protocol)));
                        }
                    } else {
                        // we didn't request any protocols but got one anyway
                        return Err(error::upgrade("invalid protocol"));
                    }
                }
                (true, Some(_)) => {
                    // we didn't request any protocols but got one anyway
                    return Err(error::upgrade("invalid protocol"));
                }
            }

            let upgraded = self.inner.upgrade().await?;
            let inner = WebSocketStream::from_raw_socket(
                upgraded,
                protocol::Role::Client,
                Some(self.config),
            )
            .await;

            (inner, protocol)
        };

        Ok(WebSocket { inner, protocol })
    }
}

/// Checks if the header value is equal to the given value.
fn header_eq(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    if let Some(header) = headers.get(&key) {
        header.as_bytes().eq_ignore_ascii_case(value.as_bytes())
    } else {
        false
    }
}

/// Checks if the header value contains the given value.
fn header_contains(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    let header = if let Some(header) = headers.get(&key) {
        header
    } else {
        return false;
    };

    if let Ok(header) = std::str::from_utf8(header.as_bytes()) {
        header.to_ascii_lowercase().contains(value)
    } else {
        false
    }
}

/// A websocket connection
#[derive(Debug)]
pub struct WebSocket {
    inner: WebSocketStream,
    protocol: Option<HeaderValue>,
}

impl WebSocket {
    /// Receive another message.
    ///
    /// Returns `None` if the stream has closed.
    pub async fn recv(&mut self) -> Option<Result<Message, Error>> {
        self.next().await
    }

    /// Send a message.
    pub async fn send(&mut self, msg: Message) -> Result<(), Error> {
        self.inner
            .send(msg.into_tungstenite())
            .await
            .map_err(Into::into)
    }

    /// Return the selected WebSocket subprotocol, if one has been chosen.
    pub fn protocol(&self) -> Option<&HeaderValue> {
        self.protocol.as_ref()
    }

    /// Closes the connection with a given code and (optional) reason.
    pub async fn close(self, code: CloseCode, reason: Option<Utf8Bytes>) -> Result<(), Error> {
        let mut inner = self.inner;
        inner
            .close(Some(tungstenite::protocol::CloseFrame {
                code: code.0.into(),
                reason: reason
                    .unwrap_or(Utf8Bytes::from_static("Goodbye"))
                    .into_tungstenite(),
            }))
            .await
            .map_err(Into::into)
    }
}

impl Stream for WebSocket {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(self.inner.poll_next_unpin(cx)) {
                Some(Ok(msg)) => {
                    if let Some(msg) = Message::from_tungstenite(msg) {
                        return Poll::Ready(Some(Ok(msg)));
                    }
                }
                Some(Err(err)) => return Poll::Ready(Some(Err(error::body(err)))),
                None => return Poll::Ready(None),
            }
        }
    }
}

impl Sink<Message> for WebSocket {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(item.into_tungstenite())
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(Into::into)
    }
}
