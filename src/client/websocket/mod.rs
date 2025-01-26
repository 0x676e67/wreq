#[cfg(feature = "json")]
mod json;
mod message;

use std::{
    borrow::Cow,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    error::{self, Kind},
    RequestBuilder,
};
use crate::{Error, Response};
use async_tungstenite::tungstenite::{self, protocol};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::{header, uri::Scheme, HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
pub use message::{CloseCode, Message};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tungstenite::protocol::WebSocketConfig;

pub type WebSocketStream =
    async_tungstenite::WebSocketStream<tokio_util::compat::Compat<crate::Upgraded>>;

/// Wrapper for [`RequestBuilder`] that performs the
/// websocket handshake when sent.
#[derive(Debug)]
pub struct WebSocketRequestBuilder {
    inner: RequestBuilder,
    nonce: Option<Cow<'static, str>>,
    protocols: Option<Vec<Cow<'static, str>>>,
    config: WebSocketConfig,
}

impl WebSocketRequestBuilder {
    pub(crate) fn new(inner: RequestBuilder) -> Self {
        Self {
            inner,
            nonce: None,
            protocols: None,
            config: WebSocketConfig::default(),
        }
    }

    /// Websocket handshake with a specified websocket key. This returns a wrapped type,
    /// so you must do this after you set up your request, and just before you send the
    /// request.
    ///
    /// This method sets the websocket key (nonce) for the handshake. The key is used to
    /// establish the websocket connection and must be set before sending the request.
    ///
    /// # Arguments
    ///
    /// * `key` - The websocket key, which can be converted into a `Cow<'static, str>`.
    ///
    /// # Returns
    ///
    /// * `Self` - The modified instance with the updated websocket key.
    ///
    /// # Example
    ///
    /// ```
    /// let request = WebSocketRequestBuilder::new(builder)
    ///     .key("my-websocket-key")
    ///     .build();
    /// ```
    pub fn key<K>(mut self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        self.nonce = Some(key.into());
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
    /// * `protocols` - A list of subprotocols, which can be converted into a `Cow<'static, [String]>`.
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

    /// Modifies the request builder before sending the request.
    ///
    /// This method allows you to customize the `RequestBuilder` by passing a closure
    /// that modifies it. The closure receives the current `RequestBuilder` and returns
    /// a modified `RequestBuilder`. This can be useful for setting additional headers,
    /// configuring timeouts, or making other adjustments to the request.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that takes a `RequestBuilder` and returns a modified `RequestBuilder`.
    ///
    /// # Returns
    ///
    /// * `Self` - The modified instance with the updated `RequestBuilder`.
    pub fn configure_request<F>(mut self, f: F) -> Self
    where
        F: FnOnce(RequestBuilder) -> RequestBuilder,
    {
        self.inner = f(self.inner);
        self
    }

    /// Sends the request and returns and [`WebSocketResponse`].
    pub async fn send(self) -> Result<WebSocketResponse, Error> {
        let (client, request) = self.inner.build_split();
        let mut request = request?;

        // Ensure the request is HTTP 1.1
        *request.version_mut() = Some(Version::HTTP_11);

        // Ensure the scheme is http or https
        let url = request.url_mut();
        match url.scheme() {
            "ws" | "wss" => {
                let new_scheme = if url.scheme() == "ws" {
                    Scheme::HTTP.as_str()
                } else {
                    Scheme::HTTPS.as_str()
                };
                url.set_scheme(new_scheme)
                    .map_err(|_| error::url_bad_scheme(url.clone()))?;
            }
            "http" | "https" => {}
            _ => {
                return Err(error::url_bad_scheme(url.clone()));
            }
        }

        // Generate a nonce if one wasn't provided
        let nonce = self
            .nonce
            .unwrap_or_else(|| Cow::Owned(tungstenite::handshake::client::generate_key()));

        // HTTP 1 requires us to set some headers.
        let headers = request.headers_mut();
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::SEC_WEBSOCKET_KEY, HeaderValue::from_str(&nonce)?);
        headers.insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );

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
                nonce,
                protocols: self.protocols,
                config: self.config,
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
    nonce: Cow<'static, str>,
    protocols: Option<Vec<Cow<'static, str>>>,
    config: WebSocketConfig,
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

            if !matches!(self.inner.version(), Version::HTTP_10 | Version::HTTP_11) {
                return Err(Error::new(
                    Kind::Upgrade,
                    Some(format!("unexpected version: {:?}", self.inner.version())),
                ));
            }

            if status != StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::new(
                    Kind::Upgrade,
                    Some(format!("unexpected status code: {}", status)),
                ));
            }

            if !header_contains(self.inner.headers(), header::CONNECTION, "upgrade") {
                log::debug!("missing Connection header");
                return Err(Error::new(Kind::Upgrade, Some("missing connection header")));
            }

            if !header_eq(self.inner.headers(), header::UPGRADE, "websocket") {
                log::debug!("server responded with invalid Upgrade header");
                return Err(Error::new(Kind::Upgrade, Some("invalid upgrade header")));
            }

            match headers.get(header::SEC_WEBSOCKET_ACCEPT) {
                Some(header) => {
                    if !header.to_str().is_ok_and(|s| {
                        s == tungstenite::handshake::derive_accept_key(self.nonce.as_bytes())
                    }) {
                        log::debug!(
                            "server responded with invalid Sec-Websocket-Accept header: {header:?}"
                        );
                        return Err(Error::new(
                            Kind::Upgrade,
                            Some(format!("invalid accept key: {:?}", header)),
                        ));
                    }
                }
                None => {
                    log::debug!("missing Sec-Websocket-Accept header");
                    return Err(Error::new(Kind::Upgrade, Some("missing accept key")));
                }
            }

            let protocol = headers.get(header::SEC_WEBSOCKET_PROTOCOL).cloned();

            match (
                self.protocols.as_ref().map_or(true, |p| p.is_empty()),
                &protocol,
            ) {
                (true, None) => {
                    // we didn't request any protocols, so we don't expect one
                    // in return
                }
                (false, None) => {
                    // server didn't reply with a protocol
                    return Err(Error::new(
                        Kind::Status(self.res.status()),
                        Some("missing protocol"),
                    ));
                }
                (false, Some(protocol)) => {
                    if let Some((protocols, protocol)) = self.protocols.zip(protocol.to_str().ok())
                    {
                        if !protocols.contains(&Cow::Borrowed(protocol)) {
                            // the responded protocol is none which we requested
                            return Err(Error::new(
                                Kind::Status(status),
                                Some(format!("invalid protocol: {}", protocol)),
                            ));
                        }
                    } else {
                        // we didn't request any protocols but got one anyway
                        return Err(Error::new(Kind::Status(status), Some("invalid protocol")));
                    }
                }
                (true, Some(_)) => {
                    // we didn't request any protocols but got one anyway
                    return Err(Error::new(
                        Kind::Status(self.res.status()),
                        Some("invalid protocol"),
                    ));
                }
            }

            let inner = WebSocketStream::from_raw_socket(
                self.inner.upgrade().await?.compat(),
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
    /// Returns the protocol negotiated during the handshake.
    pub fn protocol(&self) -> Option<&HeaderValue> {
        self.protocol.as_ref()
    }

    /// Closes the connection with a given code and (optional) reason.
    ///
    /// # WASM
    ///
    /// On wasm `code` must be [`CloseCode::Normal`], [`CloseCode::Iana(_)`],
    /// or [`CloseCode::Library(_)`]. Furthermore `reason` must be at most 123
    /// bytes long. Otherwise the call to [`close`][Self::close] will fail.
    pub async fn close(self, code: CloseCode, reason: Option<&str>) -> Result<(), Error> {
        let mut inner = self.inner;
        inner
            .close(Some(tungstenite::protocol::CloseFrame {
                code: code.into(),
                reason: reason.unwrap_or_default().into(),
            }))
            .await
            .map_err(Into::into)
    }
}

impl Stream for WebSocket {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            return match self.inner.poll_next_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
                Poll::Ready(Some(Ok(message))) => match message.try_into() {
                    Ok(message) => Poll::Ready(Some(Ok(message))),
                    Err(e) => {
                        // this fails only for raw frames (which are not received)
                        log::debug!("received invalid frame: {:?}", e);
                        Poll::Ready(Some(Err(Error::new(
                            Kind::Body,
                            Some("unsupported websocket frame"),
                        ))))
                    }
                },
            };
        }
    }
}

impl Sink<Message> for WebSocket {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(item.into()).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx).map_err(Into::into)
    }
}

impl TryFrom<tungstenite::Message> for Message {
    type Error = tungstenite::Message;

    fn try_from(value: tungstenite::Message) -> Result<Self, Self::Error> {
        match value {
            tungstenite::Message::Text(text) => Ok(Self::Text(text)),
            tungstenite::Message::Binary(data) => Ok(Self::Binary(data)),
            tungstenite::Message::Ping(data) => Ok(Self::Ping(data)),
            tungstenite::Message::Pong(data) => Ok(Self::Pong(data)),
            tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                code,
                reason,
            })) => Ok(Self::Close {
                code: code.into(),
                reason: Some(reason.into_owned()),
            }),
            tungstenite::Message::Close(None) => Ok(Self::Close {
                code: CloseCode::default(),
                reason: None,
            }),
            tungstenite::Message::Frame(_) => Err(value),
        }
    }
}

impl From<Message> for tungstenite::Message {
    fn from(value: Message) -> Self {
        match value {
            Message::Text(text) => Self::Text(text),
            Message::Binary(data) => Self::Binary(data),
            Message::Ping(data) => Self::Ping(data),
            Message::Pong(data) => Self::Pong(data),
            Message::Close { code, reason } => {
                Self::Close(Some(tungstenite::protocol::CloseFrame {
                    code: code.into(),
                    reason: reason.unwrap_or_default().into(),
                }))
            }
        }
    }
}
