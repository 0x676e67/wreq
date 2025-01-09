#[cfg(feature = "json")]
mod json;
mod message;

use std::{
    borrow::Cow,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{error::Kind, RequestBuilder};
use crate::{Error, Response};
use async_tungstenite::tungstenite;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::{header, uri::Scheme, HeaderValue, StatusCode, Version};
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
    protocols: Option<Cow<'static, [String]>>,
    config: WebSocketConfig,
}

impl WebSocketRequestBuilder {
    pub(crate) fn new(inner: RequestBuilder) -> Self {
        Self {
            inner: inner.version(Version::HTTP_11),
            nonce: None,
            protocols: None,
            config: WebSocketConfig::default(),
        }
    }

    /// Websocket handshake with a specified websocket key. This returns a wrapped type,
    /// so you must do this after you set up your request, and just before you send the
    /// request.
    pub fn key<K>(mut self, key: K) -> Self
    where
        K: Into<Cow<'static, str>>,
    {
        self.nonce = Some(key.into());
        self
    }

    /// Sets the websocket subprotocols to request.
    pub fn protocols<P>(mut self, protocols: P) -> Self
    where
        P: Into<Cow<'static, [String]>>,
    {
        self.protocols = Some(protocols.into());
        self
    }

    /// With request builder
    ///
    /// This is a helper function to modify the request builder before sending the request.
    pub fn with_builder<F>(mut self, f: F) -> Self
    where
        F: FnOnce(RequestBuilder) -> RequestBuilder,
    {
        self.inner = f(self.inner);
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

    /// Sends the request and returns and [`WebSocketResponse`].
    pub async fn send(self) -> Result<WebSocketResponse, Error> {
        let (client, request_result) = self.inner.build_split();
        let mut request = request_result?;

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
                    .expect("unexpected error setting URL scheme");
            }
            "http" | "https" => {}
            invalid_scheme => {
                return Err(Error::new(
                    Kind::Builder,
                    Some(format!(
                        "invalid scheme: {}, expected ws or wss",
                        invalid_scheme
                    )),
                ));
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
        headers.insert(
            header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&nonce)
                .map_err(|_| Error::new(Kind::Builder, Some("invalid key")))?,
        );
        headers.insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );

        if let Some(ref protocols) = self.protocols {
            // Sets subprotocols
            if !protocols.is_empty() {
                let subprotocols = protocols
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ");

                request.headers_mut().insert(
                    header::SEC_WEBSOCKET_PROTOCOL,
                    subprotocols
                        .parse()
                        .map_err(|_| Error::new(Kind::Builder, Some("invalid subprotocol")))?,
                );
            }
        }

        Ok(WebSocketResponse {
            inner: client.execute(request).await?,
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
    protocols: Option<Cow<'static, [String]>>,
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
            let headers = self.inner.headers();

            // Check the version
            if !matches!(self.inner.version(), Version::HTTP_11 | Version::HTTP_10) {
                return Err(Error::new(
                    Kind::Upgrade,
                    Some(format!("unexpected version: {:?}", self.inner.version())),
                ));
            }

            // Check the status code
            if self.inner.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::new(
                    Kind::Upgrade,
                    Some(format!("unexpected status code: {}", self.inner.status())),
                ));
            }

            // Check the connection header
            if let Some(header) = headers.get(header::CONNECTION) {
                if !header
                    .to_str()
                    .is_ok_and(|s| s.eq_ignore_ascii_case("upgrade"))
                {
                    log::debug!("server responded with invalid Connection header: {header:?}");
                    return Err(Error::new(
                        Kind::Upgrade,
                        Some(format!("invalid connection header: {:?}", header)),
                    ));
                }
            } else {
                log::debug!("missing Connection header");
                return Err(Error::new(Kind::Upgrade, Some("missing connection header")));
            }

            // Check the upgrade header
            if let Some(header) = headers.get(header::UPGRADE) {
                if !header
                    .to_str()
                    .is_ok_and(|s| s.eq_ignore_ascii_case("websocket"))
                {
                    log::debug!("server responded with invalid Upgrade header: {header:?}");
                    return Err(Error::new(
                        Kind::Upgrade,
                        Some(format!("invalid upgrade header: {:?}", header)),
                    ));
                }
            } else {
                log::debug!("missing Upgrade header");
                return Err(Error::new(Kind::Upgrade, Some("missing upgrade header")));
            }

            // Check the accept key
            if let Some(header) = headers.get(header::SEC_WEBSOCKET_ACCEPT) {
                // Check the accept key
                let expected_nonce =
                    tungstenite::handshake::derive_accept_key(self.nonce.as_bytes());
                if !header.to_str().is_ok_and(|s| s == expected_nonce) {
                    log::debug!(
                        "server responded with invalid Sec-Websocket-Accept header: {header:?}"
                    );
                    return Err(Error::new(
                        Kind::Upgrade,
                        Some(format!("invalid accept key: {:?}", header)),
                    ));
                }
            } else {
                log::debug!("missing Sec-Websocket-Accept header");
                return Err(Error::new(Kind::Upgrade, Some("missing accept key")));
            }

            // Ensure the server responded with the requested protocol
            let protocol = headers
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);

            match (
                self.protocols
                    .as_ref()
                    .map(|p| p.is_empty())
                    .unwrap_or(true),
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
                    if let Some(ref protocols) = self.protocols {
                        if !protocols.contains(protocol) {
                            // the responded protocol is none which we requested
                            return Err(Error::new(
                                Kind::Status(self.res.status()),
                                Some(format!("invalid protocol: {}", protocol)),
                            ));
                        }
                    } else {
                        // we didn't request any protocols but got one anyway
                        return Err(Error::new(
                            Kind::Status(self.res.status()),
                            Some("invalid protocol"),
                        ));
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

            let inner = async_tungstenite::WebSocketStream::from_raw_socket(
                self.inner.upgrade().await?.compat(),
                async_tungstenite::tungstenite::protocol::Role::Client,
                Some(self.config),
            )
            .await;

            (inner, protocol)
        };

        Ok(WebSocket { inner, protocol })
    }
}

/// A websocket connection
#[derive(Debug)]
pub struct WebSocket {
    inner: WebSocketStream,
    protocol: Option<String>,
}

impl WebSocket {
    /// Returns the protocol negotiated during the handshake.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
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
            .await?;
        Ok(())
    }
}

impl Stream for WebSocket {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
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
