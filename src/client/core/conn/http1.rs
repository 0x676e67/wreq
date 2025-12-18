//! HTTP/1 client connections

use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use httparse::ParserConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::core::{
    Error, Result,
    body::Incoming as IncomingBody,
    dispatch::{self, TrySendError},
    error::BoxError,
    http1::Http1Options,
    proto,
};

type Dispatcher<T, B> =
    proto::dispatch::Dispatcher<proto::dispatch::Client<B>, B, T, proto::h1::ClientTransaction>;

/// The sender side of an established connection.
pub struct SendRequest<B> {
    dispatch: dispatch::Sender<Request<B>, Response<IncomingBody>>,
}

/// Deconstructed parts of a `Connection`.
///
/// This allows taking apart a `Connection` at a later time, in order to
/// reclaim the IO object, and additional related pieces.
#[derive(Debug)]
#[non_exhaustive]
pub struct Parts<T> {
    /// The original IO object used in the handshake.
    pub io: T,
    /// A buffer of bytes that have been read but not processed as HTTP.
    ///
    /// For instance, if the `Connection` is used for an HTTP upgrade request,
    /// it is possible the server sent back the first bytes of the new protocol
    /// along with the response upgrade.
    ///
    /// You will want to check for any existing bytes if you plan to continue
    /// communicating on the IO object.
    pub read_buf: Bytes,
}

/// A future that processes all HTTP state for the IO object.
///
/// In most cases, this should just be spawned into an executor, so that it
/// can process incoming and outgoing messages, notice hangups, and the like.
#[must_use = "futures do nothing unless polled"]
pub struct Connection<T, B>
where
    T: AsyncRead + AsyncWrite,
    B: Body + 'static,
{
    inner: Dispatcher<T, B>,
}

impl<T, B> Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Body + 'static,
    B::Error: Into<BoxError>,
{
    /// Return the inner IO object, and additional information.
    ///
    /// Only works for HTTP/1 connections. HTTP/2 connections will panic.
    pub fn into_parts(self) -> Parts<T> {
        let (io, read_buf, _) = self.inner.into_inner();
        Parts { io, read_buf }
    }
}

/// A builder to configure an HTTP connection.
///
/// After setting options, the builder is used to create a handshake future.
///
/// **Note**: The default values of options are *not considered stable*. They
/// are subject to change at any time.
#[derive(Clone, Debug)]
pub struct Builder {
    opts: Http1Options,
}

// ===== impl SendRequest

impl<B> SendRequest<B> {
    /// Polls to determine whether this sender can be used yet for a request.
    ///
    /// If the associated connection is closed, this returns an Error.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.dispatch.poll_ready(cx)
    }

    /// Waits until the dispatcher is ready
    ///
    /// If the associated connection is closed, this returns an Error.
    pub async fn ready(&mut self) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Checks if the connection is currently ready to send a request.
    ///
    /// # Note
    ///
    /// This is mostly a hint. Due to inherent latency of networks, it is
    /// possible that even after checking this is ready, sending a request
    /// may still fail because the connection was closed in the meantime.
    pub fn is_ready(&self) -> bool {
        self.dispatch.is_ready()
    }
}

impl<B> SendRequest<B>
where
    B: Body + 'static,
{
    /// Sends a `Request` on the associated connection.
    ///
    /// Returns a future that if successful, yields the `Response`.
    ///
    /// # Error
    ///
    /// If there was an error before trying to serialize the request to the
    /// connection, the message will be returned as part of this error.
    pub fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = std::result::Result<Response<IncomingBody>, TrySendError<Request<B>>>>
    {
        let sent = self.dispatch.try_send(req);
        async move {
            match sent {
                Ok(rx) => match rx.await {
                    Ok(Ok(res)) => Ok(res),
                    Ok(Err(err)) => Err(err),
                    // this is definite bug if it happens, but it shouldn't happen!
                    Err(_) => panic!("dispatch dropped without returning error"),
                },
                Err(req) => {
                    debug!("connection was not ready");
                    let error = Error::new_canceled().with("connection was not ready");
                    Err(TrySendError {
                        error,
                        message: Some(req),
                    })
                }
            }
        }
    }
}

impl<B> fmt::Debug for SendRequest<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRequest").finish()
    }
}

// ===== impl Connection

impl<T, B> Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    B: Body + 'static,
    B::Error: Into<BoxError>,
{
    /// Enable this connection to support higher-level HTTP upgrades.
    pub fn with_upgrades(self) -> upgrades::UpgradeableConnection<T, B> {
        upgrades::UpgradeableConnection { inner: Some(self) }
    }
}

impl<T, B> fmt::Debug for Connection<T, B>
where
    T: AsyncRead + AsyncWrite + fmt::Debug,
    B: Body + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<T, B> Future for Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Body + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.inner).poll(cx))? {
            proto::Dispatched::Shutdown => Poll::Ready(Ok(())),
            proto::Dispatched::Upgrade(pending) => {
                // With no `Send` bound on `I`, we can't try to do
                // upgrades here. In case a user was trying to use
                // `upgrade` with this API, send a special
                // error letting them know about that.
                pending.manual();
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ===== impl Builder

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Creates a new connection builder.
    #[inline]
    pub fn new() -> Builder {
        Builder {
            opts: Default::default(),
        }
    }

    /// Provide a options configuration for the HTTP/1 connection.
    #[inline]
    pub fn options(&mut self, opts: Http1Options) {
        self.opts = opts;
    }

    /// Constructs a connection with the configured options and IO.
    ///
    /// Note, if [`Connection`] is not `await`-ed, [`SendRequest`] will
    /// do nothing.
    pub async fn handshake<T, B>(self, io: T) -> Result<(SendRequest<B>, Connection<T, B>)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Body + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        trace!("client handshake HTTP/1");

        let (tx, rx) = dispatch::channel();
        let mut conn = proto::Conn::new(io);

        // Set the HTTP/1 parser configuration
        let h1_parser_config = {
            let mut h1_parser_config = ParserConfig::default();
            h1_parser_config
                .ignore_invalid_headers_in_responses(self.opts.ignore_invalid_headers_in_responses)
                .allow_spaces_after_header_name_in_responses(
                    self.opts.allow_spaces_after_header_name_in_responses,
                )
                .allow_obsolete_multiline_headers_in_responses(
                    self.opts.allow_obsolete_multiline_headers_in_responses,
                );
            h1_parser_config
        };
        conn.set_h1_parser_config(h1_parser_config);

        // Set the h1 write strategy
        if let Some(writev) = self.opts.h1_writev {
            if writev {
                conn.set_write_strategy_queue();
            } else {
                conn.set_write_strategy_flatten();
            }
        }

        // Set the maximum size of the request headers
        if let Some(max_headers) = self.opts.h1_max_headers {
            conn.set_http1_max_headers(max_headers);
        }

        // Enable HTTP/0.9 responses if requested
        if self.opts.h09_responses {
            conn.set_h09_responses();
        }

        // Set the read buffer size if specified
        if let Some(sz) = self.opts.h1_read_buf_exact_size {
            conn.set_read_buf_exact_size(sz);
        }

        // Set the maximum buffer size for HTTP/1 connections
        if let Some(max) = self.opts.h1_max_buf_size {
            conn.set_max_buf_size(max);
        }

        let cd = proto::h1::dispatch::Client::new(rx);
        let proto = proto::h1::Dispatcher::new(cd, conn);

        Ok((SendRequest { dispatch: tx }, Connection { inner: proto }))
    }
}

mod upgrades {
    use super::*;
    use crate::client::core::upgrade::Upgraded;

    // A future binding a connection with a Service with Upgrade support.
    //
    // This type is unnameable outside the crate.
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradeableConnection<T, B>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: Body + 'static,
        B::Error: Into<BoxError>,
    {
        pub(super) inner: Option<Connection<T, B>>,
    }

    impl<I, B> Future for UpgradeableConnection<I, B>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: Body + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        type Output = Result<()>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match ready!(Pin::new(&mut self.inner.as_mut().unwrap().inner).poll(cx)) {
                Ok(proto::Dispatched::Shutdown) => Poll::Ready(Ok(())),
                Ok(proto::Dispatched::Upgrade(pending)) => {
                    let Parts { io, read_buf } = self.inner.take().unwrap().into_parts();
                    pending.fulfill(Upgraded::new(io, read_buf));
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }
}
