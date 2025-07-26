//! HTTP/2 client connections

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use http::{Request, Response};
use http_body::Body;

use crate::{
    core::{
        client::{
            body::Incoming as IncomingBody,
            bounds::Http2ClientConnExec,
            dispatch::{self, TrySendError},
            proto::{self, h2::ping},
        },
        common::time::Time,
        error::{BoxError, Error},
        rt::{Read, Timer, Write},
    },
    http2::Http2Options,
};

/// The sender side of an established connection.
pub struct SendRequest<B> {
    dispatch: dispatch::UnboundedSender<Request<B>, Response<IncomingBody>>,
}

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> SendRequest<B> {
        SendRequest {
            dispatch: self.dispatch.clone(),
        }
    }
}

/// A future that processes all HTTP state for the IO object.
///
/// In most cases, this should just be spawned into an executor, so that it
/// can process incoming and outgoing messages, notice hangups, and the like.
///
/// Instances of this type are typically created via the [\`handshake\`] function
#[must_use = "futures do nothing unless polled"]
pub struct Connection<T, B, E>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<BoxError>,
{
    inner: (PhantomData<T>, proto::h2::ClientTask<B, E, T>),
}

/// A builder to configure an HTTP connection.
///
/// After setting options, the builder is used to create a handshake future.
///
/// **Note**: The default values of options are *not considered stable*. They
/// are subject to change at any time.
#[derive(Clone, Debug)]
pub struct Builder<Ex> {
    exec: Ex,
    timer: Time,
    opts: Http2Options,
}

// ===== impl SendRequest

impl<B> SendRequest<B> {
    /// Polls to determine whether this sender can be used yet for a request.
    ///
    /// If the associated connection is closed, this returns an Error.
    pub fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<crate::core::Result<()>> {
        if self.is_closed() {
            Poll::Ready(Err(Error::new_closed()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Waits until the dispatcher is ready
    ///
    /// If the associated connection is closed, this returns an Error.
    pub async fn ready(&mut self) -> crate::core::Result<()> {
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

    /// Checks if the connection side has been closed.
    pub fn is_closed(&self) -> bool {
        self.dispatch.is_closed()
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
    ) -> impl Future<Output = Result<Response<IncomingBody>, TrySendError<Request<B>>>> {
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

impl<T, B, E> fmt::Debug for Connection<T, B, E>
where
    T: Read + Write + fmt::Debug + 'static + Unpin,
    B: Body + 'static,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<BoxError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<T, B, E> Future for Connection<T, B, E>
where
    T: Read + Write + Unpin + 'static,
    B: Body + 'static + Unpin,
    B::Data: Send,
    E: Unpin,
    B::Error: Into<BoxError>,
    E: Http2ClientConnExec<B, T> + Unpin,
{
    type Output = crate::core::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.inner.1).poll(cx))? {
            proto::Dispatched::Shutdown => Poll::Ready(Ok(())),
            proto::Dispatched::Upgrade(_pending) => unreachable!("http2 cannot upgrade"),
        }
    }
}

// ===== impl Builder

impl<Ex> Builder<Ex>
where
    Ex: Clone,
{
    /// Creates a new connection builder.
    #[inline]
    pub fn new(exec: Ex) -> Builder<Ex> {
        Builder {
            exec,
            timer: Time::Empty,
            opts: Default::default(),
        }
    }

    /// Provide a timer to execute background HTTP2 tasks.
    pub fn timer<M>(&mut self, timer: M)
    where
        M: Timer + Send + Sync + 'static,
    {
        self.timer = Time::Timer(Arc::new(timer));
    }

    /// Provide a options configuration for the HTTP/2 connection.
    pub fn options(&mut self, opts: Option<Http2Options>) {
        if let Some(opts) = opts {
            self.opts = opts;
        }
    }

    /// Constructs a connection with the configured options and IO.
    /// See [`client::conn`](crate::core::client::conn) for more.
    ///
    /// Note, if [`Connection`] is not `await`-ed, [`SendRequest`] will
    /// do nothing.
    pub async fn handshake<T, B>(
        self,
        io: T,
    ) -> crate::core::Result<(SendRequest<B>, Connection<T, B, Ex>)>
    where
        T: Read + Write + Unpin,
        B: Body + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        Ex: Http2ClientConnExec<B, T> + Unpin,
    {
        trace!("client handshake HTTP/2");

        // Crate the HTTP/2 client with the provided options.
        let builder = {
            let mut builder = http2::client::Builder::default();
            builder
                .initial_max_send_streams(self.opts.initial_max_send_streams)
                .initial_window_size(self.opts.initial_window_size)
                .initial_connection_window_size(self.opts.initial_conn_window_size)
                .max_send_buffer_size(self.opts.max_send_buffer_size);
            if let Some(id) = self.opts.initial_stream_id {
                builder.initial_stream_id(id);
            }
            if let Some(max) = self.opts.max_pending_accept_reset_streams {
                builder.max_pending_accept_reset_streams(max);
            }
            if let Some(max) = self.opts.max_concurrent_reset_streams {
                builder.max_concurrent_reset_streams(max);
            }
            if let Some(max) = self.opts.max_concurrent_streams {
                builder.max_concurrent_streams(max);
            }
            if let Some(max) = self.opts.max_header_list_size {
                builder.max_header_list_size(max);
            }
            if let Some(opt) = self.opts.enable_push {
                builder.enable_push(opt);
            }
            if let Some(max) = self.opts.max_frame_size {
                builder.max_frame_size(max);
            }
            if let Some(max) = self.opts.header_table_size {
                builder.header_table_size(max);
            }
            if let Some(v) = self.opts.enable_connect_protocol {
                builder.enable_connect_protocol(v);
            }
            if let Some(v) = self.opts.no_rfc7540_priorities {
                builder.no_rfc7540_priorities(v);
            }
            if let Some(order) = self.opts.settings_order {
                builder.settings_order(order);
            }
            if let Some(experimental_settings) = self.opts.experimental_settings {
                builder.experimental_settings(experimental_settings);
            }
            if let Some(stream_dependency) = self.opts.headers_stream_dependency {
                builder.headers_stream_dependency(stream_dependency);
            }
            if let Some(order) = self.opts.headers_pseudo_order {
                builder.headers_pseudo_order(order);
            }
            if let Some(priority) = self.opts.priorities {
                builder.priorities(priority);
            }

            builder
        };

        // Create the ping configuration for the connection.
        let ping_config = ping::Config::new(
            self.opts.adaptive_window,
            self.opts.initial_window_size,
            self.opts.keep_alive_interval,
            self.opts.keep_alive_timeout,
            self.opts.keep_alive_while_idle,
        );

        let (tx, rx) = dispatch::channel();
        let h2 =
            proto::h2::client::handshake(io, rx, builder, ping_config, self.exec, self.timer)
                .await?;
        Ok((
            SendRequest {
                dispatch: tx.unbound(),
            },
            Connection {
                inner: (PhantomData, h2),
            },
        ))
    }
}
