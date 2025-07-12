//! HTTP/2 client connections

use std::{
    error::Error,
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
        body::Incoming as IncomingBody,
        client::dispatch::{self, TrySendError},
        common::time::Time,
        proto,
        rt::{Read, Timer, Write, bounds::Http2ClientConnExec},
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
    B::Error: Into<Box<dyn Error + Send + Sync>>,
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
    pub(super) exec: Ex,
    pub(super) timer: Time,
    config: Http2Options,
}

// ===== impl SendRequest

impl<B> SendRequest<B> {
    /// Polls to determine whether this sender can be used yet for a request.
    ///
    /// If the associated connection is closed, this returns an Error.
    pub fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<crate::core::Result<()>> {
        if self.is_closed() {
            Poll::Ready(Err(crate::core::Error::new_closed()))
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
                    let error = crate::core::Error::new_canceled().with("connection was not ready");
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
    B::Error: Into<Box<dyn Error + Send + Sync>>,
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
    B::Error: Into<Box<dyn Error + Send + Sync>>,
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
            config: Default::default(),
        }
    }

    /// Provide a timer to execute background HTTP2 tasks.
    pub fn timer<M>(&mut self, timer: M)
    where
        M: Timer + Send + Sync + 'static,
    {
        self.timer = Time::Timer(Arc::new(timer));
    }

    /// Provide a configuration for HTTP/2.
    pub fn config(&mut self, opts: Option<Http2Options>) {
        if let Some(config) = opts {
            self.config = config;
        }
    }

    /// Constructs a connection with the configured options and IO.
    /// See [`client::conn`](crate::core::client::conn) for more.
    ///
    /// Note, if [`Connection`] is not `await`-ed, [`SendRequest`] will
    /// do nothing.
    pub fn handshake<T, B>(
        &self,
        io: T,
    ) -> impl Future<Output = crate::core::Result<(SendRequest<B>, Connection<T, B, Ex>)>>
    where
        T: Read + Write + Unpin,
        B: Body + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
        Ex: Http2ClientConnExec<B, T> + Unpin,
    {
        let opts = self.clone();

        async move {
            trace!("client handshake HTTP/2");

            let (tx, rx) = dispatch::channel();
            let h2 = proto::h2::client::handshake(
                io,
                rx,
                &opts.config.h2_builder,
                opts.exec,
                opts.timer,
            )
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
}
