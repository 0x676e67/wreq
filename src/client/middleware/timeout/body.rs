use crate::error::{self, BoxError, TimedOut};
use http_body::Body;
use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::time::{Sleep, sleep};

pin_project! {
    pub struct TimeoutBody<B> {
        #[pin]
        inner: InnerTimeoutBody<B>,
    }
}

enum InnerTimeoutBody<B> {
    /// A body with a total timeout.
    Total(Pin<Box<TotalTimeoutBody<B>>>),
    /// A body with a read timeout.
    Read(Pin<Box<ReadTimeoutBody<B>>>),
    /// A body with both a total and read timeout.
    TotalAndRead(Pin<Box<TotalTimeoutBody<ReadTimeoutBody<B>>>>),
}

pin_project! {
    /// A body with a total timeout.
    ///
    /// The timeout does not reset upon each chunk, but rather requires the whole
    /// body be streamed before the deadline is reached.
    pub struct TotalTimeoutBody<B> {
        #[pin]
        body: B,
        timeout: Pin<Box<Sleep>>,
    }
}

pin_project! {
    /// Middleware that applies a timeout to request and response bodies.
    pub struct ReadTimeoutBody<B> {
        timeout: Duration,
        #[pin]
        sleep: Option<Sleep>,
        #[pin]
        body: B,
    }
}

/// ==== impl TimeoutBody ====
impl<B> TimeoutBody<B> {
    /// Creates a new [`TimeoutBody`] with no timeout.
    pub fn new(deadline: Option<Duration>, read_timeout: Option<Duration>, body: B) -> Self {
        let deadline = deadline.map(tokio::time::sleep).map(Box::pin);
        match (deadline, read_timeout) {
            (Some(total), Some(read)) => {
                let body = ReadTimeoutBody::new(read, body);
                let body = TotalTimeoutBody::new(total, body);
                TimeoutBody {
                    inner: InnerTimeoutBody::TotalAndRead(Box::pin(body)),
                }
            }
            (Some(total), None) => {
                let body = TotalTimeoutBody::new(total, body);
                TimeoutBody {
                    inner: InnerTimeoutBody::Total(Box::pin(body)),
                }
            }
            (None, Some(read)) => {
                let body = ReadTimeoutBody::new(read, body);
                TimeoutBody {
                    inner: InnerTimeoutBody::Read(Box::pin(body)),
                }
            }
            (None, None) => TimeoutBody {
                inner: InnerTimeoutBody::Read(Box::pin(ReadTimeoutBody::new(
                    Duration::from_secs(0),
                    body,
                ))),
            },
        }
    }
}

impl<B> Body for TimeoutBody<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match *this.inner.as_mut() {
            InnerTimeoutBody::Total(ref mut body) => Poll::Ready(
                ready!(Body::poll_frame(body.as_mut(), cx))
                    .map(|opt_chunk| opt_chunk.map_err(error::body)),
            ),
            InnerTimeoutBody::Read(ref mut body) => Poll::Ready(
                ready!(body.as_mut().poll_frame(cx))
                    .map(|opt_chunk| opt_chunk.map_err(error::body)),
            ),
            InnerTimeoutBody::TotalAndRead(ref mut body) => {
                let mut this = body.as_mut().project();
                if let Poll::Ready(()) = this.timeout.as_mut().poll(cx) {
                    return Poll::Ready(Some(Err(error::body(error::TimedOut))));
                }

                Poll::Ready(
                    ready!(Body::poll_frame(this.body.as_mut(), cx))
                        .map(|opt_chunk| opt_chunk.map_err(error::body)),
                )
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            InnerTimeoutBody::Total(body) => body.size_hint(),
            InnerTimeoutBody::Read(body) => body.size_hint(),
            InnerTimeoutBody::TotalAndRead(body) => body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match &self.inner {
            InnerTimeoutBody::Total(body) => body.is_end_stream(),
            InnerTimeoutBody::Read(body) => body.is_end_stream(),
            InnerTimeoutBody::TotalAndRead(body) => body.is_end_stream(),
        }
    }
}

// ==== impl TotalTimeoutBody ====
impl<B> TotalTimeoutBody<B> {
    /// Creates a new [`TotalTimeoutBody`].
    pub const fn new(timeout: Pin<Box<Sleep>>, body: B) -> Self {
        TotalTimeoutBody { body, timeout }
    }
}

impl<B> Body for TotalTimeoutBody<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Poll::Ready(()) = this.timeout.as_mut().poll(cx) {
            return Poll::Ready(Some(Err(error::body(error::TimedOut))));
        }
        Poll::Ready(
            ready!(this.body.poll_frame(cx)).map(|opt_chunk| opt_chunk.map_err(crate::error::body)),
        )
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}

// ==== impl ReadTimeoutBody ====

impl<B> ReadTimeoutBody<B> {
    /// Creates a new [`ReadTimeoutBody`].
    pub const fn new(timeout: Duration, body: B) -> Self {
        ReadTimeoutBody {
            timeout,
            sleep: None,
            body,
        }
    }
}

impl<B> Body for ReadTimeoutBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        println!("ReadTimeoutBody::call: {}", self.timeout.as_millis());
        let mut this = self.project();

        // Start the `Sleep` if not active.
        let sleep_pinned = if let Some(some) = this.sleep.as_mut().as_pin_mut() {
            some
        } else {
            this.sleep.set(Some(sleep(*this.timeout)));
            this.sleep.as_mut().as_pin_mut().unwrap()
        };

        // Error if the timeout has expired.
        if let Poll::Ready(()) = sleep_pinned.poll(cx) {
            return Poll::Ready(Some(Err(Box::new(TimedOut))));
        }

        // Check for body data.
        let frame = ready!(this.body.poll_frame(cx));
        // A frame is ready. Reset the `Sleep`...
        this.sleep.set(None);

        Poll::Ready(frame.transpose().map_err(Into::into).transpose())
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
