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
    /// A wrapper body that applies timeout strategies to an inner HTTP body.
    pub struct TimeoutBody<B> {
        #[pin]
        inner: InnerBody<B>,
    }
}

pin_project! {
    /// A body wrapper that enforces a total timeout for the entire stream.
    ///
    /// The timeout applies to the whole body: if the deadline is reached before
    /// the body is fully read, an error is returned. The timer does **not** reset
    /// between chunks.
    pub struct TotalTimeoutBody<B> {
        #[pin]
        body: B,
        timeout: Pin<Box<Sleep>>,
    }
}

pin_project! {
    /// A body wrapper that enforces a timeout for each read operation.
    ///
    /// The timeout resets after every successful read. If a single read
    /// takes longer than the specified duration, an error is returned.
    pub struct ReadTimeoutBody<B> {
        timeout: Duration,
        #[pin]
        sleep: Option<Sleep>,
        #[pin]
        body: B,
    }
}

/// Represents the different timeout strategies for the HTTP body.
enum InnerBody<B> {
    /// Applies a timeout to the entire body stream.
    TotalTimeout(Pin<Box<TotalTimeoutBody<B>>>),
    /// Applies a timeout to each read operation.
    ReadTimeout(Pin<Box<ReadTimeoutBody<B>>>),
    /// Applies both total and per-read timeouts.
    CombinedTimeout(Pin<Box<TotalTimeoutBody<ReadTimeoutBody<B>>>>),
    /// No timeout applied.
    Plain(Pin<Box<B>>),
}

/// ==== impl TimeoutBody ====
impl<B> TimeoutBody<B> {
    /// Creates a new [`TimeoutBody`] with no timeout.
    pub fn new(deadline: Option<Duration>, read_timeout: Option<Duration>, body: B) -> Self {
        let deadline = deadline.map(sleep).map(Box::pin);
        match (deadline, read_timeout) {
            (Some(total), Some(read)) => {
                let body = ReadTimeoutBody::new(read, body);
                let body = TotalTimeoutBody::new(total, body);
                TimeoutBody {
                    inner: InnerBody::CombinedTimeout(Box::pin(body)),
                }
            }
            (Some(total), None) => {
                let body = TotalTimeoutBody::new(total, body);
                TimeoutBody {
                    inner: InnerBody::TotalTimeout(Box::pin(body)),
                }
            }
            (None, Some(read)) => {
                let body = ReadTimeoutBody::new(read, body);
                TimeoutBody {
                    inner: InnerBody::ReadTimeout(Box::pin(body)),
                }
            }
            (None, None) => TimeoutBody {
                inner: InnerBody::Plain(Box::pin(body)),
            },
        }
    }
}

impl<B> Body for TimeoutBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match *this.inner.as_mut() {
            InnerBody::TotalTimeout(ref mut body) => poll_and_map_body(body.as_mut(), cx),
            InnerBody::ReadTimeout(ref mut body) => poll_and_map_body(body.as_mut(), cx),
            InnerBody::CombinedTimeout(ref mut body) => poll_and_map_body(body.as_mut(), cx),
            InnerBody::Plain(ref mut body) => {
                // If no timeout is set, just poll the inner body directly.
                poll_and_map_body(body.as_mut(), cx)
            }
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            InnerBody::TotalTimeout(body) => body.size_hint(),
            InnerBody::ReadTimeout(body) => body.size_hint(),
            InnerBody::CombinedTimeout(body) => body.size_hint(),
            InnerBody::Plain(body) => body.size_hint(),
        }
    }

    #[inline(always)]
    fn is_end_stream(&self) -> bool {
        match &self.inner {
            InnerBody::TotalTimeout(body) => body.is_end_stream(),
            InnerBody::ReadTimeout(body) => body.is_end_stream(),
            InnerBody::CombinedTimeout(body) => body.is_end_stream(),
            InnerBody::Plain(body) => body.is_end_stream(),
        }
    }
}

#[inline(always)]
fn poll_and_map_body<B>(
    body: Pin<&mut B>,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<http_body::Frame<B::Data>, crate::Error>>>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    Poll::Ready(ready!(body.poll_frame(cx)).map(|opt| opt.map_err(crate::error::body)))
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
    B::Error: Into<BoxError>,
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

    #[inline(always)]
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }

    #[inline(always)]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}

/// ==== impl ReadTimeoutBody ====
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
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        // Error if the timeout has expired.
        if this.sleep.is_none() {
            this.sleep.set(Some(sleep(*this.timeout)));
        }

        // Error if the timeout has expired.
        if let Some(sleep) = this.sleep.as_mut().as_pin_mut() {
            if sleep.poll(cx).is_ready() {
                return Poll::Ready(Some(Err(Box::new(TimedOut))));
            }
        }

        // Poll the actual body
        match ready!(this.body.poll_frame(cx)) {
            Some(Ok(frame)) => {
                // Reset timeout on successful read
                this.sleep.set(None);
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            None => Poll::Ready(None),
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }

    #[inline(always)]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
