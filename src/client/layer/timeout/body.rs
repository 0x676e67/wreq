use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use http_body::Body;
use pin_project_lite::pin_project;
use tokio::time::{Sleep, sleep};

use crate::{
    Error,
    error::{BoxError, TimedOut},
};

pin_project! {
    /// A wrapper body that applies timeout strategies to an inner HTTP body.
    #[project = TimeoutBodyProj]
    pub enum TimeoutBody<B> {
        Plain {
            #[pin]
            body: B,
        },
        TotalTimeout {
            #[pin]
            body: TotalTimeoutBody<B>,
        },
        ReadTimeout {
            #[pin]
            body: ReadTimeoutBody<B>
        },
        CombinedTimeout {
            #[pin]
            body: TotalTimeoutBody<ReadTimeoutBody<B>>,
        }
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

/// ==== impl TimeoutBody ====
impl<B> TimeoutBody<B> {
    /// Creates a new [`TimeoutBody`] with no timeout.
    pub fn new(deadline: Option<Duration>, read_timeout: Option<Duration>, body: B) -> Self {
        let deadline = deadline.map(sleep).map(Box::pin);
        match (deadline, read_timeout) {
            (Some(total_timeout), Some(read_timeout)) => TimeoutBody::CombinedTimeout {
                body: TotalTimeoutBody {
                    timeout: total_timeout,
                    body: ReadTimeoutBody {
                        timeout: read_timeout,
                        sleep: None,
                        body,
                    },
                },
            },
            (Some(timeout), None) => TimeoutBody::TotalTimeout {
                body: TotalTimeoutBody { body, timeout },
            },
            (None, Some(timeout)) => TimeoutBody::ReadTimeout {
                body: ReadTimeoutBody {
                    timeout,
                    sleep: None,
                    body,
                },
            },
            (None, None) => TimeoutBody::Plain { body },
        }
    }
}

impl<B> Body for TimeoutBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    #[inline(always)]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            TimeoutBodyProj::TotalTimeout { body } => body.poll_frame(cx),
            TimeoutBodyProj::ReadTimeout { body } => body.poll_frame(cx),
            TimeoutBodyProj::CombinedTimeout { body } => body.poll_frame(cx),
            TimeoutBodyProj::Plain { body } => poll_and_map_body(body, cx),
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            TimeoutBody::TotalTimeout { body } => body.size_hint(),
            TimeoutBody::ReadTimeout { body } => body.size_hint(),
            TimeoutBody::CombinedTimeout { body } => body.size_hint(),
            TimeoutBody::Plain { body } => body.size_hint(),
        }
    }

    #[inline(always)]
    fn is_end_stream(&self) -> bool {
        match self {
            TimeoutBody::TotalTimeout { body } => body.is_end_stream(),
            TimeoutBody::ReadTimeout { body } => body.is_end_stream(),
            TimeoutBody::CombinedTimeout { body } => body.is_end_stream(),
            TimeoutBody::Plain { body } => body.is_end_stream(),
        }
    }
}

#[inline(always)]
fn poll_and_map_body<B>(
    body: Pin<&mut B>,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<http_body::Frame<B::Data>, BoxError>>>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    Poll::Ready(
        ready!(body.poll_frame(cx)).map(|opt| opt.map_err(Error::decode).map_err(Into::into)),
    )
}

// ==== impl TotalTimeoutBody ====
impl<B> Body for TotalTimeoutBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Poll::Ready(()) = this.timeout.as_mut().poll(cx) {
            return Poll::Ready(Some(Err(Error::body(TimedOut).into())));
        }
        poll_and_map_body(this.body, cx)
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
