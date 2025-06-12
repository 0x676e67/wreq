use crate::error::{BoxError, TimedOut};
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
    /// Middleware that applies a timeout to request and response bodies.
    pub struct TimeoutBody<B> {
        timeout: Duration,
        #[pin]
        sleep: Option<Sleep>,
        #[pin]
        body: B,
    }
}

impl<B> TimeoutBody<B> {
    /// Creates a new [`TimeoutBody`].
    pub fn new(timeout: Duration, body: B) -> Self {
        TimeoutBody {
            timeout,
            sleep: None,
            body,
        }
    }
}

impl<B> Body for TimeoutBody<B>
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
        println!("TimeoutBody::poll_frame: {}", self.timeout.as_millis());
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
