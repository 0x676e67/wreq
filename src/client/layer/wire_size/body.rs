use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;

use super::CompressedSize;

pin_project! {
    /// A body wrapper that counts bytes as they are read.
    ///
    /// This body wraps an inner body and tracks the total number of bytes
    /// that flow through it, updating the associated `CompressedSize` counter.
    pub struct CountingBody<B> {
        #[pin]
        inner: B,
        counter: CompressedSize,
    }
}

impl<B> CountingBody<B> {
    /// Creates a new `CountingBody` wrapping the given body.
    pub fn new(inner: B, counter: CompressedSize) -> Self {
        Self { inner, counter }
    }
}

impl<B> Body for CountingBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Count data frames
                if let Some(data) = frame.data_ref() {
                    this.counter.add(data.remaining() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
