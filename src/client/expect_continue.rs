use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use pin_project_lite::pin_project;

use crate::error::BoxError;

pub(crate) struct ExpectContinueState {
    signalled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ExpectContinueState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(ExpectContinueState {
            signalled: AtomicBool::new(false),
            waker: Mutex::new(None),
        })
    }

    pub(crate) fn signal(&self) {
        self.signalled.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn is_signalled(&self) -> bool {
        self.signalled.load(Ordering::SeqCst)
    }

    fn store_waker(&self, waker: Waker) {
        *self.waker.lock().unwrap() = Some(waker);
    }
}

pin_project! {
    /// A body wrapper that delays sending until a 100 Continue response
    /// is received or a timeout elapses.
    pub(crate) struct ExpectContinueBody {
        #[pin]
        inner: Option<crate::Body>,
        state: Arc<ExpectContinueState>,
        #[pin]
        sleep: Option<tokio::time::Sleep>,
        done: bool,
    }
}

impl ExpectContinueBody {
    pub(crate) fn new(
        inner: crate::Body,
        state: Arc<ExpectContinueState>,
        timeout: Duration,
    ) -> Self {
        ExpectContinueBody {
            inner: Some(inner),
            state,
            sleep: Some(tokio::time::sleep(timeout)),
            done: false,
        }
    }
}

impl HttpBody for ExpectContinueBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        if !*this.done {
            if this.state.is_signalled() {
                *this.done = true;
                this.sleep.set(None);
            } else if let Some(sleep) = this.sleep.as_pin_mut() {
                match sleep.poll(cx) {
                    Poll::Ready(()) => {
                        *this.done = true;
                        this.sleep.set(None);
                    }
                    Poll::Pending => {
                        this.state.store_waker(cx.waker().clone());
                        return Poll::Pending;
                    }
                }
            }
        }

        match this.inner.as_pin_mut() {
            Some(inner) => match inner.poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().map_or(true, |b| b.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(SizeHint::default, |b| b.size_hint())
    }
}
