//! An SPSC broadcast channel.
//!
//! - The value can only be a `u8`.
//! - The consumer is only notified if the value is different.
//! - The value `0` is reserved for closed.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{self, Poll},
};

use futures_util::task::AtomicWaker;

use crate::client::core::Error;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[must_use = "watch::Value is a bitfield, so the variants are not mutually exclusive"]
pub(super) enum Value {
    Pending = 1,
    Ready = 2,
    Closed = 0,
}

pub(super) fn channel(wanter: bool) -> (Sender, Receiver) {
    let initial = if wanter { Value::Pending } else { Value::Ready };
    let shared = Arc::new(Shared {
        value: AtomicU8::new(initial as _),
        waker: AtomicWaker::new(),
    });

    (
        Sender {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

struct Shared {
    value: AtomicU8,
    waker: AtomicWaker,
}

pub(super) struct Sender {
    shared: Arc<Shared>,
}

pub(super) struct Receiver {
    shared: Arc<Shared>,
}

// ===== impl Sender =====

impl Sender {
    #[inline]
    pub(super) fn send(&mut self, value: Value) {
        if self.shared.value.swap(value as u8, Ordering::SeqCst) != value as u8 {
            self.shared.waker.wake();
        }
    }
}

impl Drop for Sender {
    #[inline]
    fn drop(&mut self) {
        self.send(Value::Closed);
    }
}

// ===== impl Receiver =====

impl Future for Receiver {
    type Output = Result<(), Error>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.shared.waker.register(cx.waker());
        match self.shared.value.load(Ordering::SeqCst) {
            2 => Poll::Ready(Ok(())),
            1 => Poll::Pending,
            0 => Poll::Ready(Err(Error::new_closed())),
            unexpected => unreachable!("watch value: {}", unexpected),
        }
    }
}
