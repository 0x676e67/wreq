//! Provides a timer trait with timer-like functions

use std::{
    any::TypeId,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

/// A timer which provides timer-like functions.
pub trait Timer {
    /// Return a future that resolves in `duration` time.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>>;

    /// Return a future that resolves at `deadline`.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>>;

    /// Return an `Instant` representing the current time.
    ///
    /// The default implementation returns [`Instant::now()`].
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Reset a future to resolve at `new_deadline` instead.
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        *sleep = self.sleep_until(new_deadline);
    }
}

/// A future returned by a `Timer`.
pub trait Sleep: Send + Sync + Future<Output = ()> {
    #[doc(hidden)]
    /// This method is private and can not be implemented by downstream crate
    fn __type_id(&self, _: private::Sealed) -> TypeId
    where
        Self: 'static,
    {
        TypeId::of::<Self>()
    }
}

/// A handle to a shared timer instance.
///
/// `TimerHandle` provides a reference-counted, thread-safe handle to any type implementing the
/// [`Timer`] trait. It allows cloning and sharing a timer implementation across multiple components
/// or tasks.
///
/// This is typically used to abstract over different timer backends and to provide a unified
/// interface for spawning sleep futures or scheduling timeouts.
#[derive(Clone)]
pub struct ArcTimer(Arc<dyn Timer + Send + Sync>);

/// A user-provided timer to time background tasks.
#[derive(Clone)]
pub enum Time {
    Timer(ArcTimer),
    Empty,
}

// =====impl Sleep =====

impl dyn Sleep {
    //! This is a re-implementation of downcast methods from std::any::Any

    /// Check whether the type is the same as `T`
    pub fn is<T>(&self) -> bool
    where
        T: Sleep + 'static,
    {
        self.__type_id(private::Sealed {}) == TypeId::of::<T>()
    }

    /// Downcast a pinned &mut Sleep object to its original type
    pub fn downcast_mut_pin<T>(self: Pin<&mut Self>) -> Option<Pin<&mut T>>
    where
        T: Sleep + 'static,
    {
        if self.is::<T>() {
            #[allow(unsafe_code)]
            unsafe {
                let inner = Pin::into_inner_unchecked(self);
                Some(Pin::new_unchecked(
                    &mut *(&mut *inner as *mut dyn Sleep as *mut T),
                ))
            }
        } else {
            None
        }
    }
}

// =====impl ArcTimer =====

impl ArcTimer {
    pub(crate) fn new<T>(inner: T) -> Self
    where
        T: Timer + Send + Sync + 'static,
    {
        Self(Arc::new(inner))
    }
}

impl Timer for ArcTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        self.0.sleep(duration)
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into()
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        self.0.sleep_until(deadline)
    }
}

// =====impl Time =====

impl Time {
    pub(crate) fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        match *self {
            Time::Empty => {
                panic!("You must supply a timer.")
            }
            Time::Timer(ref t) => t.sleep(duration),
        }
    }

    pub(crate) fn now(&self) -> Instant {
        match *self {
            Time::Empty => Instant::now(),
            Time::Timer(ref t) => t.now(),
        }
    }

    pub(crate) fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        match *self {
            Time::Empty => {
                panic!("You must supply a timer.")
            }
            Time::Timer(ref t) => t.reset(sleep, new_deadline),
        }
    }
}

mod private {
    pub struct Sealed {}
}
