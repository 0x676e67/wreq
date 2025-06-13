#![allow(dead_code)]

use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::core::rt::Sleep;

#[derive(Clone)]
pub(crate) struct Timer(Arc<dyn crate::core::rt::Timer + Send + Sync>);

// =====impl Timer=====
impl Timer {
    pub(crate) fn new<T>(inner: T) -> Self
    where
        T: crate::core::rt::Timer + Send + Sync + 'static,
    {
        Self(Arc::new(inner))
    }
}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timer").finish()
    }
}

impl crate::core::rt::Timer for Timer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        self.0.sleep(duration)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        self.0.sleep_until(deadline)
    }
}
