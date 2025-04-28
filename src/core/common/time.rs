use std::time::Duration;
use std::{fmt, sync::Arc};
use std::{pin::Pin, time::Instant};

use crate::core::rt::Sleep;
use crate::core::rt::Timer;

/// A user-provided timer to time background tasks.
#[derive(Clone)]
pub(crate) enum Time {
    Timer(Arc<dyn Timer + Send + Sync>),
    Empty,
}

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Time").finish()
    }
}

impl Time {
    pub(crate) fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        match *self {
            Time::Empty => {
                panic!("You must supply a timer.")
            }
            Time::Timer(ref t) => t.sleep(duration),
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
