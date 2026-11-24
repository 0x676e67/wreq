//! Internal synchronization primitives.
//!
//! With the `parking_lot` feature, this module re-exports that crate's locks.
//! Otherwise it wraps the standard library's [`Mutex`](::std::sync::Mutex) and
//! [`RwLock`](::std::sync::RwLock), recovering the guard from a
//! [`PoisonError`](::std::sync::PoisonError) after a panic.

#[cfg(all(any(feature = "http2", feature = "http3"), target_has_atomic = "64"))]
use ::std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "parking_lot")]
pub use parking_lot::*;

#[cfg(not(feature = "parking_lot"))]
pub use self::std::*;

/// A shared 64-bit word backed by a native atomic when available.
/// Other targets use the configured [`Mutex`], which can allocate on first use on some platforms.
#[cfg(any(feature = "http2", feature = "http3"))]
#[repr(transparent)]
pub(crate) struct Word64 {
    #[cfg(target_has_atomic = "64")]
    inner: AtomicU64,
    #[cfg(not(target_has_atomic = "64"))]
    inner: Mutex<u64>,
}

#[cfg(any(feature = "http2", feature = "http3"))]
impl Word64 {
    /// Creates a word with the given initial value.
    pub(crate) const fn new(value: u64) -> Self {
        Self {
            inner: cfg_select! {
                target_has_atomic = "64" => AtomicU64::new(value),
                _ => Mutex::new(value),
            },
        }
    }

    /// Loads the current value with acquire ordering.
    #[inline]
    #[must_use]
    pub(crate) fn load(&self) -> u64 {
        cfg_select! {
            target_has_atomic = "64" => self.inner.load(Ordering::Acquire),
            _ => *self.inner.lock(),
        }
    }

    /// Adds with wrapping and returns the previous value with relaxed ordering.
    #[inline]
    pub(crate) fn fetch_add(&self, value: u64) -> u64 {
        cfg_select! {
            target_has_atomic = "64" => self.inner.fetch_add(value, Ordering::Relaxed),
            _ => {
                let mut word = self.inner.lock();
                let previous = *word;
                *word = previous.wrapping_add(value);
                previous
            }
        }
    }

    /// Updates the value with acquire-release ordering, retrying if it changed.
    /// Returns the previous value, or the observed value in `Err` if `update` declines it.
    #[inline]
    pub(crate) fn try_update(&self, update: impl FnMut(u64) -> Option<u64>) -> Result<u64, u64> {
        cfg_select! {
            target_has_atomic = "64" => {
                self.inner
                    .try_update(Ordering::AcqRel, Ordering::Acquire, update)
            }
            _ => {
                let mut update = update;
                let mut previous = self.load();
                loop {
                    // The callback may read a caller-provided clock. Keep it outside the lock.
                    let next = update(previous).ok_or(previous)?;
                    let mut word = self.inner.lock();
                    if *word == previous {
                        *word = next;
                        return Ok(previous);
                    }
                    previous = *word;
                }
            }
        }
    }
}

#[cfg(not(feature = "parking_lot"))]
mod std {
    use std::{
        ops::{Deref, DerefMut},
        sync,
    };

    /// A [`Mutex`] that never poisons and has the same interface as [`std::sync::Mutex`].
    ///
    /// See [`crate::sync`] for more details.
    #[derive(Debug)]
    pub struct Mutex<T: ?Sized>(sync::Mutex<T>);

    impl<T> Mutex<T> {
        /// Like [`std::sync::Mutex::new`].
        #[inline]
        pub const fn new(t: T) -> Mutex<T> {
            Mutex(sync::Mutex::new(t))
        }
    }

    impl<T: ?Sized> Mutex<T> {
        /// Like [`std::sync::Mutex::lock`].
        #[inline]
        pub fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
            MutexGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// Like [`std::sync::MutexGuard`].
    #[must_use]
    pub struct MutexGuard<'a, T: ?Sized + 'a>(sync::MutexGuard<'a, T>);

    impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0.deref()
        }
    }

    impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            self.0.deref_mut()
        }
    }

    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Mutex(Default::default())
        }
    }

    /// A [`RwLock`] that never poisons and has the same interface as [`std::sync::RwLock`].
    ///
    /// See [`crate::sync`] for more details.
    #[derive(Debug, Default)]
    pub struct RwLock<T: ?Sized>(sync::RwLock<T>);

    impl<T: ?Sized> RwLock<T> {
        /// Like [`std::sync::RwLock::read`].
        #[inline]
        pub fn read<'a>(&'a self) -> RwLockReadGuard<'a, T> {
            RwLockReadGuard(self.0.read().unwrap_or_else(|e| e.into_inner()))
        }

        /// Like [`std::sync::RwLock::write`].
        #[inline]
        pub fn write<'a>(&'a self) -> RwLockWriteGuard<'a, T> {
            RwLockWriteGuard(self.0.write().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// Like [`std::sync::RwLockReadGuard`].
    #[must_use]
    pub struct RwLockReadGuard<'a, T: ?Sized + 'a>(sync::RwLockReadGuard<'a, T>);

    impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0.deref()
        }
    }

    /// Like [`std::sync::RwLockWriteGuard`].
    #[must_use]
    pub struct RwLockWriteGuard<'a, T: ?Sized + 'a>(sync::RwLockWriteGuard<'a, T>);

    impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0.deref()
        }
    }

    impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            self.0.deref_mut()
        }
    }
}
