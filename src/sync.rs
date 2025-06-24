//! Synchronization primitives: [`Mutex`] and [`RwLock`] that never poison.
//!
//! These types expose APIs identical to [`std::sync::Mutex`] and [`std::sync::RwLock`],
//! but **do not return** [`std::sync::PoisonError`] even if a thread panics while holding the lock.
//!
//! This is useful in high-availability systems where panic recovery is done externally,
//! or poisoning is not meaningful in context.
//!
//! ## Implementation
//! - When the `parking_lot` feature is enabled, it uses [`parking_lot::Mutex`] and
//!   [`parking_lot::RwLock`].
//! - Otherwise, it wraps [`std::sync::Mutex`] and [`std::sync::RwLock`], using `.unwrap_or_else(|e|
//!   e.into_inner())` to silently recover from poisoning.

#[cfg(all(not(feature = "parking_lot"), test))]
pub use fallback::MutexGuard;
#[cfg(not(feature = "parking_lot"))]
pub use fallback::{Mutex, RwLock};
#[cfg(all(feature = "parking_lot", test))]
pub use parking_lot::MutexGuard;
#[cfg(feature = "parking_lot")]
pub use parking_lot::{Mutex, RwLock};

#[cfg(not(feature = "parking_lot"))]
mod fallback {
    use std::{
        fmt,
        ops::{Deref, DerefMut},
        sync,
    };

    /// A `Mutex` that never poisons and has the same interface as `std::sync::Mutex`.
    ///
    /// See [`crate::sync`] for more details.
    pub struct Mutex<T: ?Sized>(sync::Mutex<T>);

    impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, fmt)
        }
    }

    impl<T> Mutex<T> {
        /// Like `std::sync::Mutex::new`.
        #[inline]
        pub fn new(t: T) -> Mutex<T> {
            Mutex(sync::Mutex::new(t))
        }
    }

    impl<T: ?Sized> Mutex<T> {
        /// Like `std::sync::Mutex::lock`.
        #[inline]
        pub fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
            MutexGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// Like `std::sync::MutexGuard`.
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

    /// A `RwLock` that never poisons and has the same interface as `std::sync::RwLock`.
    ///
    /// See [`crate::sync`] for more details.
    pub struct RwLock<T: ?Sized>(sync::RwLock<T>);

    impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, fmt)
        }
    }

    impl<T> RwLock<T> {
        /// Like `std::sync::RwLock::new`.
        #[inline]
        pub fn new(t: T) -> RwLock<T> {
            RwLock(sync::RwLock::new(t))
        }
    }

    impl<T: ?Sized> RwLock<T> {
        /// Like `std::sync::RwLock::read`.
        #[inline]
        pub fn read<'a>(&'a self) -> RwLockReadGuard<'a, T> {
            RwLockReadGuard(self.0.read().unwrap_or_else(|e| e.into_inner()))
        }

        /// Like `std::sync::RwLock::write`.
        #[inline]
        pub fn write<'a>(&'a self) -> RwLockWriteGuard<'a, T> {
            RwLockWriteGuard(self.0.write().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// Like `std::sync::RwLockReadGuard`.
    #[must_use]
    pub struct RwLockReadGuard<'a, T: ?Sized + 'a>(sync::RwLockReadGuard<'a, T>);

    impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0.deref()
        }
    }

    /// Like `std::sync::RwLockWriteGuard`.
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
