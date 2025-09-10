//! Synchronization primitives: [`Mutex`] and [`RwLock`] that never poison.
//!
//! These types expose APIs identical to [`std::sync::Mutex`] and [`std::sync::RwLock`],
//! but **do not return** [`std::sync::PoisonError`] even if a thread panics while holding the lock.
//!
//! This is useful in high-availability systems where panic recovery is done externally,
//! or poisoning is not meaningful in context.

use std::{
    ops::{Deref, DerefMut},
    sync,
};

/// A [`Mutex`] that never poisons and has the same interface as [`std::sync::Mutex`].
pub struct Mutex<T: ?Sized>(sync::Mutex<T>);

impl<T> Mutex<T> {
    /// Like [`std::sync::Mutex::new`].
    #[inline]
    pub fn new(t: T) -> Mutex<T> {
        Mutex(sync::Mutex::new(t))
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Like [`std::sync::Mutex::lock`].
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        MutexGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl<T> Default for Mutex<T>
where
    T: Default,
{
    #[inline]
    fn default() -> Self {
        Mutex::new(T::default())
    }
}

/// Like [`std::sync::MutexGuard`].
#[must_use]
pub struct MutexGuard<'a, T: ?Sized + 'a>(sync::MutexGuard<'a, T>);

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.0.deref()
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.0.deref_mut()
    }
}

/// A [`RwLock`] that never poisons and has the same interface as [`std::sync::RwLock`].
pub struct RwLock<T: ?Sized>(sync::RwLock<T>);

impl<T> RwLock<T> {
    /// Like [`std::sync::RwLock::new`].
    #[inline]
    pub fn new(t: T) -> RwLock<T> {
        RwLock(sync::RwLock::new(t))
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Like [`std::sync::RwLock::read`].
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        RwLockReadGuard(self.0.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Like [`std::sync::RwLock::write`].
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        RwLockWriteGuard(self.0.write().unwrap_or_else(|e| e.into_inner()))
    }
}

impl<T> Default for RwLock<T>
where
    T: Default,
{
    #[inline]
    fn default() -> Self {
        RwLock::new(T::default())
    }
}

/// Like [`std::sync::RwLockReadGuard`].
#[must_use]
pub struct RwLockReadGuard<'a, T: ?Sized + 'a>(sync::RwLockReadGuard<'a, T>);

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.0.deref()
    }
}

/// Like [`std::sync::RwLockWriteGuard`].
#[must_use]
pub struct RwLockWriteGuard<'a, T: ?Sized + 'a>(sync::RwLockWriteGuard<'a, T>);

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.0.deref()
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.0.deref_mut()
    }
}
