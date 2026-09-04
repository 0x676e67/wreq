//! Maps connection destinations to independently managed pool services.
//!
//! `Map` is the outermost pool component. [`Target`] derives a compatibility
//! key and builds the service stored for that key. Entries are created lazily
//! and optionally bounded by an LRU limit. Evicting an entry removes it from
//! future lookup; clones already serving requests keep their shared state alive.

use std::{hash::Hash, marker::PhantomData, num::NonZeroUsize};

use lru::LruCache;

/// Lazily maps destination keys to reusable services.
pub(super) struct Map<T, Dst>
where
    T: Target<Dst>,
{
    /// Services indexed by connection compatibility key.
    entries: LruCache<T::Key, T::Service>,
    /// Derives keys and creates missing services.
    targeter: T,
    /// Carries the destination type without owning a destination.
    _dst: PhantomData<fn(Dst)>,
}

/// Defines how a destination is grouped and how its service is created.
pub(super) trait Target<Dst> {
    /// Stable key shared by destinations with compatible connections.
    type Key;
    /// Service responsible for one compatibility group.
    type Service;

    /// Derives the lookup key for `dst`.
    fn key(&self, dst: &Dst) -> Self::Key;

    /// Creates the service used for a previously unseen destination.
    fn service(&self, dst: &Dst) -> Self::Service;
}

impl<T, Dst> Map<T, Dst>
where
    T: Target<Dst>,
    T::Key: Eq + Hash,
{
    /// Creates a lazy map with an optional LRU entry limit.
    pub(super) fn new(targeter: T, max_entries: Option<NonZeroUsize>) -> Self {
        Self {
            entries: max_entries.map_or_else(LruCache::unbounded, LruCache::new),
            targeter,
            _dst: PhantomData,
        }
    }

    /// Returns the service for `dst`, creating it on first access.
    pub(super) fn service(&mut self, dst: &Dst) -> &mut T::Service {
        let key = self.targeter.key(dst);
        self.entries
            .get_or_insert_mut(key, || self.targeter.service(dst))
    }

    /// Retains entries selected by `predicate`.
    ///
    /// Keys are collected before removal because `LruCache` cannot be mutated
    /// while its entries are being visited.
    pub(super) fn retain<F>(&mut self, mut predicate: F)
    where
        T::Key: Clone,
        F: FnMut(&T::Key, &mut T::Service) -> bool,
    {
        let removed = self
            .entries
            .iter_mut()
            .filter_map(|(key, service)| (!predicate(key, service)).then(|| key.clone()))
            .collect::<Vec<_>>();

        for key in removed {
            self.entries.pop(&key);
        }
    }

    /// Iterates over all mapped services without changing their LRU order.
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&T::Key, &mut T::Service)> {
        self.entries.iter_mut()
    }

    /// Returns whether the map currently contains no service entries.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
