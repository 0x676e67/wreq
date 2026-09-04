//! Maps connection destinations to independently managed pool services.
//!
//! [`Map`] is the outer routing component of the pool. [`Target`] derives a
//! complete connection compatibility key and constructs the service for a new
//! key. A lookup therefore follows this model:
//!
//! ```text
//! destination -> compatibility key -> cache/negotiation service
//! ```
//!
//! Entries are created lazily and may be bounded by an LRU limit. Eviction only
//! removes an entry from future lookup. Checkouts already holding clones of its
//! shared state can finish normally.
//!
//! # Example
//!
//! The pool coordinator performs lookup while holding its map lock, then drops
//! any evicted service after releasing that lock:
//!
//! ```rust,ignore
//! let ((checkout, discarded), evicted) = map.with_service(target, |service, target| {
//!     let discarded = service.retain(now, idle_timeout);
//!     let checkout = service.checkout(target, true);
//!     (checkout, discarded)
//! });
//! drop(evicted);
//! drop(discarded);
//! let sender = checkout.await?;
//! ```

use std::{hash::Hash, marker::PhantomData, num::NonZeroUsize};

use lru::LruCache;

/// Lazily maps destination keys to independently managed pool services.
///
/// `Map` owns no synchronization. The pool coordinator locks it around lookup
/// and maintenance operations. Methods that remove an entry return the service
/// to the caller so connection senders and capacity permits can be dropped only
/// after that outer lock has been released.
///
/// Successful lookups refresh LRU order. A miss creates one service through the
/// configured [`Target`] and may return the least recently used service as an
/// eviction. Returning removals instead of dropping them internally is part of
/// the type's contract: mapped services may own senders, permits, and wakers
/// whose destructors can re-enter other pool components.
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

/// Defines how destinations are grouped and how each group service is created.
///
/// `Key` must include every setting that affects physical connection reuse.
/// Destinations with the same key share a `Service`; destinations with different
/// keys remain isolated even when their URI origins match.
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

    /// Applies `operation` to the service for `dst` and returns any LRU eviction.
    ///
    /// The caller can drop the evicted service after releasing its outer lock.
    pub(super) fn with_service<R, F>(&mut self, dst: Dst, operation: F) -> (R, Option<T::Service>)
    where
        T::Key: Clone,
        F: FnOnce(&mut T::Service, Dst) -> R,
    {
        let key = self.targeter.key(&dst);
        if let Some(service) = self.entries.get_mut(&key) {
            return (operation(service, dst), None);
        }

        let evicted = self
            .entries
            .push(key.clone(), self.targeter.service(&dst))
            .map(|(_, service)| service);
        let targeter = &self.targeter;
        let service = self
            .entries
            .get_or_insert_mut(key, || targeter.service(&dst));
        (operation(service, dst), evicted)
    }

    /// Retains entries selected by `predicate` and returns removed services.
    ///
    /// Keys are collected before removal because `LruCache` cannot be mutated
    /// while its entries are being visited.
    pub(super) fn retain<F>(&mut self, mut predicate: F) -> Vec<T::Service>
    where
        T::Key: Clone,
        F: FnMut(&T::Key, &mut T::Service) -> bool,
    {
        let removed = self
            .entries
            .iter_mut()
            .filter_map(|(key, service)| (!predicate(key, service)).then(|| key.clone()))
            .collect::<Vec<_>>();

        removed
            .into_iter()
            .filter_map(|key| self.entries.pop(&key))
            .collect()
    }

    /// Iterates from most to least recently used without changing LRU order.
    pub(super) fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = (&T::Key, &mut T::Service)> {
        self.entries.iter_mut()
    }

    /// Removes `key` when its current service satisfies `predicate`.
    pub(super) fn remove_if<F>(&mut self, key: &T::Key, predicate: F) -> Option<T::Service>
    where
        F: FnOnce(&T::Service) -> bool,
    {
        let remove = self.entries.peek(key).is_some_and(predicate);
        remove.then(|| self.entries.pop(key)).flatten()
    }

    /// Returns whether the map currently contains no service entries.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// Counts when a mapped service is actually destroyed.
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Creates one drop probe for each numeric destination.
    struct ProbeTarget(Arc<AtomicUsize>);

    impl Target<usize> for ProbeTarget {
        type Key = usize;
        type Service = DropProbe;

        fn key(&self, dst: &usize) -> Self::Key {
            *dst
        }

        fn service(&self, _dst: &usize) -> Self::Service {
            DropProbe(self.0.clone())
        }
    }

    #[test]
    fn removed_services_are_returned_for_deferred_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut map = Map::new(ProbeTarget(drops.clone()), NonZeroUsize::new(1));

        let (_, evicted) = map.with_service(1, |_, _| ());
        assert!(evicted.is_none());
        let (_, evicted) = map.with_service(2, |_, _| ());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(evicted);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let removed = map.remove_if(&2, |_| true);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(removed);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}
