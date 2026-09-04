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
//! Entries are created lazily in an unbounded routing map. An optional LRU tracks
//! only entries that currently retain reusable connection state, preserving the
//! legacy pool's global idle-host limit without counting active work.
//!
//! # Example
//!
//! The pool coordinator performs lookup while holding its map lock, then drops
//! any evicted service after releasing that lock:
//!
//! ```rust,ignore
//! let (checkout, discarded) = map.with_service(target, |service, target| {
//!     let discarded = service.retain(now, idle_timeout);
//!     let checkout = service.checkout(target, true);
//!     (checkout, discarded)
//! });
//! drop(discarded);
//! let sender = checkout.await?;
//! ```

use std::{collections::HashMap, hash::Hash, marker::PhantomData, num::NonZeroUsize};

use lru::LruCache;

/// Lazily maps destination keys to independently managed pool services.
///
/// `Map` owns no synchronization. The pool coordinator locks it around lookup
/// and maintenance operations. Methods that remove an entry return the service
/// to the caller so connection senders can be dropped only after that outer
/// lock has been released.
///
/// A miss creates one service through the configured [`Target`]. Successful
/// lookups refresh the optional idle-group LRU only when that key is already
/// tracked. The pool coordinator decides when a service gains or loses reusable
/// state and performs any resulting eviction outside this type.
pub(super) struct Map<T, Dst>
where
    T: Target<Dst>,
{
    /// Services indexed by connection compatibility key.
    entries: HashMap<T::Key, T::Service>,

    /// Least-recently-used keys that currently retain reusable state.
    retained: Option<LruCache<T::Key, ()>>,

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
    /// Creates a lazy map with an optional retained-group LRU limit.
    pub(super) fn new(targeter: T, max_retained: Option<NonZeroUsize>) -> Self {
        Self {
            entries: HashMap::new(),
            retained: max_retained.map(LruCache::new),
            targeter,
            _dst: PhantomData,
        }
    }

    /// Applies `operation` to the service for `dst`.
    pub(super) fn with_service<R, F>(&mut self, dst: Dst, operation: F) -> R
    where
        T::Key: Clone,
        F: FnOnce(&mut T::Service, Dst) -> R,
    {
        let key = self.targeter.key(&dst);
        if let Some(retained) = &mut self.retained {
            let _ = retained.get(&key);
        }

        let targeter = &self.targeter;
        let service = self
            .entries
            .entry(key)
            .or_insert_with(|| targeter.service(&dst));
        operation(service, dst)
    }

    /// Returns the service stored for `key` without changing idle LRU order.
    pub(super) fn get_mut(&mut self, key: &T::Key) -> Option<&mut T::Service> {
        self.entries.get_mut(key)
    }

    /// Removes idle markers whose services no longer satisfy `predicate`.
    pub(super) fn prune_retained<F>(&mut self, mut predicate: F)
    where
        T::Key: Clone,
        F: FnMut(&T::Service) -> bool,
    {
        let Some(retained) = &mut self.retained else {
            return;
        };
        retained
            .iter()
            .filter(|(key, ())| {
                self.entries
                    .get(*key)
                    .is_none_or(|service| !predicate(service))
            })
            .map(|(key, ())| key.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|key| {
                let _ = retained.pop(&key);
            });
    }

    /// Marks `key` as the most recently used retained group.
    ///
    /// The returned key is the least recently used group displaced by the
    /// configured limit. An unbounded map returns `None`.
    pub(super) fn mark_retained(&mut self, key: &T::Key) -> Option<T::Key>
    where
        T::Key: Clone,
    {
        let retained = self.retained.as_mut()?;
        if retained.get(key).is_some() {
            return None;
        }
        retained.push(key.clone(), ()).map(|(key, ())| key)
    }

    /// Stops counting `key` as a retained idle group.
    pub(super) fn unmark_retained(&mut self, key: &T::Key) {
        if let Some(retained) = &mut self.retained {
            let _ = retained.pop(key);
        }
    }

    /// Retains entries selected by `predicate` and returns removed services.
    pub(super) fn retain<F>(&mut self, mut predicate: F) -> Vec<T::Service>
    where
        F: FnMut(&T::Key, &mut T::Service) -> bool,
    {
        let retained = &mut self.retained;
        self.entries
            .extract_if(|key, service| {
                let remove = !predicate(key, service);
                if remove {
                    let _ = retained.as_mut().and_then(|retained| retained.pop(key));
                }
                remove
            })
            .map(|(_, service)| service)
            .collect()
    }

    /// Iterates over mapped services without changing idle LRU order.
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&T::Key, &mut T::Service)> {
        self.entries.iter_mut()
    }

    /// Removes `key` when its current service satisfies `predicate`.
    pub(super) fn remove_if<F>(&mut self, key: &T::Key, predicate: F) -> Option<T::Service>
    where
        F: FnOnce(&T::Service) -> bool,
    {
        let remove = self.entries.get(key).is_some_and(predicate);
        if remove {
            self.unmark_retained(key);
            self.entries.remove(key)
        } else {
            None
        }
    }

    /// Returns whether the map contains no service entries.
    #[cfg(test)]
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

        map.with_service(1, |_, _| ());
        assert_eq!(map.mark_retained(&1), None);
        map.with_service(2, |_, _| ());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let evicted = map.mark_retained(&2);
        assert_eq!(evicted, Some(1));
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let removed = map.remove_if(&evicted.unwrap(), |_| true);
        drop(removed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let removed = map.remove_if(&2, |_| true);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(removed);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}
