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
//! let (checkout, discarded) = map.with_service(&targeter, target, |service, target| {
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
/// A miss creates one service through the borrowed [`Target`]. Successful
/// lookups refresh the optional idle-group LRU only when that key is already
/// tracked. The pool coordinator decides when a service gains or loses reusable
/// state and performs any resulting eviction outside this type.
pub(super) struct Map<T, Dst>
where
    T: Target<Dst>,
{
    /// Services indexed by connection compatibility key.
    entries: HashMap<T::Key, T::Service>,

    /// Retained-group LRU; stale markers are reconciled before capacity eviction.
    retained: Option<LruCache<T::Key, ()>>,

    /// Names the borrowed factory and destination without owning either.
    _target: PhantomData<fn(T, Dst)>,
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
    pub(super) fn new(max_retained: Option<NonZeroUsize>) -> Self {
        Self {
            entries: HashMap::new(),
            retained: max_retained.map(LruCache::new),
            _target: PhantomData,
        }
    }

    /// Applies `operation` to the service for `dst`, creating it on a miss.
    /// The coordinator supplies its factory without copying it into the map.
    pub(super) fn with_service<R, F>(&mut self, targeter: &T, dst: Dst, operation: F) -> R
    where
        T::Key: Clone,
        F: FnOnce(&mut T::Service, Dst) -> R,
    {
        let key = targeter.key(&dst);
        if let Some(retained) = &mut self.retained {
            let _ = retained.get(&key);
        }

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
        // LRU iteration borrows its ordering links. Collect keys before removal
        // so pruning cannot invalidate the iterator or reorder surviving groups.
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
    /// A full LRU removes markers rejected by `predicate` before eviction.
    /// The returned key is the remaining least recently used group displaced by
    /// the limit. An unbounded map returns `None`.
    pub(super) fn mark_retained<F>(&mut self, key: &T::Key, predicate: F) -> Option<T::Key>
    where
        T::Key: Clone,
        F: FnMut(&T::Service) -> bool,
    {
        let retained = self.retained.as_mut()?;
        if retained.get(key).is_some() {
            return None;
        }

        // Checkout/return updates its own key. Other entries can lose reusable
        // state independently, but only a full LRU needs that state reconciled.
        // Scan all markers before eviction: a stale MRU must free capacity before
        // a healthy LRU is displaced. Hot hits need neither this scan nor a Vec.
        if retained.len() == retained.cap().get() {
            self.prune_retained(predicate);
        }
        self.retained
            .as_mut()?
            .push(key.clone(), ())
            .map(|(key, ())| key)
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

    /// Models retained state and counts when a mapped service is destroyed.
    /// The flag lets the test change retention without replacing the entry.
    /// Drop updates a shared counter to verify deferred destruction.
    struct DropProbe(Arc<AtomicUsize>, bool);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Creates one drop probe for each numeric destination.
    /// Uses the destination unchanged as the map key.
    /// All probes share a counter that remains readable after their removal.
    struct ProbeTarget(Arc<AtomicUsize>);

    impl Target<usize> for ProbeTarget {
        type Key = usize;
        type Service = DropProbe;

        fn key(&self, dst: &usize) -> Self::Key {
            *dst
        }

        fn service(&self, _dst: &usize) -> Self::Service {
            DropProbe(self.0.clone(), true)
        }
    }

    #[test]
    fn removed_services_are_returned_for_deferred_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let targeter = ProbeTarget(drops.clone());
        let mut map = Map::new(NonZeroUsize::new(1));

        map.with_service(&targeter, 1, |_, _| ());
        assert_eq!(map.mark_retained(&1, |probe| probe.1), None);
        map.with_service(&targeter, 2, |_, _| ());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let evicted = map.mark_retained(&2, |probe| probe.1);
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

    #[test]
    fn retained_lru_checks_stale_markers_only_before_eviction() {
        let drops = Arc::new(AtomicUsize::new(0));
        let targeter = ProbeTarget(drops.clone());
        let mut map = Map::new(NonZeroUsize::new(3));
        let inspected = AtomicUsize::new(0);
        let retains = |probe: &DropProbe| {
            inspected.fetch_add(1, Ordering::Relaxed);
            probe.1
        };

        for key in 1..=3 {
            map.with_service(&targeter, key, |_, _| ());
            assert_eq!(map.mark_retained(&key, retains), None);
        }
        for _ in 0..100 {
            assert_eq!(map.mark_retained(&1, retains), None);
        }
        assert_eq!(inspected.load(Ordering::Relaxed), 0);

        // Lose the most recent group's idle state without removing its entry.
        // Its stale marker must not evict the healthy least recent group (2).
        map.with_service(&targeter, 3, |probe, _| probe.1 = false);
        map.with_service(&targeter, 4, |_, _| ());
        assert_eq!(map.mark_retained(&4, retains), None);
        assert_eq!(inspected.load(Ordering::Relaxed), 3);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        map.with_service(&targeter, 5, |_, _| ());
        assert_eq!(map.mark_retained(&5, retains), Some(2));
        assert_eq!(inspected.load(Ordering::Relaxed), 6);
        assert_eq!(
            map.retained
                .as_ref()
                .unwrap()
                .iter()
                .map(|(key, ())| *key)
                .collect::<Vec<_>>(),
            [5, 4, 1]
        );
        let removed = map.remove_if(&2, |_| true);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(removed);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
