//! Maps connection destinations to independently managed pool services.
//!
//! [`Map`] routes each connection compatibility key to its pool service.
//!
//! Entries are created lazily in an unbounded routing map. An optional LRU tracks
//! only entries that currently retain reusable connection state.
//!
//! The pool coordinator performs lookup while holding its map lock, then drops
//! any evicted service after releasing that lock.

use std::{collections::HashMap, hash::Hash, num::NonZeroUsize};

use lru::LruCache;

/// Lazily maps destination keys to independently managed pool services.
///
/// `Map` owns no synchronization. The pool coordinator locks it around lookup
/// and maintenance operations. Methods that remove an entry return the service
/// to the caller so connection senders can be dropped only after that outer
/// lock has been released.
///
/// Lookups refresh the optional idle-group LRU when the key is already tracked.
/// The pool coordinator decides when a service gains or loses reusable state
/// and performs any resulting eviction outside this type.
pub(super) struct Map<K, S> {
    /// Services indexed by connection compatibility key.
    entries: HashMap<K, S>,

    /// Retained-group LRU; stale markers are reconciled before capacity eviction.
    retained: Option<LruCache<K, ()>>,
}

impl<K, S> Map<K, S>
where
    K: Eq + Hash,
{
    /// Creates a lazy map with an optional retained-group LRU limit.
    #[must_use]
    pub(super) fn new(max_retained: Option<NonZeroUsize>) -> Self {
        Self {
            entries: HashMap::new(),
            retained: max_retained.map(LruCache::new),
        }
    }

    /// Returns the service for `key`, creating it on a miss.
    pub(super) fn get_or_insert_with(&mut self, key: &K, make: impl FnOnce() -> S) -> &mut S
    where
        K: Clone,
    {
        if let Some(retained) = &mut self.retained {
            let _ = retained.get(key);
        }
        self.entries.entry(key.clone()).or_insert_with(make)
    }

    /// Returns the service stored for `key` without changing idle LRU order.
    #[must_use]
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut S> {
        self.entries.get_mut(key)
    }

    /// Removes idle markers whose services no longer satisfy `predicate`.
    ///
    /// Returns the pruned keys so the caller can reconcile entries that remain.
    pub(super) fn prune_retained<F>(&mut self, mut predicate: F) -> Vec<K>
    where
        K: Clone,
        F: FnMut(&S) -> bool,
    {
        let Some(retained) = &mut self.retained else {
            return Vec::new();
        };
        // LRU iteration borrows its ordering links. Collect keys before removal
        // so pruning cannot invalidate the iterator or reorder surviving groups.
        let pruned = retained
            .iter()
            .filter(|(key, ())| {
                self.entries
                    .get(*key)
                    .is_none_or(|service| !predicate(service))
            })
            .map(|(key, ())| key.clone())
            .collect::<Vec<_>>();
        for key in &pruned {
            let _ = retained.pop(key);
        }
        pruned
    }

    /// Marks `key` as the most recently used retained group.
    ///
    /// A full LRU first removes markers rejected by `predicate` and returns their
    /// keys, then the remaining least recently used group displaced by the limit.
    /// An unbounded map returns neither.
    #[must_use]
    pub(super) fn mark_retained<F>(&mut self, key: &K, predicate: F) -> (Vec<K>, Option<K>)
    where
        K: Clone,
        F: FnMut(&S) -> bool,
    {
        let Some(retained) = &mut self.retained else {
            return (Vec::new(), None);
        };
        if retained.get(key).is_some() {
            return (Vec::new(), None);
        }

        // Checkout/return updates its own key. Other entries can lose reusable
        // state independently, but only a full LRU needs that state reconciled.
        // Scan all markers before eviction: a stale MRU must free capacity before
        // a healthy LRU is displaced. Hot hits need neither this scan nor a Vec.
        let pruned = if retained.len() == retained.cap().get() {
            self.prune_retained(predicate)
        } else {
            Vec::new()
        };
        let evicted = self
            .retained
            .as_mut()
            .and_then(|retained| retained.push(key.clone(), ()))
            .map(|(key, ())| key);
        (pruned, evicted)
    }

    /// Stops counting `key` as a retained idle group.
    pub(super) fn unmark_retained(&mut self, key: &K) {
        if let Some(retained) = &mut self.retained {
            let _ = retained.pop(key);
        }
    }

    /// Retains entries selected by `predicate` and returns removed services.
    #[must_use]
    pub(super) fn retain<F>(&mut self, mut predicate: F) -> Vec<S>
    where
        F: FnMut(&K, &mut S) -> bool,
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
    #[must_use]
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut S)> {
        self.entries.iter_mut()
    }

    /// Removes `key` when its current service satisfies `predicate`.
    #[must_use]
    pub(super) fn remove_if<F>(&mut self, key: &K, predicate: F) -> Option<S>
    where
        F: FnOnce(&S) -> bool,
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

    #[test]
    fn removed_services_are_returned_for_deferred_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let make = || DropProbe(drops.clone(), true);
        let mut map = Map::new(NonZeroUsize::new(1));

        map.get_or_insert_with(&1, make);
        assert_eq!(map.mark_retained(&1, |probe| probe.1), (vec![], None));
        map.get_or_insert_with(&2, make);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let (pruned, evicted) = map.mark_retained(&2, |probe| probe.1);
        assert!(pruned.is_empty());
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
        let make = || DropProbe(drops.clone(), true);
        let mut map = Map::new(NonZeroUsize::new(3));
        let inspected = AtomicUsize::new(0);
        let retains = |probe: &DropProbe| {
            inspected.fetch_add(1, Ordering::Relaxed);
            probe.1
        };

        for key in 1..=3 {
            map.get_or_insert_with(&key, make);
            assert_eq!(map.mark_retained(&key, retains), (vec![], None));
        }
        for _ in 0..100 {
            assert_eq!(map.mark_retained(&1, retains), (vec![], None));
        }
        assert_eq!(inspected.load(Ordering::Relaxed), 0);

        // Lose the most recent group's idle state without removing its entry.
        // Its stale marker is reported for cleanup and must not evict the
        // healthy least recent group (2).
        map.get_or_insert_with(&3, make).1 = false;
        map.get_or_insert_with(&4, make);
        assert_eq!(map.mark_retained(&4, retains), (vec![3], None));
        assert_eq!(inspected.load(Ordering::Relaxed), 3);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        map.get_or_insert_with(&5, make);
        assert_eq!(map.mark_retained(&5, retains), (vec![], Some(2)));
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
