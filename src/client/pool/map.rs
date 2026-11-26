//! Keyed pool map with optional retained-group LRU tracking.
//!
//! Entries are created lazily in an unbounded map, while an optional LRU tracks only
//! groups currently retaining reusable state. Lookups run under the caller's lock, and
//! removed entries are returned so callers can drop connections after unlocking.

use std::{collections::HashMap, hash::Hash, num::NonZeroUsize};

use lru::LruCache;

/// Unsynchronized map from compatibility keys to pool entries with an optional idle-group LRU.
///
/// The caller synchronizes access externally and drops any returned entries after unlocking.
/// Lookups refresh the LRU when a key is already tracked, while the caller decides when an
/// entry gains or loses retained state and performs capacity eviction.
pub(super) struct Map<K, S> {
    /// Pool entries indexed by compatibility key.
    entries: HashMap<K, S>,
    /// LRU of retained groups; stale markers are reconciled before capacity eviction.
    retained: Option<LruCache<K, ()>>,
}

impl<K, S> Map<K, S>
where
    K: Eq + Hash,
{
    /// Creates a lazy map with an optional retained-group LRU limit.
    #[must_use]
    pub(super) fn new(max_size: Option<NonZeroUsize>) -> Self {
        Self {
            entries: HashMap::new(),
            retained: max_size.map(LruCache::new),
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
        // Skip hashing for the single-entry fast path without scanning a sparse table.
        if self.entries.len() == 1 && self.entries.capacity() <= 3 {
            return self
                .entries
                .iter_mut()
                .next()
                .and_then(|(stored, service)| (stored == key).then_some(service));
        }
        self.entries.get_mut(key)
    }

    /// Removes idle markers whose services no longer satisfy `predicate`.
    ///
    /// Returns the pruned keys so the caller can reconcile entries that remain.
    #[must_use]
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

    /// Ensures `key` is tracked as a retained group, promoting it to MRU when `promote` is `true`.
    ///
    /// A full LRU first removes markers rejected by `predicate` and returns their
    /// keys, then the remaining least recently used group displaced by the limit.
    /// An unbounded map returns neither.
    #[must_use]
    pub(super) fn mark_retained<F>(
        &mut self,
        key: &K,
        promote: bool,
        predicate: F,
    ) -> (Vec<K>, Option<K>)
    where
        K: Clone,
        F: FnMut(&S) -> bool,
    {
        let Some(retained) = &mut self.retained else {
            return (Vec::new(), None);
        };
        let present = if promote {
            retained.get(key).is_some()
        } else {
            retained.contains(key)
        };
        if present {
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
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut S)> {
        self.entries.iter_mut()
    }

    /// Removes and returns the service for `key` if `predicate` returns `true`.
    #[must_use]
    pub(super) fn remove_if<F>(&mut self, key: &K, predicate: F) -> Option<S>
    where
        F: FnOnce(&mut S) -> bool,
    {
        let remove = self.entries.get_mut(key).is_some_and(predicate);
        if remove {
            self.unmark_retained(key);
            self.entries.remove(key)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    impl<K, S> Map<K, S> {
        #[must_use]
        pub(in crate::client::pool) fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
    }

    /// Counts drops while letting tests toggle retained state.
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
        assert!(map.get_mut(&1).is_some());
        assert!(map.get_mut(&2).is_none());
        assert_eq!(map.mark_retained(&1, true, |probe| probe.1), (vec![], None));
        map.get_or_insert_with(&2, make);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let (pruned, evicted) = map.mark_retained(&2, true, |probe| probe.1);
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
            assert_eq!(map.mark_retained(&key, true, retains), (vec![], None));
        }
        for _ in 0..100 {
            assert_eq!(map.mark_retained(&1, true, retains), (vec![], None));
        }
        assert_eq!(inspected.load(Ordering::Relaxed), 0);

        // Lose the most recent group's idle state without removing its entry.
        // Its stale marker is reported for cleanup and must not evict the
        // healthy least recent group (2).
        map.get_or_insert_with(&3, make).1 = false;
        map.get_or_insert_with(&4, make);
        assert_eq!(map.mark_retained(&4, true, retains), (vec![3], None));
        assert_eq!(inspected.load(Ordering::Relaxed), 3);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        map.get_or_insert_with(&5, make);
        assert_eq!(map.mark_retained(&5, true, retains), (vec![], Some(2)));
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
