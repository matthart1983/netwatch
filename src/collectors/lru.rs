//! A map capped at a fixed number of entries, evicted least recently used
//! first. The reverse-DNS, GeoIP and WHOIS caches each keep one, keyed by
//! peer address, so a host that talks to millions of peers keeps a few
//! thousand.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

pub(crate) struct BoundedLru<K, V> {
    map: HashMap<K, Slot<V>>,
    /// Entries kept at most.
    cap: usize,
    /// Advanced on every read and write; a slot keeps the value from its
    /// last one.
    clock: u64,
}

struct Slot<V> {
    value: V,
    used: u64,
}

impl<K: Eq + Hash + Clone, V> BoundedLru<K, V> {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap,
            clock: 0,
        }
    }

    /// The value for `key`, which becomes the most recently used.
    pub(crate) fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.clock += 1;
        let clock = self.clock;
        self.map.get_mut(key).map(|slot| {
            slot.used = clock;
            &slot.value
        })
    }

    /// The value for `key` to change in place. Not a use: a background
    /// worker updating an entry does not keep it from eviction.
    pub(crate) fn peek_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get_mut(key).map(|slot| &mut slot.value)
    }

    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.contains_key(key)
    }

    /// Insert or replace. A new key in a full map first evicts the least
    /// recently used quarter, so the sort is paid once per `cap / 4`
    /// insertions.
    pub(crate) fn put(&mut self, key: K, value: V) {
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            let mut by_use: Vec<(u64, K)> = self
                .map
                .iter()
                .map(|(key, slot)| (slot.used, key.clone()))
                .collect();
            by_use.sort_unstable_by_key(|(used, _)| *used);
            // At least one, or a map of fewer than four would never evict.
            for (_, key) in by_use.into_iter().take((self.cap / 4).max(1)) {
                self.map.remove(&key);
            }
        }
        self.clock += 1;
        let used = self.clock;
        self.map.insert(key, Slot { value, used });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recent_quarter() {
        const CAP: usize = 4096;
        let mut entries = BoundedLru::new(CAP);
        let failed = |i: usize| format!("10.0.{}.{}", i / 256, i % 256);
        for i in 0..CAP {
            entries.put(failed(i), ());
        }
        // Read the oldest entry, so it is no longer the least recently used.
        assert!(entries.get(&failed(0)).is_some());
        entries.put("192.0.2.1".into(), ());
        assert_eq!(entries.len(), CAP - CAP / 4 + 1);
        assert!(entries.contains_key(&failed(0)));
        assert!(!entries.contains_key(&failed(1)));
        assert!(entries.contains_key(&failed(CAP / 4 + 1)));
        for i in 0..CAP * 2 {
            entries.put(format!("10.1.{}.{}", i / 256, i % 256), ());
            assert!(entries.len() <= CAP);
        }
    }

    #[test]
    fn replacing_or_peeking_does_not_evict() {
        let mut entries = BoundedLru::new(2);
        entries.put(1, "a");
        entries.put(2, "b");
        entries.put(1, "c");
        *entries.peek_mut(&2).unwrap() = "d";
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(&1), Some(&"c"));
        // Peeking at 2 did not count as a use, so 2 goes first.
        entries.put(3, "e");
        assert!(!entries.contains_key(&2));
        assert!(entries.contains_key(&1));
        assert!(entries.contains_key(&3));
    }
}
