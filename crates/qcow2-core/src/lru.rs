//! Minimal LRU cache for `no_std` environments.
//!
//! Provides the same interface as the `lru` crate's `LruCache`, backed by a
//! `Vec` of key-value pairs with linear scan. This is efficient for the small
//! cache sizes used by QCOW2 metadata caching (typically 8–32 entries).

extern crate alloc;

use alloc::vec::Vec;

/// A fixed-capacity least-recently-used cache.
///
/// Keys are compared by equality. On access, the entry moves to the back
/// (most recently used). When the cache is full and a new entry is inserted,
/// the front entry (least recently used) is evicted.
pub struct LruCache<K, V> {
    entries: Vec<(K, V)>,
    capacity: usize,
}

impl<K: PartialEq, V> LruCache<K, V> {
    /// Create a new cache with the given maximum capacity.
    ///
    /// A capacity of zero is treated as one.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Look up a value by key, marking it as most recently used.
    ///
    /// Returns `Some(&V)` if found, `None` otherwise.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        // Move to back (most recently used)
        let entry = self.entries.remove(idx);
        self.entries.push(entry);
        self.entries.last().map(|(_, v)| v)
    }

    /// Insert a key-value pair, evicting the least recently used entry if full.
    ///
    /// If the key already exists, its value is updated and it becomes the
    /// most recently used.
    pub fn put(&mut self, key: K, value: V) {
        // Check for existing key
        if let Some(idx) = self.entries.iter().position(|(k, _)| *k == key) {
            self.entries.remove(idx);
        } else if self.entries.len() >= self.capacity {
            // Evict least recently used (front)
            self.entries.remove(0);
        }
        self.entries.push((key, value));
    }

    /// Remove and return the value for a key, if present.
    pub fn pop(&mut self, key: &K) -> Option<V> {
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(idx).1)
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = LruCache::new(4);
        cache.put(1, "one");
        cache.put(2, "two");
        assert_eq!(cache.get(&1), Some(&"one"));
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), None);
    }

    #[test]
    fn evicts_lru_when_full() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(2, "two");
        cache.put(3, "three"); // evicts 1

        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), Some(&"three"));
    }

    #[test]
    fn access_refreshes_lru_order() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(2, "two");
        cache.get(&1); // refresh 1, now 2 is LRU
        cache.put(3, "three"); // evicts 2

        assert_eq!(cache.get(&1), Some(&"one"));
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&3), Some(&"three"));
    }

    #[test]
    fn put_existing_key_updates_value() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(1, "ONE");
        assert_eq!(cache.get(&1), Some(&"ONE"));
    }

    #[test]
    fn pop_removes_entry() {
        let mut cache = LruCache::new(4);
        cache.put(1, "one");
        assert_eq!(cache.pop(&1), Some("one"));
        assert_eq!(cache.get(&1), None);
    }

    #[test]
    fn pop_nonexistent_returns_none() {
        let mut cache: LruCache<i32, &str> = LruCache::new(4);
        assert_eq!(cache.pop(&42), None);
    }

    #[test]
    fn clear_empties_cache() {
        let mut cache = LruCache::new(4);
        cache.put(1, "one");
        cache.put(2, "two");
        cache.clear();
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), None);
    }

    #[test]
    fn capacity_one() {
        let mut cache = LruCache::new(1);
        cache.put(1, "one");
        cache.put(2, "two"); // evicts 1
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two"));
    }

    #[test]
    fn zero_capacity_treated_as_one() {
        let mut cache = LruCache::new(0);
        cache.put(1, "one");
        assert_eq!(cache.get(&1), Some(&"one"));
    }
}
