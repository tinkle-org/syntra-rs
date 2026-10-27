//! Bounded duplicate-result cache.
//!
//! The coordinator compares cursor bytes by equality only, so an older
//! duplicate whose result no longer equals the committed cursor is
//! indistinguishable from a gap and returns `RecoveryNeeded`. The
//! application holds a bounded recent-result cache keyed by checkpoint
//! bytes to answer such duplicates without re-applying effects: a hit
//! returns the cached result without touching persistence or the
//! coordinator, a miss goes through the normal validate/offer/persist/
//! confirm path. The cache is strictly bounded: insertion beyond capacity
//! evicts the oldest entry first (FIFO). It never grows without bound.

use std::collections::{HashSet, VecDeque};

/// Bounded FIFO cache of recently confirmed result keys.
///
/// Keys are opaque checkpoint encodings chosen by the driver (typically
/// `generation || base || result`). Equality only; no ordering or parsing.
#[derive(Debug)]
pub struct DuplicateCache {
    capacity: usize,
    order: VecDeque<Vec<u8>>,
    set: HashSet<Vec<u8>>,
}

impl DuplicateCache {
    /// Cache holding at most `capacity` keys. Zero capacity caches nothing.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    /// Maximum entries retained.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Entries currently retained.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// True when no entries are retained.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// True when `key` was recently confirmed and retained.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.set.contains(key)
    }

    /// Record a confirmed result. Duplicate inserts are no-ops. Beyond
    /// capacity the oldest entry is evicted first.
    pub fn insert(&mut self, key: Vec<u8>) {
        if self.capacity == 0 {
            return;
        }
        if self.set.contains(&key) {
            return;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.set.insert(key);
    }

    /// Forget all entries.
    pub fn clear(&mut self) {
        self.order.clear();
        self.set.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_avoids_reapply_miss_goes_through() {
        let mut c = DuplicateCache::new(4);
        assert!(!c.contains(b"k1"));
        c.insert(b"k1".to_vec());
        assert!(c.contains(b"k1"));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn bounded_fifo_evicts_oldest() {
        let mut c = DuplicateCache::new(2);
        c.insert(b"a".to_vec());
        c.insert(b"b".to_vec());
        assert!(c.contains(b"a"));
        c.insert(b"c".to_vec());
        assert!(!c.contains(b"a"), "oldest must be evicted first");
        assert!(c.contains(b"b"));
        assert!(c.contains(b"c"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn duplicate_insert_is_noop_and_zero_capacity_caches_nothing() {
        let mut c = DuplicateCache::new(2);
        c.insert(b"a".to_vec());
        c.insert(b"a".to_vec());
        assert_eq!(c.len(), 1);
        let mut z = DuplicateCache::new(0);
        z.insert(b"a".to_vec());
        assert!(z.is_empty());
    }
}
