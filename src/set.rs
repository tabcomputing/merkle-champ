//! A persistent CHAMP set: a [`ChampMap`] from keys to `()`, with the same
//! canonical shape, cached identities and structural diff.

use crate::{ChampMap, Change, Identify, Identity, KeyHash, feed};
use sha2::Sha256;
use std::fmt;

/// A persistent set with canonical shape and a cached content identity.
/// `Clone` is O(1).
///
/// Its identity is the identity of the map from its elements to `()`
/// (FORMAT.md, section 8), so a set and a `ChampMap<K, ()>` with the same keys
/// have the same identity.
pub struct ChampSet<K> {
    map: ChampMap<K, ()>,
}

/// One difference between two versions of a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetChange<K> {
    Added(K),
    Removed(K),
}

impl<K> Clone for ChampSet<K> {
    fn clone(&self) -> Self {
        ChampSet {
            map: self.map.clone(),
        }
    }
}

impl<K> Default for ChampSet<K> {
    fn default() -> Self {
        ChampSet {
            map: ChampMap::default(),
        }
    }
}

impl<K: KeyHash + Ord + Clone> ChampSet<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Adds an element; returns true if it was not already present.
    pub fn insert(&mut self, key: K) -> bool {
        if self.map.contains_key(&key) {
            return false;
        }
        self.map.insert(key, ());
        true
    }

    /// Removes an element; returns true if it was present. The resulting
    /// shape is exactly that of a set that never contained it.
    pub fn remove(&mut self, key: &K) -> bool {
        self.map.remove(key).is_some()
    }

    /// Persistent form of [`insert`](Self::insert): a new version.
    pub fn with(&self, key: K) -> Self {
        let mut next = self.clone();
        next.insert(key);
        next
    }

    /// Persistent form of [`remove`](Self::remove): a new version.
    pub fn without(&self, key: &K) -> Self {
        let mut next = self.clone();
        next.remove(key);
        next
    }

    /// Elements in trie order, which is deterministic for given contents.
    pub fn iter(&self) -> impl Iterator<Item = &K> {
        self.map.iter().map(|(k, _)| k)
    }

    /// True if both versions share the same root node.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        self.map.ptr_eq(&other.map)
    }

    /// Checks the canonical-form invariants (for tests and debugging).
    pub fn check_invariants(&self) -> Result<(), String> {
        self.map.check_invariants()
    }

    /// The underlying map from elements to `()`.
    pub fn as_map(&self) -> &ChampMap<K, ()> {
        &self.map
    }
}

impl<K: KeyHash + Ord + Clone + Identify> ChampSet<K> {
    /// The set's content identity, computed lazily and cached.
    pub fn identity(&self) -> Identity {
        self.map.identity()
    }

    /// Elements added and removed from `self` to `other`, using the same
    /// structural walk as [`ChampMap::diff`].
    pub fn diff(&self, other: &Self) -> Vec<SetChange<K>> {
        self.map
            .diff(&other.map)
            .into_iter()
            .map(|c| match c {
                Change::Added(k, ()) => SetChange::Added(k),
                Change::Removed(k, ()) => SetChange::Removed(k),
                Change::Changed(..) => unreachable!("set values never change"),
            })
            .collect()
    }
}

impl<K: KeyHash + Ord + Clone + Identify> Identify for ChampSet<K> {
    /// A nested set contributes tag `t` and its identity (FORMAT.md, section 5).
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b't', &self.identity());
    }
}

impl<K: KeyHash + Ord + Clone + Identify> PartialEq for ChampSet<K> {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl<K: KeyHash + Ord + Clone + Identify> Eq for ChampSet<K> {}

impl<K: fmt::Debug + KeyHash + Ord + Clone> fmt::Debug for ChampSet<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<K: KeyHash + Ord + Clone> FromIterator<K> for ChampSet<K> {
    fn from_iter<I: IntoIterator<Item = K>>(iter: I) -> Self {
        let mut set = ChampSet::new();
        for k in iter {
            set.insert(k);
        }
        set
    }
}

impl<K: KeyHash + Ord + Clone> Extend<K> for ChampSet<K> {
    fn extend<I: IntoIterator<Item = K>>(&mut self, iter: I) {
        for k in iter {
            self.insert(k);
        }
    }
}
