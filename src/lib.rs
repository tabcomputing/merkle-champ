//! A persistent hash map and set using CHAMP (Compressed Hash-Array Mapped Prefix
//! trie; Steindorfer and Vinju, OOPSLA 2015), with three properties aimed at
//! content-addressed systems:
//!
//! 1. **Canonical shape.** A map's structure depends only on its contents and
//!    the key placement hash, never on the order of inserts and removals.
//!    Removal re-inlines single entries upward, so deleting a key yields the
//!    same tree as never having inserted it.
//! 2. **Lazily cached identities.** Every node can produce a SHA-256 identity
//!    of its contents. It is computed on first request and cached in the
//!    node; because nodes are shared between versions, a later version only
//!    rehashes the nodes on the paths that changed. Reads and writes compute
//!    key placement hashes but never content identities.
//! 3. **Structural diff.** Two versions are compared by walking both trees
//!    together, skipping shared subtrees by pointer, and by identity when both
//!    identities are already cached.
//!
//! [`ChampMap`] is the map; [`ChampSet`] is a set built on it (a map from
//! elements to `()`), with the same three properties. Both are re-exported at
//! the crate root from the [`map`] and [`set`] modules.
//!
//! ```
//! use merkle_champ::{ChampMap, ChampSet};
//!
//! let v1: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)].into_iter().collect();
//! let v2 = v1.update("a".into(), 10);             // v1 is unchanged
//! assert_eq!(v1.get(&"a".to_string()), Some(&1));
//! assert_eq!(v1.diff(&v2).len(), 1);
//!
//! // History does not matter: equal contents, equal identity.
//! let other: ChampMap<String, u64> = [("b".to_string(), 2), ("a".into(), 1)].into_iter().collect();
//! assert_eq!(v1.identity(), other.identity());
//!
//! let set: ChampSet<u64> = [3, 1, 2].into_iter().collect();
//! assert!(set.contains(&2));
//! ```
//!
//! The identity format (placement hash, traversal, canonical rules, node
//! domains, value encodings, versioning) is specified in `FORMAT.md` and
//! pinned by golden vectors in `tests/golden.rs`.
//!
//! # Requirements on keys and values
//!
//! - `KeyHash` must agree with equality: equal keys have equal hashes.
//! - `Ord` must be a total order consistent with `Eq`.
//! - `Identify` must be injective and self-delimiting: equal values produce
//!   the same encoding and unequal values different ones, or the map identity
//!   is not a content identity.
//! - Anything that affects equality, hashing or identity must not change while
//!   stored (for example through interior mutability): node identities are
//!   cached. The library never evaluates or forces values; callers supply
//!   stable identities for whatever they store.
//!
//! # Untrusted keys
//!
//! The provided placement hashes are deterministic, unkeyed and not
//! cryptographic. Keys chosen by an adversary can be made to collide, which
//! degrades the colliding entries to a linear collision node. For untrusted
//! keys, wrap them in a type whose `KeyHash` is keyed or cryptographic (this
//! defines a different identity format).
//!
//! # Panics in user code
//!
//! `Clone`, comparisons, `KeyHash` and `Identify` are user code. If one of them
//! panics during an update, the map is left unchanged and canonical: every
//! update performs all user calls before it replaces any node, and only
//! clears cached identities after the change beneath them has succeeded.
//! (Copy-on-write copies made before the panic are equal in content.)
//!
//! Updates use copy-on-write paths: cloning a map is O(1), and an update
//! copies only the nodes on the path it changes, in place when a node is not
//! shared with another version.

use sha2::{Digest, Sha256};

pub mod map;
pub mod set;

pub use map::{ChampMap, Change, Iter};
pub use set::{ChampSet, SetChange};

/// A 32-byte SHA-256 content identity.
pub type Identity = [u8; 32];

pub(crate) const BITS: u32 = 5;
pub(crate) const FANOUT_MASK: u64 = 0x1f;
/// Shifts 0, 5, ..., 60 index trie levels; past the last level, keys with
/// identical 64-bit hashes share a collision node.
pub(crate) const HASH_BITS: u32 = 64;

// ---------------------------------------------------------------- hashing

/// Deterministic, portable 64-bit hash used to place a key in the trie.
///
/// It must be identical on every platform and run, since it decides the
/// map's shape and therefore its identity. It need not be cryptographic.
pub trait KeyHash {
    fn key_hash(&self) -> u64;
}

/// FNV-1a over bytes, finished with the MurmurHash3 64-bit mixer so the low
/// bits used by the first trie levels are well distributed.
pub fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    mix64(h ^ bytes.len() as u64)
}

fn mix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

impl KeyHash for str {
    fn key_hash(&self) -> u64 {
        hash_bytes(self.as_bytes())
    }
}
impl KeyHash for String {
    fn key_hash(&self) -> u64 {
        hash_bytes(self.as_bytes())
    }
}
impl KeyHash for [u8] {
    fn key_hash(&self) -> u64 {
        hash_bytes(self)
    }
}
impl KeyHash for Vec<u8> {
    fn key_hash(&self) -> u64 {
        hash_bytes(self)
    }
}
impl KeyHash for u64 {
    fn key_hash(&self) -> u64 {
        mix64(*self)
    }
}
impl KeyHash for i64 {
    fn key_hash(&self) -> u64 {
        mix64(*self as u64)
    }
}

/// Feeds a value's canonical content into an identity hash.
///
/// Implementations must be injective over the values that can occur, which in
/// practice means a type tag plus length-prefixed bytes.
pub trait Identify {
    fn identify(&self, hasher: &mut Sha256);
}

pub(crate) fn feed(hasher: &mut Sha256, tag: u8, bytes: &[u8]) {
    hasher.update([tag]);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

impl Identify for str {
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b's', self.as_bytes());
    }
}
impl Identify for String {
    fn identify(&self, hasher: &mut Sha256) {
        self.as_str().identify(hasher);
    }
}
impl Identify for [u8] {
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b'b', self);
    }
}
impl Identify for Vec<u8> {
    fn identify(&self, hasher: &mut Sha256) {
        self.as_slice().identify(hasher);
    }
}
impl Identify for u64 {
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b'u', &self.to_le_bytes());
    }
}
impl Identify for i64 {
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b'i', &self.to_le_bytes());
    }
}
impl Identify for Identity {
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b'#', self);
    }
}
impl Identify for () {
    fn identify(&self, hasher: &mut Sha256) {
        hasher.update([b'0']);
    }
}
