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
//! [`Vector`] is the companion sequence: a persistent vector trie whose shape
//! depends only on its length and element type, with the same cached
//! identities (the [`vector`] module). Values have one encoding ([`Identify`])
//! in maps, sets and vectors, and each can nest in the others. The [`pack`]
//! module reads and writes packs of stored objects: MCHPACK2, canonical and
//! lazily readable, and transfs's MCHPACK1.
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
//! - To store and load a map (see [`codec`]), keys and values also implement
//!   [`Decode`], which must read back exactly what `Identify` writes and
//!   reject anything it could not have written.
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
//!
//! # Storing maps
//!
//! A stored node is exactly the bytes its identity hashes (FORMAT.md, section
//! 9), so loading verifies itself. [`ChampMap::save`] adds a map's nodes to an
//! [`Objects`] set and [`ChampMap::load`] reads them back. The crate performs
//! no I/O: moving objects to disk or across a network is up to the caller.
//!
//! ```
//! use merkle_champ::{ChampMap, Objects};
//!
//! let map: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)].into_iter().collect();
//! let mut objects = Objects::new();
//! let root = map.save(&mut objects);
//! assert_eq!(root, map.identity());
//! let loaded: ChampMap<String, u64> = ChampMap::load(&root, &objects).unwrap();
//! assert_eq!(loaded, map);
//! ```

pub mod codec;
pub mod map;
pub mod pack;
pub mod sequence;
pub mod set;
pub mod vector;

pub use codec::{Decode, DecodeError, Loader, Objects, Sink, read_tagged, write_tagged};
pub use map::{ChampMap, Change, Iter};
pub use sequence::Sequence;
pub use set::{ChampSet, SetChange};
pub use vector::Vector;

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

pub(crate) fn mix64(mut h: u64) -> u64 {
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

/// Writes a value's canonical encoding: into a hasher to compute an identity,
/// or into a buffer to store it.
///
/// Implementations must be injective over the values that can occur, which in
/// practice means a type tag plus length-prefixed bytes ([`write_tagged`]).
pub trait Identify {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S);

    /// Adds any separately stored objects this value refers to, such as a
    /// nested map's nodes, to `objects`. Called by [`ChampMap::save`]. Most
    /// values are stored inline and keep the default, which does nothing.
    fn save_objects(&self, _objects: &mut Objects) {}

    /// How a [`Vector`] of this type fills its leaves (FORMAT.md, section
    /// 10). `None`, the default, puts 32 elements in a leaf, each encoded with
    /// [`identify`](Self::identify). Fixed-width numbers give their tag and
    /// width in bytes, and fill leaves of 1 KB with their little-endian bytes.
    const PACKED: Option<(u8, u8)> = None;

    /// Writes the bytes of packed elements, in order. Called only for types
    /// whose [`PACKED`](Self::PACKED) is set.
    fn pack<S: Sink + ?Sized>(items: &[Self], sink: &mut S)
    where
        Self: Sized,
    {
        for item in items {
            item.identify(sink);
        }
    }
}

impl Identify for str {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        write_tagged(sink, b's', self.as_bytes());
    }
}
impl Identify for String {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        self.as_str().identify(sink);
    }
}
impl Identify for [u8] {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        write_tagged(sink, b'b', self);
    }
}
impl Identify for Vec<u8> {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        self.as_slice().identify(sink);
    }
}
/// Fixed-width numbers: a tag (`u` unsigned, `i` signed, `f` floating) and
/// their little-endian bytes, whose length gives the width. In a vector they
/// are packed.
macro_rules! fixed_width {
    ($($t:ty => $tag:literal),* $(,)?) => {$(
        impl Identify for $t {
            fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
                write_tagged(sink, $tag, &self.to_le_bytes());
            }
            const PACKED: Option<(u8, u8)> = Some(($tag, std::mem::size_of::<$t>() as u8));
            fn pack<S: Sink + ?Sized>(items: &[Self], sink: &mut S) {
                if let [item] = items {
                    sink.update(&item.to_le_bytes());
                    return;
                }
                // A leaf at a time, through a buffer, rather than an update
                // per element.
                const N: usize = 1024 / std::mem::size_of::<$t>();
                let mut buf = [0u8; 1024];
                for chunk in items.chunks(N) {
                    let mut n = 0;
                    for item in chunk {
                        let b = item.to_le_bytes();
                        buf[n..n + b.len()].copy_from_slice(&b);
                        n += b.len();
                    }
                    sink.update(&buf[..n]);
                }
            }
        }
    )*};
}
fixed_width!(
    u8 => b'u', u16 => b'u', u32 => b'u', u64 => b'u',
    i8 => b'i', i16 => b'i', i32 => b'i', i64 => b'i',
    f32 => b'f', f64 => b'f',
);
impl Identify for Identity {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        write_tagged(sink, b'#', self);
    }
}
impl Identify for () {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        sink.update(b"0");
    }
}
