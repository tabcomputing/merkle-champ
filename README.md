# merkle-champ

A persistent hash map and set for content-addressed systems: a CHAMP trie
(Steindorfer and Vinju, "Optimizing Hash-Array Mapped Tries for Fast and Lean
Immutable JVM Collections", OOPSLA 2015) with three additions.

- **Canonical shape.** A map's structure depends only on its contents (and the
  key placement hash). Removal re-inlines single entries upward, so deleting a
  key produces exactly the tree that never having inserted it would. Key
  placement hashing is deterministic and portable, so the shape is the same on
  every machine and run.
- **Lazily cached Merkle identities.** `map.identity()` is a SHA-256 identity
  of the contents. Each node computes its identity on first request and caches
  it. Versions share unchanged nodes, so after a write only the changed path is
  rehashed. Reads and writes compute key placement hashes but never content
  identities.
- **Structural diff.** `a.diff(&b)` walks both tries together, skipping shared
  subtrees by pointer, and by identity when both identities are already cached.

`ChampSet<K>` is a set built on the map (a map from elements to `()`), with
the same canonical shape, identities and diff (reporting added and removed
elements).

Maps and sets nest: in a `ChampMap<K, ChampMap<..>>` every inner map (for example one
per namespace level) has its own cached identity, which its parent's identity
covers.

`Sequence<T>` is the companion sequence: a content-defined tree (a "prolly
tree", as in Noms and Dolt) whose leaves and branches end where a rolling
hash over the elements says. So its shape depends only on its contents,
equal contents have equal identities however they were made, and an edit
anywhere rewrites only the few nodes near it: inserting into a million
elements takes a few microseconds and rewrites 3 or 4 nodes, which a store
shares across versions. Insert, remove, update, splice, concat and slice all
work this way. Fixed-width numbers (`u8` to `u64`, `i8` to `i64`, `f32`,
`f64`) are packed about 1 KB to a leaf, so a `Sequence<u8>` is a compact
persistent byte string; other elements go about 32 to a leaf. Against imbl's
RRB `Vector` it is faster at building, iterating, inserting, joining and
slicing, slower at random reads and point updates, and it has identities
([bench-results/sequence-2026-10-05.md](bench-results/sequence-2026-10-05.md)).
Values encode the same way in maps, sets and sequences, and all three nest.

The `pack` module reads and writes MCHPACK2, packs of stored objects
(FORMAT.md, section 11). The index comes right after the header, so a reader
opens a pack with one read and fetches objects by range (`pack::Index`, which
does no I/O). Objects are in a canonical order found without knowing what
they are, so equal contents give byte-identical packs. Blobs can share a
pack with nodes, each right after the first object that refers to it.

A blob can be stored in a pack compressed, as a zstd frame, and keep the
identity of its content (FORMAT.md, section 11.3), so the same chunk
compressed two ways is still one object. A frame may use a zstd dictionary,
itself a blob in the same pack. `pack::encode_members` writes such packs from
frames the caller made, without compressing anything itself.
`pack::read_member` and `pack::decode` read them with the `zstd` feature (the
C library) or `ruzstd` (pure Rust, for wasm32). Reading checks each member's
SHA-256 by default, refuses members larger than a set bound before
allocating, and can rely on zstd's checksum instead for packs a program
trusts. A pack without compressed members is unchanged, byte for byte.

The identity format is specified in [FORMAT.md](FORMAT.md) and pinned by
golden vectors. Keys and values must satisfy the consistency requirements in
the crate documentation (equal keys hash equally, `Identify` is injective,
nothing identity-relevant changes while stored). The placement hash is not
cryptographic; see FORMAT.md before using untrusted keys.

Status: early. Written to serve as the global store of the March language,
where it was chosen by measurement over alternatives (see `bench-results/`).

## Use

```rust
use merkle_champ::ChampMap;

let v1: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)].into_iter().collect();
let v2 = v1.update("a".into(), 10).without(&"b".to_string());
assert_eq!(v1.get(&"a".into()), Some(&1));       // v1 is unchanged
assert_eq!(v1.diff(&v2).len(), 2);
let id = v2.identity();                           // cached; later versions reuse subtrees
assert_eq!(id, v2.identity());

use merkle_champ::ChampSet;
let effects: ChampSet<String> = ["io".to_string(), "clock".into()].into_iter().collect();
let fewer = effects.without(&"clock".to_string());
assert_eq!(effects.diff(&fewer).len(), 1);
```

Keys implement `KeyHash` (deterministic 64-bit hash) and `Ord` (orders entries
that share a full hash). Keys and values implement `Identify` for identities,
and `Decode` to be loaded back. `Identify` is provided for strings, byte
vectors, the fixed-width integers and floats, `()`, 32-byte identities, and
nested maps, sets and sequences.

## Storing and loading

A stored node is exactly the bytes its identity hashes (FORMAT.md, section 9),
so loading verifies itself, as with Git objects. `save` adds a map's nodes to an
`Objects` set, keyed by the hash of their bytes. `load` reads a map back and
checks that every node is canonical, whatever bytes were supplied.

```rust
use merkle_champ::{ChampMap, Objects};

let v1: ChampMap<String, u64> = (0..1000).map(|i| (format!("k{i}"), i)).collect();
let mut objects = Objects::new();
let root = v1.save(&mut objects);                 // the map's identity
let v2 = v1.update("k7".into(), 0);
v2.save(&mut objects);                            // adds only the changed path
let loaded: ChampMap<String, u64> = ChampMap::load(&root, &objects).unwrap();
assert_eq!(loaded, v1);
```

Sequences store and load the same way, as their nodes and a header that
records the length and root. Loading checks that the tree is the one the
elements build, so an edit to a loaded sequence gives what it would have
given before saving:

```rust
use merkle_champ::{Objects, Sequence};

let v1: Sequence<u64> = (0..100_000).collect();
let mut objects = Objects::new();
let id = v1.save(&mut objects);                   // the sequence's identity
v1.insert(50_000, 7).save(&mut objects);          // adds a few nodes
let loaded: Sequence<u64> = Sequence::load(&id, &objects).unwrap();
assert_eq!(loaded.insert(50_000, 7).identity(), v1.insert(50_000, 7).identity());
```

A chunk list of 78,000 references (transfs's case: a 32-byte identity and a
length each, measured by length) saves in about 4 ms once identities are
computed, as 2,127 objects and 4 MB, and loads in about 7 ms; a new version
with one chunk inserted adds 6 objects in 40 µs (local release build, not a
benchmark).

Nested maps, sets and sequences are stored as their own trees and shared on
load. The
crate performs no I/O: moving objects to disk or across a network is up to the
caller. PERSISTENCE.md discusses a layer built on top for stores, packs, sync
and history.

At 1,000,000 `u64` entries (local release build, not a benchmark): saving takes
about 0.3 s and 53 MB in 308,603 objects, loading about 0.15-0.18 s, and saving
a new version after one write adds 5 objects in about 50 µs.

## Layout

A node is a single allocation, `Arc<[Slot]>`: a header (two 32-bit bitmaps,
subtree size, collision marker, cached identity) followed by inline entries
and then child pointers, both in bit order. One trie level is one pointer hop.
Updates copy only the nodes on the changed path, in place when a node is not
shared with another version.

CHAMP indexes nodes with population counts. On x86-64, enabling the `popcnt`
instruction (`-C target-feature=+popcnt`, or a `-C target-cpu` of x86-64-v2 or
later) measurably speeds up lookups; without it Rust emits a software
popcount. This is an optimization only: results and identities are identical
either way, and the crate sets no target flags. The benchmarks in
`bench-results/` were built with it enabled.

## Tests and benchmarks

```sh
cargo test --release
cargo run --release --example store_bench
RUSTFLAGS="-C target-feature=+popcnt" cargo run --release --example store_bench   # as measured
```

The tests check behaviour against a `BTreeMap` model under random operations,
history-independence of shape and identity, return to the empty identity after
deleting everything, forced full-hash collisions and deep shared prefixes,
persistence, diff against a model, and nested identities (`properties.rs`);
fixed golden vectors and an independent recomputation of small identities
from FORMAT.md (`golden.rs`); and collision diffs in both directions,
independently built maps with cold and warm identities, randomized historical
snapshots with `get_mut`, no-op changes, and panics injected into user
`Clone` and comparisons (`robustness.rs`); and the set against a model,
history independence, equality with the unit map, diff, nesting, and golden
vectors (`set.rs`); and edge cases: hashes differing only in the top bits
(deepest chains), extreme and integer hashes, a 200-entry collision node,
every diff shape between an entry and a sub-trie in both directions, `Send` and
`Sync` with concurrent identity requests, a panic while computing an identity,
type and nesting separation in encodings, identity uniqueness across 4,096
small maps, iteration, equality without `Identify`, and very large keys
(`edge_cases.rs`); and storage: round trips of every provided type, stored
bytes equal to identity preimages, identical object sets for equal maps,
incremental saves, nested maps and sets shared on load (including 2^60 paths
through 61 maps), the nesting limit, missing objects, loading as the wrong
type, and rejection of malformed and non-canonical nodes at every rule in
FORMAT.md section 9 (`codec.rs`). A long randomized soak over nested maps runs with
`cargo test --release -- --ignored soak`.

`store_bench` compares this map with `imbl`'s `HashMap` (using the same fixed
hasher) and `OrdMap`, and with a clone-on-write `std` `HashMap`, on workloads
shaped like a namespaced store at 100, 10,000 and 1,000,000 entries. Raw
outputs are in `bench-results/`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
