# merkle-champ

A persistent hash map for content-addressed systems: a CHAMP trie
(Steindorfer and Vinju, "Optimizing Hash-Array Mapped Tries for Fast and Lean
Immutable JVM Collections", OOPSLA 2015) with three additions.

- **Canonical shape.** A map's structure depends only on its contents. Removal
  re-inlines single entries upward, so deleting a key produces exactly the tree
  that never having inserted it would. Key hashing is deterministic and
  portable, so the shape is the same on every machine and run.
- **Lazily cached Merkle identities.** `map.identity()` is a SHA-256 identity
  of the contents. Each node computes its identity on first request and caches
  it. Versions share unchanged nodes, so after a write only the changed path is
  rehashed. Reads and writes never hash.
- **Structural diff.** `a.diff(&b)` walks both tries together, skipping shared
  subtrees by pointer, and by identity when both identities are already cached.

Maps nest: a `ChampMap<K, ChampMap<..>>` gives every inner map (for example
one per namespace level) its own identity.

Status: prototype, written to measure whether a CHAMP is the right structure
for the March language's global store. Not yet published.

## Use

```rust
use merkle_champ::ChampMap;

let v1: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)].into_iter().collect();
let v2 = v1.update("a".into(), 10).without(&"b".to_string());
assert_eq!(v1.get(&"a".into()), Some(&1));       // v1 is unchanged
assert_eq!(v1.diff(&v2).len(), 2);
let id = v2.identity();                           // cached; later versions reuse subtrees
```

Keys implement `KeyHash` (deterministic 64-bit hash) and `Ord` (orders entries
that share a full hash). Keys and values implement `Identify` for identities.
Implementations are provided for strings, byte vectors, `u64`, `i64`, `()`,
32-byte identities, and nested maps.

## Layout

A node is a single allocation, `Arc<[Slot]>`: a header (two 32-bit bitmaps,
subtree size, collision marker, cached identity) followed by inline entries
and then child pointers, both in bit order. One trie level is one pointer hop.
Updates copy only the nodes on the changed path, in place when a node is not
shared with another version.

CHAMP indexes nodes with population counts. Build with the `popcnt`
instruction enabled (`-C target-feature=+popcnt`, or any
`-C target-cpu` from x86-64-v2 up); without it Rust emits a software popcount
and lookups are measurably slower.

## Tests and benchmarks

```sh
cargo test --release
RUSTFLAGS="-C target-feature=+popcnt" cargo run --release --example store_bench
```

The tests check behaviour against a `BTreeMap` model under random operations,
history-independence of shape and identity, return to the empty identity after
deleting everything, forced full-hash collisions and deep shared prefixes,
persistence, diff against a model, and nested identities.

`store_bench` compares this map with `imbl`'s `HashMap` (using the same fixed
hasher) and `OrdMap`, and with a clone-on-write `std` `HashMap`, on workloads
shaped like a namespaced store at 100, 10,000 and 1,000,000 entries. Raw
outputs are in `bench-results/`.
