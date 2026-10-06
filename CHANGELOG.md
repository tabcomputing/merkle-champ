# Changelog

## 0.2.0 (unreleased)

The crate gains a persistent sequence, `Sequence` (the `sequence` module),
and the pack format that was the separate `merkle-champ-pack` crate (the
`pack` module). The sequence is a content-defined tree: leaves and branches
end where a rolling hash over the elements says (FORMAT.md, section 10), so
its shape depends only on its contents, and every edit (insert, remove,
update, splice, concat, slice) re-chunks only near the change and reuses the
rest. Identities are cached SHA-256, a `Builder` appends in constant time,
and sequences nest with maps and sets through `Identify` (tag `v`).
Fixed-width numbers are packed about 1 KB to a leaf and hashed as their
bytes, so `Sequence<u8>` serves as a persistent byte string.

A dense vector trie, `Vector`, came first in this release cycle and was
replaced before release: its leaves ended at fixed positions, so an insert in
the middle rewrote every leaf after it, which defeats sharing in a store.

Packs are MCHPACK2 (`pack`, FORMAT.md section 11), the format agreed with
transfs and Pandora: little-endian, the index right after the header, and
object data in a canonical, type-free order (a preorder over the identities
each object contains, from the roots), which every full reader verifies, so
equal contents give byte-identical packs. Blobs
(`"merkle-champ/blob/v1" || content`, `pack::blob`) can share a pack with
nodes. `pack::Index` reads objects by range without I/O. MCHPACK1, transfs's
first format from the `merkle-champ-pack` crate, is dropped: no stored packs
needed it (Thomas, 2026-10-05).

`Identify` gains `PACKED` and `pack`, with defaults, for sequences; existing
implementations need no change. It is now implemented for `u8`, `u16`,
`u32`, `i8`, `i16`, `i32`, `f32` and `f64` (tags `u`, `i`, `f`). Sequence
operations require `T: Clone + Identify`, since the chunking fingerprints the
elements.
`merkle-champ-pack` users switch to `merkle_champ::pack` and to MCHPACK2:
`pack::encode(roots, &objects)` and `pack::decode(bytes)`, which returns the
roots and the objects.

Maps can be stored as bytes and loaded back. The identity format is unchanged:
every identity computed by 0.1 is the same in 0.2, and the golden vectors are
the same.

**Breaking:** `Identify::identify` writes into a generic `Sink` instead of a
`sha2::Sha256`, so that the same encoder produces identities and stored bytes.
To update an implementation, change its signature and pass slices:

```rust
// 0.1
fn identify(&self, hasher: &mut Sha256) { hasher.update([b'K']); }
// 0.2
fn identify<S: merkle_champ::Sink + ?Sized>(&self, sink: &mut S) { sink.update(b"K"); }
```

If the file also imports `sha2::Digest`, name `Sink` by path as above rather
than importing it, since both traits give `Sha256` an `update` method.

Added:

- `Sink`, implemented for `Sha256` and `Vec<u8>`, and the helpers
  `write_tagged` and `read_tagged` for the provided encoding shape.
- `Identify::save_objects`, a default no-op, which nested maps and sets use to
  store their own trees.
- `Decode`, implemented for every provided type and for nested maps and sets.
- `Objects`, a set of stored objects keyed by the SHA-256 of their bytes.
- `ChampMap::save`/`load`/`load_with` and `ChampSet::save`/`load`/`load_with`.
  Loading checks every node for canonical form, shares nested maps that occur
  more than once, and limits nesting to `codec::MAX_NESTING`.
- `DecodeError` and `Loader`.
- FORMAT.md section 9, "Stored form". Its preface now says that a change which
  alters an identity is a new format version, since this section adds to the
  document without altering any identity.
