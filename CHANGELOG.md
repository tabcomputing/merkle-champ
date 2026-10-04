# Changelog

## 0.2.0 (unreleased)

The crate gains a persistent vector, `Vector` (the `vector` module), and the
pack format that was the separate `merkle-champ-pack` crate (the `pack`
module). The vector is a 32-way trie whose shape depends only on its length,
with cached SHA-256 identities (FORMAT.md, section 10), a `Builder` that fills
leaves in place, and nesting with maps and sets through `Identify` (tag `v`).
`merkle-champ-pack` users switch to `merkle_champ::pack`; the format, MCHPACK1,
is unchanged.

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
