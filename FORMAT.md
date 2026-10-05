# merkle-champ identity format, version 1

This document specifies how a map's identity is computed, so that another
implementation can reproduce it byte for byte, and how a map is stored
(section 9). `tests/golden.rs` pins the values below. Any change that alters an
identity computed under this document is a new format version and must change
the domain strings.

## 1. Placement hash

Each key has a 64-bit placement hash from its `KeyHash` implementation. It
decides where the key sits in the trie and therefore the trie's shape. It is
deterministic and portable, and deliberately not cryptographic.

Provided implementations:

- **Bytes** (`str`, `String`, `[u8]`, `Vec<u8>`; a string hashes its UTF-8
  bytes): FNV-1a 64 over the bytes (offset basis `0xcbf29ce484222325`, prime
  `0x100000001b3`), then XOR with the byte length as `u64`, then the
  MurmurHash3 64-bit finalizer (`fmix64`).
- **`u64`**: `fmix64(value)`. **`i64`**: `fmix64(value as u64)`
  (two's complement).

`fmix64(h)`: `h ^= h >> 33; h *= 0xff51afd7ed558ccd; h ^= h >> 33;
h *= 0xc4ceb9fe1a85ec53; h ^= h >> 33` (wrapping multiplication).

## 2. Trie traversal

Level `L` (0-based) uses the 5-bit fragment `(hash >> 5L) & 31`, least
significant bits first. Levels 0 to 12 exist; level 12 sees only bits 60-63.
Keys whose full 64-bit hashes are equal are stored together in a collision
node reached below level 12.

## 3. Canonical form

- A branch node has a 32-bit `datamap` (fragments holding an entry inline)
  and a 32-bit `nodemap` (fragments holding a child node); they are disjoint.
  Entries are stored in ascending fragment order, then children in ascending
  fragment order.
- A fragment holds a child node exactly when two or more keys of that subtree
  share it. So a chain of single-child branches appears only where keys share
  successive fragments, and it ends where they diverge or at a collision node.
- No node other than the root holds exactly one entry and no children; such
  an entry lives in its parent instead. Removal restores this, so the shape
  never depends on history.
- A collision node holds two or more entries, sorted by the key's `Ord`, and
  no children. All its keys share one full hash.
- The empty map is a root branch with both bitmaps zero.

## 4. Node identity

All integers are little-endian. `||` is concatenation. SHA-256 throughout.

Branch:

```
SHA-256( "merkle-champ/branch/v1"
      || datamap (u32) || nodemap (u32)
      || for each entry in order:  Identify(key) || Identify(value)
      || for each child in order:  identity(child)   (32 bytes) )
```

Collision node:

```
SHA-256( "merkle-champ/collision/v1"
      || entry count (u64)
      || for each entry in key order:  Identify(key) || Identify(value) )
```

The map's identity is its root node's identity. The two domain strings differ
before either ends, so a branch encoding cannot be read as a collision
encoding. The number of entries and children in a branch is fixed by the
bitmaps, so the encoding is unambiguous.

## 5. Value encodings (`Identify`)

Each provided encoding is a one-byte type tag followed, except for `()`, by a
`u64` byte length and the bytes. Encodings are therefore self-delimiting and
distinguished by type; for numbers, the length gives the width. Numbers are
little-endian, and floats are encoded by their bits, so `0.0` and `-0.0`
differ, as do NaNs with different payloads.

| Type | Tag | Payload |
|---|---|---|
| `str`, `String` | `s` | UTF-8 bytes |
| `[u8]`, `Vec<u8>` | `b` | bytes |
| `u8`, `u16`, `u32`, `u64` | `u` | 1, 2, 4 or 8 bytes |
| `i8`, `i16`, `i32`, `i64` | `i` | 1, 2, 4 or 8 bytes, two's complement |
| `f32`, `f64` | `f` | 4 or 8 bytes, the IEEE 754 bits |
| `[u8; 32]` (an identity) | `#` | 32 bytes |
| nested `ChampMap` | `m` | the nested map's 32-byte identity |
| nested `ChampSet` | `t` | the nested set's 32-byte identity |
| nested `Vector` | `v` | the nested vector's 32-byte identity (section 10) |
| `()` | `0` | nothing (no length) |

User implementations must keep the same properties: injective (equal values
encode equally, unequal values differently) and self-delimiting. They should
use tags that cannot be confused with the provided ones if both can occur in
one map.

## 6. What the identity does and does not cover

It covers exactly the stored keys and values, through their encodings. It
does not cover how the map was built, which versions share nodes, or the
placement-hash implementation beyond its effect on shape. Two maps with equal
contents have equal identities under this format, whatever their histories.

The library never evaluates, forces, or interprets values. A value's identity
is whatever its `Identify` writes; if a store holds suspended computations,
choosing whether their identity is that of the computation or of its eventual
result is the caller's decision.

## 7. Untrusted keys

The placement hash is unkeyed and not cryptographic. Whoever chooses keys can
choose colliding ones, and colliding entries share a collision node searched
linearly. With untrusted keys, use a key type whose `KeyHash` is keyed or
cryptographic. That changes the placement and therefore the identities, so it
is a different format and should use different domain strings.

## 8. Sets

A `ChampSet<K>` is stored and identified exactly as the map from its elements
to `()`: same placement, shape and node encoding, with each value encoded as
the single byte `0`. Its identity therefore equals that of a
`ChampMap<K, ()>` with the same keys. When a set is nested as a value inside
another map, it contributes tag `t` and its identity, so a nested set and a
nested unit map remain distinguishable.

## 9. Stored form

A node is stored as exactly the bytes its identity hashes (section 4): the
domain string, the header fields, the entry encodings and the children's
identities. So an object's identity is the SHA-256 of its stored bytes, and
anyone holding the bytes can verify them against the identity that named them.
The empty map is the 30-byte object `"merkle-champ/branch/v1" || 0u32 || 0u32`.

- **Children are references.** A branch stores its children's 32-byte
  identities, never their bytes, so every node is a separate object.
- **Nested maps and sets are references too.** A value encoded as `m` or `t`
  (section 5) holds the nested root's identity. The nested tree is stored as
  its own objects.
- **The bytes determine the node.** The domain string tells a branch from a
  collision node. A branch's bitmaps give its entry and child counts, and a
  collision node gives its entry count. Entries decode in order because the
  encodings are self-delimiting, and a collision node's full hash is the
  placement hash of any of its keys. The subtree size is not stored; a reader
  recomputes it.
- **Decoders need more than injectivity.** To load a map, every key and value
  encoding must be readable back: a decoder consumes exactly one encoding and
  rejects anything the encoder could not have written.

A reader loads a node knowing where it sits: its depth and the hash prefix
above it. It rejects, at minimum:

- bytes that do not start with a known domain string, that end early, or that
  continue past the node;
- a branch whose bitmaps overlap, or that uses a position beyond the hash bits
  remaining at its depth (only positions 0-15 at the last level, shift 60);
- an entry whose key hash does not select its position, or does not agree
  with the prefix above it;
- a node other than the root with exactly one entry and no children, or none
  at all;
- a branch past the last level, or a collision node above it;
- a collision node with fewer than two entries, keys not in strictly
  increasing `Ord` order, or a key whose hash is not the node's full hash.

These checks make every loaded map canonical, so a loaded map behaves like
one built in memory, whatever bytes were supplied.

## 10. Vectors

`Vector` has its own identity format, version 1, in its own domains, so a
vector's identity can never equal a map's. `tests/vector.rs` checks the
implementation against an independent computation of this section.

### 10.1 Canonical shape

A leaf holds `W` elements, fixed by the element type:

- **Packed** element types, the fixed-width numbers of section 5, fill 1,024
  bytes: `W = 1024 / width`, so 1,024 `u8`, 512 `u16`, 256 `u32` or `f32`,
  128 `u64`, `i64` or `f64`.
- **Every other** element type has `W = 32`.

A vector of `len` elements is split by its length alone:

- **The tail** holds the last elements: indexes `tailoff` to `len - 1`, where
  `tailoff = ((len - 1) / W) * W` for `len > 0`, and `tailoff = 0` for the
  empty vector. A non-empty vector's tail holds 1 to `W` elements.
- **The tree** holds the first `tailoff` elements, a multiple of `W`, and is
  absent when `tailoff` is 0. Its leaves hold exactly `W` elements each, in
  order. Above them are `h ≥ 1` levels of branches; a branch holds 1 to 32
  children, in order, and every branch except those on the rightmost path is
  full. `h` is the smallest value with `W × 32^h ≥ tailoff`.

The shape therefore depends only on `len` and the element type, never on how
the vector was built.

### 10.2 Node identity

Elements are encoded with `Identify` (section 5). All integers are
little-endian.

```
leaf   = SHA-256( "merkle-champ/vector/leaf/v1"   || count (u8) || Identify(e) for each element in order )
packed = SHA-256( "merkle-champ/vector/packed-leaf/v1" || tag (u8) || width (u8) || count (u16)
                  || each element's bytes in order )
branch = SHA-256( "merkle-champ/vector/branch/v1" || count (u8) || identity(child) for each child in order )
```

`count` is the number of elements (leaf) or children (branch), 1 to `W` or 32
(0 for the empty vector's tail). A leaf of packed elements is a `packed`
leaf: `tag` and `width` are the element type's tag and byte width from
section 5 (`u` and 8 for `u64`), and each element contributes its
little-endian bytes alone, without a tag or length, since the leaf's header
gives both. Packing hashes only the elements' bytes, 8 of the 17 an encoded
`u64` takes and 1 of the 10 for a `u8`, and fills leaves of 1 KB, which keeps
a byte string's node overhead small.

### 10.3 Vector identity

```
vector = SHA-256( "merkle-champ/vector/v1" || len (u64)
               || identity(tree root)   if tailoff > 0
               || identity(tail leaf)   if len > 0 )
```

Given `len` and the element type, which parts are present and where the tail
begins are fixed, so the encoding is unambiguous. The element type is in the
leaves, so vectors of the same numbers in different types differ. The empty
vector's identity is `SHA-256("merkle-champ/vector/v1" || 0u64)`, whatever
its element type: there is one empty sequence.

### 10.4 Nesting and storage

A nested vector encodes, through `Identify`, as the tag `v`, a `u64` length
32 and its identity, as a nested map is `m` (section 5). Storing vectors (as
section 9 stores maps) is not yet specified.

## 11. Packs

A pack carries a set of stored objects as one immutable byte string. An
object is anything whose identity is the SHA-256 of its stored bytes: a map
or set node (section 9), a vector node, a blob, or another system's object,
such as March's compiled code. The `pack` module reads and writes packs and
does no I/O: fetching and publishing them belong to the caller.

### 11.1 Blobs

A blob is opaque content. It is stored as the domain string followed by the
content, and its identity is the SHA-256 of that:

```
blob = "merkle-champ/blob/v1" || content
```

A value refers to a blob by its identity (tag `#`, section 5). Packs never
look inside a blob.

### 11.2 MCHPACK2

The format agreed on 2026-10-03 between transfs, Pandora and March, from
Pandora's proposal. All integers are little-endian, and offsets count from
the start of the pack.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `MCHPACK2` |
| 8 | 4 | flags, `u32`: 0; readers reject any other value |
| 12 | 4 | root count R, `u32` |
| 16 | 8 | object count N, `u64` |
| 24 | 32R | the roots, unique, in the writer's order |
| 24 + 32R | 48N | the index: per object, identity (32), offset (`u64`), length (`u64`) |
| 24 + 32R + 48N | | the objects' bytes, in canonical order |

- **The index** has one entry per object, in strictly increasing identity
  order, so a reader finds an object by binary search.
- **Every root** is an object in the pack.
- **The data area** holds exactly the objects, each once, contiguous, in the
  canonical order below, and ends where the pack ends.

**References.** The references of an object `o` are the other objects in the
pack whose identity appears as 32 consecutive bytes anywhere in `o`'s bytes,
in order of first appearance, each once. A blob has no references. Nothing
about the objects' kinds is needed, so the rule finds references wherever an
object keeps them:
- a branch's children;
- a nested map's root inside an entry (tag `m`);
- a blob named by an `Identity` value (tag `#`);
- a callee's identity inside March's compiled code, stored raw after an
  opcode.

Identities of objects outside the pack are ignored: in a delta pack they are
in the base it extends.

**Canonical order.** A depth-first preorder over references, from the roots
in header order:

```
emitted := {}
for r in roots: visit(r)
visit(x):
  if x in emitted: return
  emit x
  for y in references(x): visit(y)
```

Every object must be emitted; a pack with an object its roots do not reach is
invalid. This gives:

- **One pack per content.** Equal roots and objects always give byte-identical
  packs, however the objects were produced.
- **Lazy opening.** The first root is the first object, so a reader fetches
  the header and index in one read, then the top of the tree.
- **Locality.** A blob comes right after the first object that refers to it,
  so a point read gets a leaf and its page together.

**Verification.**
- A reader that fetches objects one by one, by the ranges in the index,
  checks each object's SHA-256 against its index identity.
- A full reader also recomputes the canonical order and checks that the
  offsets follow it with no gaps, no unreachable objects and no trailing
  bytes, so a valid pack is the only encoding of its roots and objects.

A chance match of an identity inside unrelated bytes has probability 2^-256
per position, and even then it only changes the order, the same way for
writer and reader.

**Golden pack** (`tests/pack.rs`). Four objects:
- `"example/root/v1" || id(other) || id(leaf)`, the one root;
- `other` = `"example/leaf/v1c"`;
- `leaf` = `"example/leaf/v1" || id(page)`;
- `page` = `blob("page")`.

Their data order is root, other, leaf, page. The pack is 414 bytes, and its
SHA-256 is
`2930478cf38da08f57e5c04ee04bcb47206ac28a83a2c54c963a5484e9d2b9d0`.

### 11.3 MCHPACK1

transfs's first format, still read and written. Integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `MCHPACK1` |
| 8 | 4 | object count N, `u32` |
| 12 | 8 | index offset, `u64` |
| 20 | | the objects' bytes, in identity order |
| index offset | 48N | per object, identity (32), offset (`u64`), length (`u64`), by identity |

It has no roots and no canonical order beyond identity order, so it is
deterministic but cannot be opened lazily from its first bytes.
