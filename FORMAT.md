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
distinguished by type.

| Type | Tag | Payload |
|---|---|---|
| `str`, `String` | `s` | UTF-8 bytes |
| `[u8]`, `Vec<u8>` | `b` | bytes |
| `u64` | `u` | 8 bytes |
| `i64` | `i` | 8 bytes, two's complement |
| `[u8; 32]` (an identity) | `#` | 32 bytes |
| nested `ChampMap` | `m` | the nested map's 32-byte identity |
| nested `ChampSet` | `t` | the nested set's 32-byte identity |
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
