# merkle-champ identity format, version 1

This document specifies how a map's identity is computed, so that another
implementation can reproduce it byte for byte. `tests/golden.rs` pins the
values below. Any change to any part of this document is a new format version
and must change the domain strings.

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
