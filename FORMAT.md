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
| `TextByte` (a byte of UTF-8 text) | `s` | 1 byte, as a one-byte string |
| `[u8; 32]` (an identity) | `#` | 32 bytes |
| nested `ChampMap` | `m` | the nested map's 32-byte identity |
| nested `ChampSet` | `t` | the nested set's 32-byte identity |
| nested `Sequence` | `v` | the nested sequence's 32-byte identity (section 10) |
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

## 10. Sequences

`Sequence` has its own identity format, version 1, in its own domains. Its
shape depends only on its contents: leaves and branches end where a rolling
hash over the elements says, so equal contents give the same tree however
they were made, and an edit anywhere changes only the nodes near it.
`tests/sequence.rs` checks the implementation against an independent
computation of this section, and the golden identities in 10.6 were also
recomputed separately in Python.

### 10.1 Element fingerprints

`mix64` is MurmurHash3's 64-bit finalizer: `h ^= h >> 33; h *= 0xff51afd7ed558ccd;
h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53; h ^= h >> 33`, multiplications modulo
2^64.

- **Fixed-width numbers** (the packed types of section 5): `w` is the
  element's little-endian bytes as an unsigned 64-bit integer, zero-extended,
  and `print = mix64(w ^ 0x9e3779b97f4a7c15) | 1`.
- **Every other type:** `print = mix64(f) | 1`, where `f` is FNV-1a 64 (offset
  basis `0xcbf29ce484222325`, prime `0x100000001b3`) over the element's
  encoding (section 5).

A fingerprint is odd, so a run of equal elements cannot drive the rolling
hash to zero.

### 10.2 Leaves

A leaf targets `W` elements: 32, or for packed types 1,024 bytes of them
(`W = 1024 / width`: 1,024 `u8`, 128 `u64` or `f64`). It holds at least
`W / 4` and at most `4W`, except that the last leaf may be shorter. Let
`b = log2 W`.

The rolling hash runs over the whole sequence, regardless of where leaves
end: `h(-1) = 0` and `h(i) = (h(i - 1) << 1) + print(e(i))`, modulo 2^64. An
element's influence shifts out of it after 64 more elements. The **cut
level** after element `i` is -1 if `h(i)` has fewer than `b` leading zero
bits, and otherwise `floor((zeros - b) / 5)`.

Scanning from the start, a leaf ends after element `i` when, counting the
elements of the current leaf including `i`:

- the count is at least `W / 4` and the cut level is at least 0, or
- the count is `4W`, or
- `i` is the last element.

A leaf's **end level** is the cut level after its last element.

### 10.3 Branches

Level 1 groups the leaves into branches, level 2 groups level-1 branches,
and so on. At level `L`, a branch ends after a child when, counting the
branch's children including it:

- the count is at least 2 and the child's end level is at least `L`, or
- the count is 128, or
- the child is the last node of the level.

A branch's end level is its last child's. The **root** is the only node of
the first level with one node: a single leaf, or a branch. Since every
branch but the last of its level has at least two children, the height is
at most logarithmic in the number of leaves. Each level needs 5 more zero
bits than the one below, so a branch has 32 children on average.

### 10.4 Node identity

All integers are little-endian.

```
leaf     = SHA-256( "merkle-champ/sequence/leaf/v1" || count (u16) || Identify(e) for each element )
packed   = SHA-256( "merkle-champ/sequence/packed-leaf/v1" || tag (u8) || width (u8) || count (u16)
                    || each element's little-endian bytes )
branch   = SHA-256( "merkle-champ/sequence/branch/v1" || count (u16)
                    || for each child: its length in elements (u64) || identity(child) )
measured = SHA-256( "merkle-champ/sequence/measured-branch/v1" || count (u16) || m (u8)
                    || for each child: its length in elements (u64)
                       || its m measures (u64 each) || identity(child) )
```

A leaf of packed elements is a `packed` leaf, with the type's tag and width
from section 5. A branch records its children's lengths, so a stored branch
is enough to find which child holds the element at an index.

**Measures.** An element type may declare `m` quantities per element, summed
over each child, beyond the count: a chunk's byte length, or a text byte's
code points and newlines. Its branches are `measured` branches, which record
each child's sums, so a stored branch is also enough to find the element
where a running total passes a value: the chunk holding a byte offset, or
the byte where the n-th character starts. A type without measures uses
`branch`. Leaves are the same either way, since their measures follow from
their elements.

`TextByte`, a byte of UTF-8 text, is packed under the tag `s` with width 1,
and has two measures: code points (1 for each byte that starts one, that is
not of the form `10xxxxxx`) and newlines (1 for byte `0x0a`). So text and a
byte sequence with the same bytes have different identities.

### 10.5 Sequence identity

```
sequence = SHA-256( "merkle-champ/sequence/v1" || len (u64) || identity(root) if len > 0 )
```

The element type is in the leaves, so sequences of the same numbers in
different types differ. The empty sequence has one identity, whatever its
element type.

### 10.6 Golden identities

| Contents | Identity |
|---|---|
| `u64` 0 to 999 | `7a25cee465767ef587d2a0dd984ccf06fb5ec95d94504665282822413c972970` |
| `u8`, element `i` = `7i mod 256`, 5,000 of them | `dba099dab8dd20cde67d061f0558ebf40bfd1925a7ed03259d80c55bab9d8ec0` |
| strings `"item 0"` to `"item 99"` | `19dc2f35f57068d900061e75043868be820242dd773aa5057cae757db6e18266` |
| empty | `06b6c643f3db9aaa0a211a969915be4d471aa54a0f3af8202570dc23ac0a0b20` |
| text: `"line i é中😀\n"` for `i` from 0 to 1,999, 38,890 bytes | `8f945ddaa0ffebc4c53bd7c8930e76bd6b1ab901dc5284414aa982595a690d8b` |

### 10.7 Edits (informative)

Every edit is a join: the elements before one point, new elements, and the
elements after another point, of the same sequence or another. At each
level, re-chunking starts where the node holding the first change starts,
since every cut before it depends only on what precedes it. It stops at the
first new cut that falls where an old node ended, past the rolling hash's
window at the leaves: from there the old nodes are the new ones. An insert in
a million elements rewrites three or four nodes.

The exception is a long run of equal elements, or of a short repeating
pattern. In a run the rolling hash is the same at every position, so the run
is cut by count, either at every chance or only at the maximum, and an edit
inside it moves every cut after it in the run. Re-chunking then goes to the
end of the run. The result is still canonical, and the run's leaves are equal
to each other, so a store keeps one copy; only the work is longer.

### 10.8 Nesting and storage

A nested sequence encodes, through `Identify`, as the tag `v`, a `u64`
length 32 and its identity, as a nested map is `m` (section 5).

A stored sequence is its identity preimage (section 10.5): the domain, its
length, and its root's identity if it has one. So a sequence's identity
names an object, and a nested sequence is found from its parent. Each node
is stored as its identity preimage (section 10.4). Packs (section 11) find a
sequence's root, and a branch's children, by their identities in its bytes.

Loading reads the tree in element order and accepts only the canonical tree:

- **Kinds.** Each node is of the kinds the element type gives: packed or
  not, with the type's tag and width, and measured or not, with its number
  of measures.
- **Records.** Each branch's recorded lengths and measures are its
  children's, and the sequence's recorded length is its root's.
- **Cuts.** The rules of sections 10.2 and 10.3 hold: every leaf and branch
  ends at its first cut, except one that ends the sequence, which may end
  without a cut. A leaf holds at most `4W` elements, a branch 2 to 128
  children (the last of a level may have one), and a root branch at least
  two.

A node's end level is not stored. Loading recomputes it with the rolling
hash, which runs over the elements in order. A subtree that recurs with the
same rolling hash before it, as in a run of equal chunks, is loaded once and
shared.

## 11. Packs

A pack carries a set of stored objects as one immutable byte string. An
object is anything whose identity is the SHA-256 of its stored bytes: a map
or set node (section 9), a sequence node, a blob, or another system's object,
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
| 8 | 4 | flags, `u32`: bit 0, encoded members (section 11.3); readers reject any other bit |
| 12 | 4 | root count R, `u32` |
| 16 | 8 | object count N, `u64` |
| 24 | 32R | the roots, unique, in the writer's order |
| 24 + 32R | 48N | the index: per object, identity (32), offset (`u64`), length (`u64`); 64N with encoded members |
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

### 11.3 Encoded members

Agreed on 2026-10-07 between transfs, Pandora and March (`PACK-ENCODING.md`),
so that blobs can be stored compressed and keep the identity of their
uncompressed content. A pack whose flags have bit 0 set has **encoded
members**, and its index entries are 64 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | identity: SHA-256 of the object |
| 32 | 8 | offset of the stored bytes, `u64` |
| 40 | 8 | stored length, `u64` |
| 48 | 8 | decoded length: the object's length, `u64` |
| 56 | 1 | encoding: 0 raw, 1 zstd, 2 zstd with a dictionary |
| 57 | 4 | dictionary, `u32`: for encoding 2, the position in the index of the dictionary's entry; otherwise 0 |
| 61 | 3 | zero |

**Encodings.**
- **Raw (0).** The stored bytes are the object, as in section 11.2, and the
  decoded length equals the stored length.
- **zstd (1).** The member is a blob, and the stored bytes are its content
  compressed as exactly one zstd frame (RFC 8878). The object is
  `"merkle-champ/blob/v1"` followed by the decompressed content, so the
  decoded length is the content's length plus 20. The frame records its
  content size, which must equal that length, and names no dictionary. A
  content checksum is optional and recommended.
- **zstd with a dictionary (2).** As zstd, compressed with the dictionary in
  the entry at the given position. That entry is a blob, raw or zstd, never
  itself encoding 2, and its content is a zstd dictionary in the standard
  format (magic `0xEC30A437`). If the frame names a dictionary ID, it is the
  dictionary's.

**Rules.**
- **A dictionary is a member of every pack that uses it,** a delta pack
  included: the rule that leaves out objects the reader already has does not
  apply to it. A member names its dictionary by a position in its own pack,
  so a pack always decodes and verifies on its own.
- **A pack has the flag only if some member is encoded,** so a pack with
  none has exactly one form, section 11.2's.
- **Unknown values are rejected:** another encoding, a nonzero dictionary
  field for encodings 0 and 1, and nonzero reserved bytes.

**Order.** Section 11.2's canonical order holds, with references taken as
follows:
- a raw member's are found in its bytes, as before;
- a zstd member has none, since it is a blob;
- a member with a dictionary has one, its dictionary, which therefore lies
  right after the first member that uses it.

Nothing is decompressed to find the order.

**Verification.** A reader decompresses an encoded member, checks that the
decoded length and frame are as above, and checks the object's SHA-256
against the index. It may instead rely on the frame's content checksum, but
only for bytes it already trusts, such as a pack it wrote to its own disk:
the checksum detects corruption, not substitution. The decoded length is
declared before any data is read, so a reader can refuse a member larger
than it expects before allocating.

**Packs are unique per content and encoding.** The same objects compressed
differently give different packs, with the same identities, order and
decoded contents. A pack's **raw form**, every member decoded and written as
in section 11.2, is the unique pack of its contents, the normal form for
comparing packs.

MCHPACK1, transfs's first format (big-endian, data in identity order, the
index at the end), was dropped on 2026-10-05: no stored packs needed it.
