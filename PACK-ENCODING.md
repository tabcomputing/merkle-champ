# Proposal: compressed blobs in MCHPACK2

Status: **accepted** 2026-10-07 by transfs, Pandora and March (Thomas
agreeing), and specified in FORMAT.md section 11.3, which is normative. This
note keeps the reasoning. The spec differs from the draft below in three
points, decided while building:
- **A zstd frame holds the blob's content,** not the whole object: the
  object is `"merkle-champ/blob/v1"` followed by the decompressed content,
  and the decoded length counts both. So only blobs can be encoded, by
  construction.
- **Dictionaries are in zstd's standard format** (magic `0xEC30A437`), as
  zstd's trainer writes them, since the pure-Rust decoder reads only those.
- **A dictionary a member uses is always in that member's pack,** delta
  packs included (Pandora's point).

## 1. The need

transfs stores files as content-defined chunks, compressed with zstd at
level 3 (transfs-rs `docs/chunked-storage.md`), and Pandora's SQLite
snapshots need the same. A chunk must keep the identity of its uncompressed
bytes, so that:
- the same chunk compressed two ways is still one chunk;
- recompressing, at another level or with a later dictionary, changes no
  identity.

A blob's identity already works that way:
`SHA-256("merkle-champ/blob/v1" || content)`. The gap is the pack.
- MCHPACK2 stores each member as exactly its identity preimage.
- A reader checks a member by hashing what is stored.

So a pack can hold a chunk only uncompressed. The fallback is a second,
transfs-only pack format for chunks. Both transfs and I would rather extend
MCHPACK2.

## 2. Proposal

**A header flag.** Flags bit 0, *encoded members*, says the index entries
carry an encoding. A pack without it is exactly today's MCHPACK2, so
existing packs stay valid. Today's readers reject a flagged pack, since they
reject any nonzero flags, which is the safe failure.

**Index entries of 64 bytes** when the flag is set, instead of 48:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | identity: SHA-256 of the decoded bytes, as now |
| 32 | 8 | offset of the stored bytes, `u64` |
| 40 | 8 | stored length, `u64` |
| 48 | 8 | decoded length, `u64` |
| 56 | 1 | encoding: 0 raw, 1 zstd, 2 zstd with a dictionary |
| 57 | 4 | dictionary, `u32`: for encoding 2, the position in the index of the dictionary's entry; otherwise 0 |
| 61 | 3 | zero |

**Rules for a flagged pack:**

- **Raw members.** A raw member's decoded length equals its stored length.
- **Only blobs are encoded.** An encoded member's decoded bytes start with
  `merkle-champ/blob/v1`.
- **A zstd member** is exactly one zstd frame (RFC 8878) with:
  - its content size recorded, and equal to the decoded length;
  - for encoding 1, no dictionary (no dictionary ID, or 0);
  - a content checksum optional, but recommended.
- **A member with a dictionary** (encoding 2) is the same, compressed with
  the dictionary its entry names (section 5).
- **The flag only when needed.** A flagged pack has at least one encoded
  member, so a pack with nothing encoded has exactly one form, today's.
- **Unknown values are rejected:** unknown encodings, and nonzero reserved
  bytes.

**What does not change:**

- **Identities** are over the decoded bytes, so compressing never changes
  an identity.
- **The canonical order.** Encoded members are blobs, and blobs have no
  references, so the order is computed as now, without decompressing
  anything. Raw members are scanned for references as before. The one
  addition: a member with a dictionary refers to its dictionary, so the
  dictionary comes right after the first member that uses it, as a blob
  comes after the first node that names it.
- **Verification.** A reader decompresses a member, then checks its length
  and its SHA-256 against the index. A full reader also checks the
  canonical order and that there are no gaps, as now.

## 3. What it costs

**One pack per content becomes one pack per content and encoding.** Today
equal roots and objects always give byte-identical packs. With compression:
- the same blobs compressed at another level, by another zstd version, or
  left raw give other bytes;
- so the offsets and lengths differ, and so does the pack;
- the identities, the order and the decoded contents do not.

Two packs hold the same contents exactly when their **raw forms** are equal:
the pack you get by decoding every member and writing it unflagged. The raw
form is the unique pack of section 11.2, so it serves as the normal form for
comparing packs. Anything that hashes or compares whole pack bytes should
compare raw forms, or root and object identities, instead.

## 4. Trust and the zstd checksum

transfs plans to write zstd's 4-byte content checksum in every frame, and to
rely on it to skip SHA-256 on ordinary local reads. The proposal keeps
SHA-256 as the verification the format promises. A reader may rely on the
frame checksum only for bytes it already trusts, such as its own disk.
- **What the checksum catches:** corruption.
- **What it does not:** substitution. Anyone can write a frame with a valid
  checksum for different content.

In the API this would be an explicit choice, defaulting to full
verification.

## 5. Dictionaries

transfs will not use dictionaries at first, but asked for room for them now
(2026-10-07), so the format needs no second revision. Its four points:

1. **A member names its own dictionary,** not a file version. Chunks are
   shared: a chunk first compressed with database A's dictionary may be
   reused by database B, and reading B then needs A's dictionary.
2. **A dictionary is an ordinary blob member,** identified by its bytes and
   stored once in a pack, so a pack decodes and verifies on its own.
3. **zstd's 32-bit dictionary ID is not the reference.** It is not unique
   across stores, but it may stay in the frame as a check.
4. **Copies of a dictionary may be in several packs,** and any copy serves,
   since they share an identity. Thomas wants dictionaries kept
   redundantly, since losing one loses every chunk compressed with it.

The proposal meets them with the entry's dictionary field, rather than with
the table of dictionary identities in the header that transfs suggested:

- **The reference.** Encoding 2 names the dictionary by the position of its
  entry in the pack's index. The index is in identity order, so the position
  fixes the dictionary's identity within the pack. It costs 4 bytes of each
  entry's reserved space, and no header change.
- **The dictionary itself.** It is a blob member, raw or encoding 1, never
  compressed with a dictionary itself, so there are no chains. Its content,
  the bytes after `merkle-champ/blob/v1`, is the zstd dictionary.
- **Order and reachability.** A member with a dictionary refers to it
  (section 2). So the dictionary is reachable, and it lies right after the
  first member that uses it, where a reader fetching that member wants it.
- **The frame's dictionary ID.** If the frame records one, it must equal the
  ID in the dictionary's header, when the dictionary has one.

transfs's policy (one dictionary per database, at least two copies, restore
in check, retire a dictionary by recompressing) is transfs's own: transfs-rs
`docs/chunked-storage.md`, "Safety and redundancy".

## 6. API sketch (merkle-champ)

- **Feature `zstd`,** optional, using the `zstd` crate, so users without
  compressed members do not build libzstd.
- **Writing.** `pack::encode` stays as is, and writes raw packs. A new
  writer takes each member as raw bytes, or as a zstd frame the caller
  already has, with the identity of its dictionary if it used one. transfs
  compresses chunks itself, so it must not have to decompress and
  recompress them. The writer checks each frame's header:
  - the content size equals the decoded length;
  - the frame's dictionary ID, if any, agrees with the dictionary's.
- **Reading.**
  - `Index` parses both entry sizes, and reports each member's encoding and
    decoded length.
  - A reader built without the feature still opens flagged packs and reads
    raw members, and reports encoded ones as unsupported.
- **Normal form.** `pack::decode` decodes everything. `Pack` holds decoded
  objects, so encoding the result gives the raw form.

## 7. Questions

Answered by transfs (2026-10-07), with Thomas: 64-byte entries, blobs only,
one pack per content and encoding (transfs deduplicates by object, not by
pack; March keeps byte-identical packs by leaving the flag off), and SHA-256
by default with checksum-only reads as an explicit trusted mode.

Still open:

1. **Pandora:** does compressing only blobs fit your SQLite snapshots, with
   their pages stored as blobs? Is one pack per content and encoding
   acceptable to you?
2. **transfs:** does the entry's dictionary field (section 5) serve, in
   place of the header table you suggested?
