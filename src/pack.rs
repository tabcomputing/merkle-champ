//! Immutable indexed packs of stored objects: MCHPACK2 (FORMAT.md, section
//! 11). Little-endian; the index right after the header, so a reader opens a
//! pack lazily; and object data in a canonical order found without type
//! knowledge, so equal contents give byte-identical packs. Blobs and other
//! opaque objects may share a pack with nodes, each right after the first
//! object that refers to it.
//!
//! Blobs may be stored compressed, as zstd frames, keeping the identity of
//! their content (section 11.3): [`encode_members`] writes such packs from
//! frames the caller made, and [`read_member`] and [`decode`] read them,
//! with the `zstd` feature (the C library) or `ruzstd` (pure Rust, for
//! wasm32). Writing needs neither.
//!
//! Storage transport and ref publication belong to the caller: this module
//! does no I/O. [`Index`] tells a caller which byte ranges to fetch.
use crate::{Identity, Objects};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct PackError(&'static str);

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for PackError {}

pub type Result<T> = std::result::Result<T, PackError>;

fn identity(bytes: &[u8]) -> Identity {
    Sha256::digest(bytes).into()
}

/// The domain of blobs: a blob is stored as this string followed by its
/// content, and its identity is the SHA-256 of that (FORMAT.md, section 11.1).
/// Blobs are opaque to packs: their bytes are never scanned for references.
pub const BLOB_DOMAIN: &[u8] = b"merkle-champ/blob/v1";

/// The stored bytes of a blob with this content. Insert them into an
/// [`Objects`] to get the blob's identity.
pub fn blob(content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BLOB_DOMAIN.len() + content.len());
    bytes.extend_from_slice(BLOB_DOMAIN);
    bytes.extend_from_slice(content);
    bytes
}

// MCHPACK2 (FORMAT.md, section 11.2). All integers are little-endian, and
// offsets count from the start of the pack:
//
// 0        8    magic "MCHPACK2"
// 8        4    flags, u32: bit 0, encoded members; others reserved
// 12       4    root count R, u32
// 16       8    object count N, u64
// 24       32R  roots, unique, in the writer's order
// 24+32R   48N  index: identity, offset (u64), length (u64), by identity
// ...           object bytes, in canonical order, with no gaps
//
// Objects are stored preimages: an object's identity is the SHA-256 of its
// bytes. Its *references* are the other objects in the pack whose identity
// appears as 32 consecutive bytes anywhere in it, in order of first
// appearance; blobs ([`BLOB_DOMAIN`]) have none. The canonical order is a
// depth-first preorder over references from the roots, in root order, each
// object once, and every object must be reached. It needs no knowledge of
// what the objects are, so any reader can recompute and check it.
//
// With encoded members (section 11.3) an index entry is 64 bytes: identity,
// offset, stored length, decoded length (u64 each after the identity), an
// encoding byte, a u32 dictionary position, and 3 zero bytes. A zstd member
// is a blob whose content is one zstd frame; it has no references but its
// dictionary, if any.

const MAGIC: &[u8; 8] = b"MCHPACK2";
const HEADER_SIZE: usize = 24;
const ENTRY_SIZE: usize = 48;
const ENCODED_ENTRY_SIZE: usize = 64;
const FLAG_ENCODED: u32 = 1;
const ZSTD_MAGIC: u32 = 0xFD2F_B528;
const DICTIONARY_MAGIC: u32 = 0xEC30_A437;

/// How a member is stored (FORMAT.md, section 11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// The object's bytes, as its identity hashes them.
    Raw,
    /// A blob whose content is one zstd frame.
    Zstd,
    /// A blob whose content is one zstd frame compressed with a dictionary:
    /// the member at this position in the index.
    ZstdDictionary(u32),
}

/// An index entry: where a member's bytes lie, and how to decode them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: Identity,
    /// The stored bytes' offset in the pack.
    pub offset: u64,
    /// The stored bytes' length.
    pub length: u64,
    /// The object's length once decoded: the stored length for a raw member.
    pub decoded_length: u64,
    pub encoding: Encoding,
}

/// A decoded and fully verified pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    /// The roots, in the pack's order.
    pub roots: Vec<Identity>,
    /// The objects, decoded: encoding them again gives the pack's raw form.
    pub objects: Objects,
}

/// How [`read_member`] and [`decode_with`] read members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOptions {
    /// The largest decoded member accepted. A member that declares more is
    /// refused before anything is allocated for it, since the index is
    /// untrusted input.
    pub max_decoded: u64,
    /// Rely on a zstd frame's content checksum instead of SHA-256, for the
    /// members whose frames have one. Only for bytes already trusted, such
    /// as a pack this program wrote to its own disk: the checksum detects
    /// corruption, not substitution. Members without a checksum are still
    /// checked by identity.
    pub trust_checksums: bool,
}

impl Default for ReadOptions {
    /// At most 64 MiB a member, and every member checked by identity.
    fn default() -> Self {
        ReadOptions {
            max_decoded: 64 << 20,
            trust_checksums: false,
        }
    }
}

/// A member for [`encode_members`] to write.
#[derive(Clone, Copy, Debug)]
pub enum Member<'a> {
    /// An object, stored as its bytes.
    Raw(&'a [u8]),
    /// A blob whose content the caller compressed as one zstd frame, which
    /// records its content size, with the identity of the dictionary it
    /// used, if any. The dictionary must be a member of the same pack.
    Zstd {
        frame: &'a [u8],
        dictionary: Option<Identity>,
    },
}

/// The fields of a zstd frame header (RFC 8878, section 3.1.1) the format
/// checks.
struct FrameHeader {
    content_size: Option<u64>,
    dictionary_id: u32,
    checksum: bool,
}

fn frame_header(frame: &[u8]) -> Result<FrameHeader> {
    let bad = PackError("invalid zstd frame header");
    if frame.len() < 5 || frame[..4] != ZSTD_MAGIC.to_le_bytes() {
        return Err(PackError("not a zstd frame"));
    }
    let descriptor = frame[4];
    if descriptor & 0x08 != 0 {
        return Err(bad);
    }
    let single_segment = descriptor & 0x20 != 0;
    let id_size = [0, 1, 2, 4][usize::from(descriptor & 3)];
    let size_size = match descriptor >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let start = if single_segment { 5 } else { 6 };
    let field = |at: usize, n: usize| -> Result<u64> {
        let bytes = frame
            .get(at..at + n)
            .ok_or(PackError("invalid zstd frame header"))?;
        let mut word = [0u8; 8];
        word[..n].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(word))
    };
    let dictionary_id = field(start, id_size)? as u32;
    let content_size = match size_size {
        0 => None,
        2 => Some(field(start + id_size, 2)? + 256),
        n => Some(field(start + id_size, n)?),
    };
    Ok(FrameHeader {
        content_size,
        dictionary_id,
        checksum: descriptor & 0x04 != 0,
    })
}

/// The ID in a zstd dictionary's header, if it is in the standard format.
fn dictionary_id(dictionary: &[u8]) -> Option<u32> {
    if dictionary.len() < 8 || dictionary[..4] != DICTIONARY_MAGIC.to_le_bytes() {
        return None;
    }
    Some(u32::from_le_bytes(
        dictionary[4..8].try_into().expect("4 bytes"),
    ))
}

/// Finds references: which pack members' identities occur in an object's
/// bytes. A 64K-bit filter on each window's first two bytes keeps the
/// scan to one table lookup per byte for most positions.
struct Members<'a> {
    position: HashMap<&'a Identity, usize>,
    filter: Vec<u64>,
}

impl<'a> Members<'a> {
    fn new(ids: impl Iterator<Item = &'a Identity>) -> Self {
        let mut position = HashMap::new();
        let mut filter = vec![0u64; 1 << 10];
        for (i, id) in ids.enumerate() {
            position.insert(id, i);
            let k = u16::from_le_bytes([id[0], id[1]]) as usize;
            filter[k >> 6] |= 1 << (k & 63);
        }
        Members { position, filter }
    }

    /// The members referenced by `bytes`, other than `own`, in order of
    /// first appearance.
    fn references(&self, own: usize, bytes: &[u8]) -> Vec<usize> {
        let mut found = Vec::new();
        if bytes.starts_with(BLOB_DOMAIN) || bytes.len() < 32 {
            return found;
        }
        let mut seen = HashSet::new();
        for i in 0..=bytes.len() - 32 {
            let k = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            if self.filter[k >> 6] & (1 << (k & 63)) == 0 {
                continue;
            }
            let window: &Identity = bytes[i..i + 32].try_into().expect("32 bytes");
            if let Some(&m) = self.position.get(window)
                && m != own
                && seen.insert(m)
            {
                found.push(m);
            }
        }
        found
    }
}

/// The canonical order of the members `ids` (in identity order) from
/// `roots`, as positions: depth-first preorder over references, given for
/// each member by `references`, iteratively, since chains can be long.
fn canonical_order(
    roots: &[Identity],
    ids: &[&Identity],
    references: impl Fn(&Members<'_>, usize) -> Vec<usize>,
) -> Result<Vec<usize>> {
    let members = Members::new(ids.iter().copied());
    let mut emitted = vec![false; ids.len()];
    let mut order = Vec::with_capacity(ids.len());
    let mut seen_roots = HashSet::new();
    for root in roots {
        if !seen_roots.insert(root) {
            return Err(PackError("pack roots must be unique"));
        }
        let &r = members
            .position
            .get(root)
            .ok_or(PackError("pack root is not in the pack"))?;
        if emitted[r] {
            continue;
        }
        emitted[r] = true;
        order.push(r);
        let mut stack = vec![(references(&members, r), 0)];
        while let Some((refs, next)) = stack.last_mut() {
            let Some(&m) = refs.get(*next) else {
                stack.pop();
                continue;
            };
            *next += 1;
            if !emitted[m] {
                emitted[m] = true;
                order.push(m);
                stack.push((references(&members, m), 0));
            }
        }
    }
    if order.len() != ids.len() {
        return Err(PackError("pack object not reachable from its roots"));
    }
    Ok(order)
}

/// A member's references in a pack with encoded members: a raw member's are
/// in its bytes, a zstd member has none but its dictionary.
fn encoded_references(
    members: &Members<'_>,
    m: usize,
    encoding: Encoding,
    bytes: &[u8],
) -> Vec<usize> {
    match encoding {
        Encoding::Raw => members.references(m, bytes),
        Encoding::Zstd => Vec::new(),
        Encoding::ZstdDictionary(d) => vec![d as usize],
    }
}

fn u64_of(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| PackError("pack size overflow"))
}

/// Writes a pack of `objects` with these roots, which must be unique
/// members. Every object must be reachable from the roots. Every member is
/// raw, so this is the unique pack of these roots and objects.
pub fn encode(roots: &[Identity], objects: &Objects) -> Result<Vec<u8>> {
    let members: Vec<(&Identity, &[u8])> = objects.iter().collect();
    let ids: Vec<&Identity> = members.iter().map(|(id, _)| *id).collect();
    let order = canonical_order(roots, &ids, |m, i| m.references(i, members[i].1))?;
    let stored: Vec<&[u8]> = members.iter().map(|(_, b)| *b).collect();
    write_pack(roots, &ids, &stored, None, &order)
}

/// Writes a pack whose members may be zstd frames (FORMAT.md, section
/// 11.3), from bytes and frames the caller has, so nothing is compressed or
/// decompressed here. `members` may be in any order; each identity once.
///
/// A raw member is checked against its identity. A zstd member's identity
/// is the caller's: that of the blob whose content the frame holds, which
/// only decompressing can check, as every reader does. Its frame header is
/// checked here: it records its content size, which gives the decoded
/// length, and names no dictionary but its own. A dictionary must be a
/// member, a blob holding a standard zstd dictionary, raw or zstd itself.
///
/// If no member is a zstd frame, the pack is exactly what [`encode`] writes.
pub fn encode_members(roots: &[Identity], members: &[(Identity, Member<'_>)]) -> Result<Vec<u8>> {
    let mut sorted: Vec<&(Identity, Member<'_>)> = members.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(PackError("pack member identities must be unique"));
    }
    let ids: Vec<&Identity> = sorted.iter().map(|(id, _)| id).collect();
    let position = |id: &Identity| ids.binary_search(&id).ok();
    let mut entries = Vec::with_capacity(sorted.len());
    let mut stored = Vec::with_capacity(sorted.len());
    for (id, member) in &sorted {
        match *member {
            Member::Raw(bytes) => {
                if identity(bytes) != *id {
                    return Err(PackError("pack object identity mismatch"));
                }
                entries.push((u64_of(bytes.len())?, Encoding::Raw));
                stored.push(bytes);
            }
            Member::Zstd { frame, dictionary } => {
                let header = frame_header(frame)?;
                let content = header
                    .content_size
                    .ok_or(PackError("zstd frame without its content size"))?;
                let decoded = content
                    .checked_add(BLOB_DOMAIN.len() as u64)
                    .ok_or(PackError("pack size overflow"))?;
                let encoding = match dictionary {
                    None if header.dictionary_id != 0 => {
                        return Err(PackError("zstd frame names a dictionary"));
                    }
                    None => Encoding::Zstd,
                    Some(d) => {
                        let p = position(&d)
                            .ok_or(PackError("zstd dictionary is not a pack member"))?;
                        match sorted[p].1 {
                            Member::Zstd {
                                dictionary: Some(_),
                                ..
                            } => {
                                return Err(PackError(
                                    "zstd dictionary compressed with a dictionary",
                                ));
                            }
                            Member::Raw(bytes) => {
                                let dict = bytes
                                    .strip_prefix(BLOB_DOMAIN)
                                    .ok_or(PackError("zstd dictionary is not a blob"))?;
                                let did = dictionary_id(dict).ok_or(PackError(
                                    "zstd dictionary not in the standard format",
                                ))?;
                                if header.dictionary_id != 0 && header.dictionary_id != did {
                                    return Err(PackError("zstd frame names another dictionary"));
                                }
                            }
                            Member::Zstd { .. } => {}
                        }
                        if p == ids.len() || *ids[p] == *id {
                            return Err(PackError("zstd member is its own dictionary"));
                        }
                        Encoding::ZstdDictionary(
                            u32::try_from(p).map_err(|_| PackError("too many pack members"))?,
                        )
                    }
                };
                entries.push((decoded, encoding));
                stored.push(frame);
            }
        }
    }
    let order = canonical_order(roots, &ids, |m, i| {
        encoded_references(m, i, entries[i].1, stored[i])
    })?;
    let encoded = entries.iter().any(|(_, e)| *e != Encoding::Raw);
    write_pack(
        roots,
        &ids,
        &stored,
        encoded.then_some(&entries[..]),
        &order,
    )
}

/// Writes the header, the index and the data in `order`. `encodings`, if
/// given, makes a pack with encoded members: each member's decoded length
/// and encoding.
fn write_pack(
    roots: &[Identity],
    ids: &[&Identity],
    stored: &[&[u8]],
    encodings: Option<&[(u64, Encoding)]>,
    order: &[usize],
) -> Result<Vec<u8>> {
    let root_count = u32::try_from(roots.len()).map_err(|_| PackError("too many roots in pack"))?;
    let entry_size = if encodings.is_some() {
        ENCODED_ENTRY_SIZE
    } else {
        ENTRY_SIZE
    };
    let data_start = ids
        .len()
        .checked_mul(entry_size)
        .and_then(|n| n.checked_add(HEADER_SIZE + 32 * roots.len()))
        .ok_or(PackError("pack size overflow"))?;
    let mut offsets = vec![0u64; ids.len()];
    let mut end = data_start;
    for &m in order {
        offsets[m] = u64_of(end)?;
        end = end
            .checked_add(stored[m].len())
            .ok_or(PackError("pack size overflow"))?;
    }
    let mut pack = Vec::with_capacity(end);
    pack.extend_from_slice(MAGIC);
    let flags = if encodings.is_some() { FLAG_ENCODED } else { 0 };
    pack.extend_from_slice(&flags.to_le_bytes());
    pack.extend_from_slice(&root_count.to_le_bytes());
    pack.extend_from_slice(&u64_of(ids.len())?.to_le_bytes());
    for root in roots {
        pack.extend_from_slice(root);
    }
    for (m, id) in ids.iter().enumerate() {
        pack.extend_from_slice(*id);
        pack.extend_from_slice(&offsets[m].to_le_bytes());
        pack.extend_from_slice(&u64_of(stored[m].len())?.to_le_bytes());
        if let Some(encodings) = encodings {
            let (decoded, encoding) = encodings[m];
            let (code, dictionary) = match encoding {
                Encoding::Raw => (0u8, 0u32),
                Encoding::Zstd => (1, 0),
                Encoding::ZstdDictionary(d) => (2, d),
            };
            pack.extend_from_slice(&decoded.to_le_bytes());
            pack.push(code);
            pack.extend_from_slice(&dictionary.to_le_bytes());
            pack.extend_from_slice(&[0; 3]);
        }
    }
    for &m in order {
        pack.extend_from_slice(stored[m]);
    }
    Ok(pack)
}

/// The header and index of a pack, for reading its objects one at a time.
/// It needs only the pack's first [`Index::needed`] bytes, so a caller
/// fetching a pack by byte range opens it with one read, then fetches
/// objects as [`locate`](Index::locate) says and checks each with
/// [`verify`](Index::verify), or, in a pack with encoded members, reads each
/// with [`read_member`]. It does no I/O.
#[derive(Debug, Clone)]
pub struct Index {
    roots: Vec<Identity>,
    entries: Vec<Entry>,
    encoded: bool,
}

impl Index {
    /// How many bytes from the start of a pack hold its header and index,
    /// from at least its first 24 bytes.
    pub fn needed(head: &[u8]) -> Result<usize> {
        if head.len() < HEADER_SIZE || &head[..8] != MAGIC {
            return Err(PackError("invalid pack header"));
        }
        let flags = u32::from_le_bytes(head[8..12].try_into().expect("header"));
        if flags & !FLAG_ENCODED != 0 {
            return Err(PackError("unknown pack flags"));
        }
        let entry_size = if flags & FLAG_ENCODED != 0 {
            ENCODED_ENTRY_SIZE
        } else {
            ENTRY_SIZE
        };
        let roots = u32::from_le_bytes(head[12..16].try_into().expect("header")) as usize;
        let count = u64::from_le_bytes(head[16..24].try_into().expect("header"));
        usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(entry_size))
            .and_then(|n| n.checked_add(HEADER_SIZE + 32 * roots))
            .ok_or(PackError("pack index size overflow"))
    }

    /// Reads the header and index from the start of a pack. Checks the
    /// header, that the roots are unique, that index entries are in
    /// strictly increasing identity order, that every object lies in the
    /// data area, after the index, and, with encoded members, that every
    /// entry is well formed (FORMAT.md, section 11.3).
    pub fn parse(prefix: &[u8]) -> Result<Index> {
        let data_start = Self::needed(prefix)?;
        if prefix.len() < data_start {
            return Err(PackError("pack index incomplete"));
        }
        let encoded = prefix[8] & 1 != 0;
        let root_count = u32::from_le_bytes(prefix[12..16].try_into().expect("header")) as usize;
        let roots: Vec<Identity> = prefix[HEADER_SIZE..HEADER_SIZE + 32 * root_count]
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        if roots.iter().collect::<HashSet<_>>().len() != roots.len() {
            return Err(PackError("pack roots must be unique"));
        }
        let entry_size = if encoded {
            ENCODED_ENTRY_SIZE
        } else {
            ENTRY_SIZE
        };
        let u64_at =
            |e: &[u8], at: usize| u64::from_le_bytes(e[at..at + 8].try_into().expect("8 bytes"));
        let mut entries: Vec<Entry> = Vec::new();
        for e in prefix[HEADER_SIZE + 32 * root_count..data_start].chunks_exact(entry_size) {
            let id: Identity = e[..32].try_into().expect("32 bytes");
            let offset = u64_at(e, 32);
            let length = u64_at(e, 40);
            if entries.last().is_some_and(|prev| prev.id >= id) {
                return Err(PackError("pack identities are not unique and sorted"));
            }
            if offset < data_start as u64 || offset.checked_add(length).is_none() {
                return Err(PackError("invalid pack object bounds"));
            }
            let (decoded_length, encoding) = if encoded {
                let decoded = u64_at(e, 48);
                let dictionary = u32::from_le_bytes(e[57..61].try_into().expect("4 bytes"));
                if e[61..64] != [0; 3] {
                    return Err(PackError("nonzero reserved bytes in a pack entry"));
                }
                let encoding = match (e[56], dictionary) {
                    (0, 0) if decoded == length => Encoding::Raw,
                    (0, 0) => return Err(PackError("raw pack member with another decoded length")),
                    (1, 0) => Encoding::Zstd,
                    (2, d) => Encoding::ZstdDictionary(d),
                    (0 | 1, _) => return Err(PackError("dictionary given without encoding 2")),
                    _ => return Err(PackError("unknown pack member encoding")),
                };
                if encoding != Encoding::Raw && decoded < BLOB_DOMAIN.len() as u64 {
                    return Err(PackError("zstd pack member shorter than a blob"));
                }
                (decoded, encoding)
            } else {
                (length, Encoding::Raw)
            };
            entries.push(Entry {
                id,
                offset,
                length,
                decoded_length,
                encoding,
            });
        }
        if encoded {
            if entries.iter().all(|e| e.encoding == Encoding::Raw) {
                return Err(PackError("pack flagged with no encoded member"));
            }
            for (i, e) in entries.iter().enumerate() {
                if let Encoding::ZstdDictionary(d) = e.encoding {
                    let d = d as usize;
                    if d == i
                        || entries
                            .get(d)
                            .is_none_or(|x| matches!(x.encoding, Encoding::ZstdDictionary(_)))
                    {
                        return Err(PackError("invalid zstd dictionary position"));
                    }
                }
            }
        }
        Ok(Index {
            roots,
            entries,
            encoded,
        })
    }

    pub fn roots(&self) -> &[Identity] {
        &self.roots
    }

    /// The number of objects.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the pack has encoded members (FORMAT.md, section 11.3).
    pub fn is_encoded(&self) -> bool {
        self.encoded
    }

    /// The identities of the pack's objects, in identity order.
    pub fn ids(&self) -> impl Iterator<Item = &Identity> {
        self.entries.iter().map(|e| &e.id)
    }

    /// The entries, in identity order. A dictionary position (encoding 2)
    /// indexes this slice.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// An object's entry.
    pub fn entry(&self, id: &Identity) -> Option<&Entry> {
        let i = self.entries.binary_search_by(|e| e.id.cmp(id)).ok()?;
        Some(&self.entries[i])
    }

    /// Where an object's stored bytes lie in the pack: offset and length.
    pub fn locate(&self, id: &Identity) -> Option<(u64, u64)> {
        self.entry(id).map(|e| (e.offset, e.length))
    }

    /// Whether fetched bytes are the object with this identity: for raw
    /// members. An encoded member is read with [`read_member`].
    pub fn verify(id: &Identity, bytes: &[u8]) -> bool {
        identity(bytes) == *id
    }
}

/// Decodes a member fetched by its entry's range and checks it, returning
/// the object's bytes (FORMAT.md, section 11.3). For encoding 2,
/// `dictionary` is the object read for the entry the encoding names. A
/// member declaring more than `options.max_decoded` bytes is refused before
/// anything is allocated. Decompressing needs the `zstd` or `ruzstd`
/// feature; raw members need neither.
pub fn read_member(
    entry: &Entry,
    stored: &[u8],
    dictionary: Option<&[u8]>,
    options: &ReadOptions,
) -> Result<Vec<u8>> {
    if entry.decoded_length > options.max_decoded {
        return Err(PackError("pack member larger than allowed"));
    }
    if stored.len() as u64 != entry.length {
        return Err(PackError("pack member of the wrong length"));
    }
    let (object, checked) = match entry.encoding {
        Encoding::Raw => (stored.to_vec(), false),
        Encoding::Zstd | Encoding::ZstdDictionary(_) => {
            let dictionary = match (entry.encoding, dictionary) {
                (Encoding::Zstd, _) => None,
                (_, Some(d)) => {
                    let d = d
                        .strip_prefix(BLOB_DOMAIN)
                        .ok_or(PackError("zstd dictionary is not a blob"))?;
                    Some((
                        d,
                        dictionary_id(d)
                            .ok_or(PackError("zstd dictionary not in the standard format"))?,
                    ))
                }
                (_, None) => return Err(PackError("zstd dictionary missing")),
            };
            let header = frame_header(stored)?;
            let size = entry.decoded_length - BLOB_DOMAIN.len() as u64;
            if header.content_size != Some(size) {
                return Err(PackError("zstd frame content size differs from the index"));
            }
            match dictionary {
                None if header.dictionary_id != 0 => {
                    return Err(PackError("zstd frame names a dictionary"));
                }
                Some((_, did)) if header.dictionary_id != 0 && header.dictionary_id != did => {
                    return Err(PackError("zstd frame names another dictionary"));
                }
                _ => {}
            }
            let size =
                usize::try_from(size).map_err(|_| PackError("pack member larger than allowed"))?;
            let content = decompress(stored, dictionary.map(|(d, _)| d), size)?;
            let mut object = Vec::with_capacity(BLOB_DOMAIN.len() + content.len());
            object.extend_from_slice(BLOB_DOMAIN);
            object.extend_from_slice(&content);
            (object, header.checksum && options.trust_checksums)
        }
    };
    if !checked && identity(&object) != entry.id {
        return Err(PackError("pack object identity mismatch"));
    }
    Ok(object)
}

/// One zstd frame's content, exactly `size` bytes, checking the frame's
/// checksum if it has one.
#[cfg(feature = "zstd")]
fn decompress(frame: &[u8], dictionary: Option<&[u8]>, size: usize) -> Result<Vec<u8>> {
    let bad = PackError("invalid zstd frame");
    if zstd::zstd_safe::find_frame_compressed_size(frame)
        .map_err(|_| PackError("invalid zstd frame"))?
        != frame.len()
    {
        return Err(PackError("not exactly one zstd frame"));
    }
    let mut decoder = match dictionary {
        Some(d) => zstd::bulk::Decompressor::with_dictionary(d),
        None => zstd::bulk::Decompressor::new(),
    }
    .map_err(|_| PackError("invalid zstd dictionary"))?;
    let content = decoder.decompress(frame, size).map_err(|_| bad)?;
    if content.len() != size {
        return Err(PackError("zstd frame content size differs from the index"));
    }
    Ok(content)
}

/// One zstd frame's content, exactly `size` bytes, checking the frame's
/// checksum if it has one.
#[cfg(all(feature = "ruzstd", not(feature = "zstd")))]
fn decompress(frame: &[u8], dictionary: Option<&[u8]>, size: usize) -> Result<Vec<u8>> {
    use ruzstd::decoding::{BlockDecodingStrategy, Dictionary, FrameDecoder};
    let bad = |_| PackError("invalid zstd frame");
    let mut decoder = FrameDecoder::new();
    let mut forced = None;
    if let Some(d) = dictionary {
        let d = Dictionary::decode_dict(d).map_err(|_| PackError("invalid zstd dictionary"))?;
        forced = Some(d.id);
        decoder.add_dict(d).map_err(bad)?;
    }
    let mut input = frame;
    decoder.init(&mut input).map_err(bad)?;
    if let Some(id) = forced {
        decoder.force_dict(id).map_err(bad)?;
    }
    let mut content = Vec::with_capacity(size);
    // A block at a time, so a frame that decodes to more than it declared
    // stops at the first block past the declared size.
    while !decoder.is_finished() {
        decoder
            .decode_blocks(&mut input, BlockDecodingStrategy::UptoBlocks(1))
            .map_err(bad)?;
        decoder
            .collect_to_writer(&mut content)
            .map_err(|_| PackError("invalid zstd frame"))?;
        if content.len() > size {
            return Err(PackError("zstd frame content size differs from the index"));
        }
    }
    decoder
        .collect_to_writer(&mut content)
        .map_err(|_| PackError("invalid zstd frame"))?;
    if !input.is_empty() {
        return Err(PackError("not exactly one zstd frame"));
    }
    if content.len() != size {
        return Err(PackError("zstd frame content size differs from the index"));
    }
    if let Some(sum) = decoder.get_checksum_from_data()
        && decoder.get_calculated_checksum() != Some(sum)
    {
        return Err(PackError("zstd frame checksum mismatch"));
    }
    Ok(content)
}

#[cfg(not(any(feature = "zstd", feature = "ruzstd")))]
fn decompress(_: &[u8], _: Option<&[u8]>, _: usize) -> Result<Vec<u8>> {
    Err(PackError(
        "reading zstd pack members needs the zstd or ruzstd feature",
    ))
}

/// Reads a whole pack and verifies everything: the header and index, each
/// object's identity, and that the data is exactly the objects in
/// canonical order, with nothing unreachable and no bytes to spare. So a
/// pack that decodes is the only pack its roots and objects encode to, or,
/// with encoded members, the only one with those members' stored bytes.
/// Uses the default [`ReadOptions`].
pub fn decode(pack: &[u8]) -> Result<Pack> {
    decode_with(pack, &ReadOptions::default())
}

/// [`decode`] with these options.
pub fn decode_with(pack: &[u8], options: &ReadOptions) -> Result<Pack> {
    let index = Index::parse(pack)?;
    let entries = &index.entries;
    let stored = |e: &Entry| -> Result<&[u8]> {
        usize::try_from(e.offset)
            .ok()
            .zip(usize::try_from(e.offset + e.length).ok())
            .filter(|&(_, end)| end <= pack.len())
            .map(|(start, end)| &pack[start..end])
            .ok_or(PackError("invalid pack object bounds"))
    };
    // Members without a dictionary first, so dictionaries are ready.
    let mut objects: Vec<Option<Vec<u8>>> = vec![None; entries.len()];
    for with_dictionary in [false, true] {
        for (i, e) in entries.iter().enumerate() {
            let dictionary = match e.encoding {
                Encoding::ZstdDictionary(d) if with_dictionary => objects[d as usize].as_deref(),
                Encoding::ZstdDictionary(_) => continue,
                _ if with_dictionary => continue,
                _ => None,
            };
            objects[i] = Some(read_member(e, stored(e)?, dictionary, options)?);
        }
    }
    let objects: Vec<Vec<u8>> = objects
        .into_iter()
        .map(|o| o.expect("every member read"))
        .collect();
    let ids: Vec<&Identity> = entries.iter().map(|e| &e.id).collect();
    let order = canonical_order(&index.roots, &ids, |m, i| {
        encoded_references(m, i, entries[i].encoding, &objects[i])
    })?;
    let mut expected = Index::needed(pack)? as u64;
    for m in order {
        if entries[m].offset != expected {
            return Err(PackError("pack data not in canonical order"));
        }
        expected += entries[m].length;
    }
    if expected != pack.len() as u64 {
        return Err(PackError("unused bytes in pack data area"));
    }
    let mut set = Objects::new();
    for (e, bytes) in entries.iter().zip(objects) {
        // Read and checked above, by identity or, if the caller chose, by a
        // frame's checksum.
        set.insert_unchecked(e.id, bytes);
    }
    Ok(Pack {
        roots: index.roots,
        objects: set,
    })
}
