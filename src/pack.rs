//! Immutable indexed packs of stored objects: MCHPACK2 (FORMAT.md, section
//! 11). Little-endian; the index right after the header, so a reader opens a
//! pack lazily; and object data in a canonical order found without type
//! knowledge, so equal contents give byte-identical packs. Blobs and other
//! opaque objects may share a pack with nodes, each right after the first
//! object that refers to it.
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
// 8        4    flags, u32: 0 (others reserved)
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

const MAGIC: &[u8; 8] = b"MCHPACK2";
const HEADER_SIZE: usize = 24;
const ENTRY_SIZE: usize = 48;

/// A decoded and fully verified pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    /// The roots, in the pack's order.
    pub roots: Vec<Identity>,
    pub objects: Objects,
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

/// The canonical order of `objects` (identity order, as `Objects` keeps
/// them) from `roots`, as positions in `objects`: depth-first preorder
/// over references, iteratively, since chains can be long.
fn canonical_order(roots: &[Identity], objects: &[(&Identity, &[u8])]) -> Result<Vec<usize>> {
    let members = Members::new(objects.iter().map(|(id, _)| *id));
    let mut emitted = vec![false; objects.len()];
    let mut order = Vec::with_capacity(objects.len());
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
        let mut stack = vec![(members.references(r, objects[r].1), 0)];
        while let Some((refs, next)) = stack.last_mut() {
            let Some(&m) = refs.get(*next) else {
                stack.pop();
                continue;
            };
            *next += 1;
            if !emitted[m] {
                emitted[m] = true;
                order.push(m);
                let refs = members.references(m, objects[m].1);
                stack.push((refs, 0));
            }
        }
    }
    if order.len() != objects.len() {
        return Err(PackError("pack object not reachable from its roots"));
    }
    Ok(order)
}

fn u64_of(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| PackError("pack size overflow"))
}

/// Writes a pack of `objects` with these roots, which must be unique
/// members. Every object must be reachable from the roots.
pub fn encode(roots: &[Identity], objects: &Objects) -> Result<Vec<u8>> {
    let members: Vec<(&Identity, &[u8])> = objects.iter().collect();
    let order = canonical_order(roots, &members)?;
    let root_count =
        u32::try_from(roots.len()).map_err(|_| PackError("too many roots in pack"))?;
    let data_start = members
        .len()
        .checked_mul(ENTRY_SIZE)
        .and_then(|n| n.checked_add(HEADER_SIZE + 32 * roots.len()))
        .ok_or(PackError("pack size overflow"))?;
    let mut offsets = vec![0u64; members.len()];
    let mut end = data_start;
    for &m in &order {
        offsets[m] = u64_of(end)?;
        end = end
            .checked_add(members[m].1.len())
            .ok_or(PackError("pack size overflow"))?;
    }
    let mut pack = Vec::with_capacity(end);
    pack.extend_from_slice(MAGIC);
    pack.extend_from_slice(&0u32.to_le_bytes());
    pack.extend_from_slice(&root_count.to_le_bytes());
    pack.extend_from_slice(&u64_of(members.len())?.to_le_bytes());
    for root in roots {
        pack.extend_from_slice(root);
    }
    for (m, (id, bytes)) in members.iter().enumerate() {
        pack.extend_from_slice(*id);
        pack.extend_from_slice(&offsets[m].to_le_bytes());
        pack.extend_from_slice(&u64_of(bytes.len())?.to_le_bytes());
    }
    for &m in &order {
        pack.extend_from_slice(members[m].1);
    }
    Ok(pack)
}

/// The header and index of a pack, for reading its objects one at a time.
/// It needs only the pack's first [`Index::needed`] bytes, so a caller
/// fetching a pack by byte range opens it with one read, then fetches
/// objects as [`locate`](Index::locate) says and checks each with
/// [`verify`](Index::verify). It does no I/O.
#[derive(Debug, Clone)]
pub struct Index {
    roots: Vec<Identity>,
    entries: Vec<(Identity, u64, u64)>,
}

impl Index {
    /// How many bytes from the start of a pack hold its header and index,
    /// from at least its first 24 bytes.
    pub fn needed(head: &[u8]) -> Result<usize> {
        if head.len() < HEADER_SIZE || &head[..8] != MAGIC {
            return Err(PackError("invalid pack header"));
        }
        if head[8..12] != [0; 4] {
            return Err(PackError("unknown pack flags"));
        }
        let roots = u32::from_le_bytes(head[12..16].try_into().expect("header")) as usize;
        let count = u64::from_le_bytes(head[16..24].try_into().expect("header"));
        usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(ENTRY_SIZE))
            .and_then(|n| n.checked_add(HEADER_SIZE + 32 * roots))
            .ok_or(PackError("pack index size overflow"))
    }

    /// Reads the header and index from the start of a pack. Checks the
    /// header, that the roots are unique, that index entries are in
    /// strictly increasing identity order, and that every object lies in
    /// the data area, after the index.
    pub fn parse(prefix: &[u8]) -> Result<Index> {
        let data_start = Self::needed(prefix)?;
        if prefix.len() < data_start {
            return Err(PackError("pack index incomplete"));
        }
        let root_count = u32::from_le_bytes(prefix[12..16].try_into().expect("header")) as usize;
        let roots: Vec<Identity> = prefix[HEADER_SIZE..HEADER_SIZE + 32 * root_count]
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32 bytes"))
            .collect();
        if roots.iter().collect::<HashSet<_>>().len() != roots.len() {
            return Err(PackError("pack roots must be unique"));
        }
        let mut entries = Vec::new();
        for e in prefix[HEADER_SIZE + 32 * root_count..data_start].chunks_exact(ENTRY_SIZE) {
            let id: Identity = e[..32].try_into().expect("32 bytes");
            let offset = u64::from_le_bytes(e[32..40].try_into().expect("8 bytes"));
            let length = u64::from_le_bytes(e[40..48].try_into().expect("8 bytes"));
            if entries.last().is_some_and(|(prev, _, _)| *prev >= id) {
                return Err(PackError("pack identities are not unique and sorted"));
            }
            if offset < data_start as u64 || offset.checked_add(length).is_none() {
                return Err(PackError("invalid pack object bounds"));
            }
            entries.push((id, offset, length));
        }
        Ok(Index { roots, entries })
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

    /// The identities of the pack's objects, in identity order.
    pub fn ids(&self) -> impl Iterator<Item = &Identity> {
        self.entries.iter().map(|(id, _, _)| id)
    }

    /// Where an object's bytes lie in the pack: offset and length.
    pub fn locate(&self, id: &Identity) -> Option<(u64, u64)> {
        let i = self.entries.binary_search_by(|(e, _, _)| e.cmp(id)).ok()?;
        let (_, offset, length) = self.entries[i];
        Some((offset, length))
    }

    /// Whether fetched bytes are the object with this identity.
    pub fn verify(id: &Identity, bytes: &[u8]) -> bool {
        identity(bytes) == *id
    }
}

/// Reads a whole pack and verifies everything: the header and index, each
/// object's identity, and that the data is exactly the objects in
/// canonical order, with nothing unreachable and no bytes to spare. So a
/// pack that decodes is the only pack its roots and objects encode to.
pub fn decode(pack: &[u8]) -> Result<Pack> {
    let index = Index::parse(pack)?;
    let mut objects = Objects::new();
    for &(id, offset, length) in &index.entries {
        let (start, end) = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(offset + length).ok())
            .filter(|&(_, end)| end <= pack.len())
            .ok_or(PackError("invalid pack object bounds"))?;
        if objects.insert(&pack[start..end]) != id {
            return Err(PackError("pack object identity mismatch"));
        }
    }
    let members: Vec<(&Identity, &[u8])> = objects.iter().collect();
    let order = canonical_order(&index.roots, &members)?;
    let mut expected = Index::needed(pack)? as u64;
    for m in order {
        let (_, offset, length) = index.entries[m];
        if offset != expected {
            return Err(PackError("pack data not in canonical order"));
        }
        expected += length;
    }
    if expected != pack.len() as u64 {
        return Err(PackError("unused bytes in pack data area"));
    }
    Ok(Pack {
        roots: index.roots,
        objects,
    })
}
