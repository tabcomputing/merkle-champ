//! The persistent CHAMP map. See the crate documentation for its properties
//! and requirements, and FORMAT.md for the identity format.

use crate::codec::{Decode, DecodeError, Loader, Objects, Sink, read_bytes, read_identity};
use crate::{BITS, FANOUT_MASK, HASH_BITS, Identify, Identity, KeyHash, write_tagged};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::{Arc, OnceLock};

// ------------------------------------------------------------------ nodes
//
// A node is ONE allocation: `Arc<[Slot]>`, whose first slot is the header and
// whose remaining slots are the inline entries (in bit order) followed by the
// child pointers (in bit order). Keeping header, entries and child pointers in
// the same allocation makes each trie level a single pointer hop.

type Node<K, V> = Arc<[Slot<K, V>]>;

#[derive(Clone)]
enum Slot<K, V> {
    Header(Header),
    Entry(K, V),
    Child(Node<K, V>),
}

#[derive(Clone)]
struct Header {
    datamap: u32,
    nodemap: u32,
    /// Entries in this subtree.
    size: usize,
    /// `Some(hash)` for a collision node (all entries share this full hash,
    /// sorted by key, no children); `None` for a branch.
    collision: Option<u64>,
    identity: OnceLock<Box<Identity>>,
}

fn fragment(hash: u64, shift: u32) -> u32 {
    ((hash >> shift) & FANOUT_MASK) as u32
}

fn index(map: u32, bit: u32) -> usize {
    (map & (bit - 1)).count_ones() as usize
}

fn header<K, V>(node: &[Slot<K, V>]) -> &Header {
    match &node[0] {
        Slot::Header(h) => h,
        _ => unreachable!("node without header"),
    }
}

fn header_mut<K, V>(node: &mut [Slot<K, V>]) -> &mut Header {
    match &mut node[0] {
        Slot::Header(h) => h,
        _ => unreachable!("node without header"),
    }
}

fn entry_kv<K, V>(node: &[Slot<K, V>], i: usize) -> (&K, &V) {
    match &node[1 + i] {
        Slot::Entry(k, v) => (k, v),
        _ => unreachable!("not an entry slot"),
    }
}

fn size<K, V>(node: &[Slot<K, V>]) -> usize {
    header(node).size
}

fn empty_node<K, V>() -> Node<K, V> {
    Arc::from(vec![Slot::Header(Header {
        datamap: 0,
        nodemap: 0,
        size: 0,
        collision: None,
        identity: OnceLock::new(),
    })])
}

fn build<K, V>(
    datamap: u32,
    nodemap: u32,
    size: usize,
    collision: Option<u64>,
    slots: Vec<Slot<K, V>>,
) -> Node<K, V> {
    let mut all = Vec::with_capacity(slots.len() + 1);
    all.push(Slot::Header(Header {
        datamap,
        nodemap,
        size,
        collision,
        identity: OnceLock::new(),
    }));
    all.extend(slots);
    Arc::from(all)
}

/// Builds the canonical sub-trie holding two entries whose hashes agree on
/// every fragment above `shift`.
fn merge_two<K: Ord, V>(a: (K, V), ha: u64, b: (K, V), hb: u64, shift: u32) -> Node<K, V> {
    if shift >= HASH_BITS {
        let (first, second) = if a.0 < b.0 { (a, b) } else { (b, a) };
        return build(
            0,
            0,
            2,
            Some(ha),
            vec![
                Slot::Entry(first.0, first.1),
                Slot::Entry(second.0, second.1),
            ],
        );
    }
    let (fa, fb) = (fragment(ha, shift), fragment(hb, shift));
    if fa == fb {
        let child = merge_two(a, ha, b, hb, shift + BITS);
        build(0, 1 << fa, 2, None, vec![Slot::Child(child)])
    } else {
        let (first, second) = if fa < fb { (a, b) } else { (b, a) };
        build(
            (1 << fa) | (1 << fb),
            0,
            2,
            None,
            vec![
                Slot::Entry(first.0, first.1),
                Slot::Entry(second.0, second.1),
            ],
        )
    }
}

fn get<'a, K: Ord, V>(mut node: &'a [Slot<K, V>], key: &K, hash: u64) -> Option<&'a V> {
    let mut shift = 0;
    loop {
        let h = header(node);
        if h.collision.is_some() {
            return (1..node.len()).find_map(|i| match &node[i] {
                Slot::Entry(k, v) if k == key => Some(v),
                _ => None,
            });
        }
        let bit = 1 << fragment(hash, shift);
        if h.datamap & bit != 0 {
            let (k, v) = entry_kv(node, index(h.datamap, bit));
            return (k == key).then_some(v);
        }
        if h.nodemap & bit == 0 {
            return None;
        }
        let skip = 1 + h.datamap.count_ones() as usize + index(h.nodemap, bit);
        node = match &node[skip] {
            Slot::Child(c) => c,
            _ => unreachable!(),
        };
        shift += BITS;
    }
}

/// Inserts into a node, copying it only if it is shared. Returns the previous
/// value if the key was present.
fn insert<K, V>(node: &mut Node<K, V>, key: K, value: V, hash: u64, shift: u32) -> Option<V>
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    let h = header(node).clone();
    if h.collision.is_some() {
        let pos = (1..node.len()).position(|i| matches!(&node[i], Slot::Entry(k, _) if *k >= key));
        if let Some(p) = pos
            && let Slot::Entry(k, _) = &node[1 + p]
            && *k == key
        {
            let slots = Arc::make_mut(node);
            header_mut(slots).identity = OnceLock::new();
            let Slot::Entry(_, v) = &mut slots[1 + p] else {
                unreachable!()
            };
            return Some(std::mem::replace(v, value));
        }
        let mut slots: Vec<_> = node[1..].to_vec();
        slots.insert(pos.unwrap_or(slots.len()), Slot::Entry(key, value));
        *node = build(0, 0, h.size + 1, h.collision, slots);
        return None;
    }
    let bit = 1 << fragment(hash, shift);
    let entries = h.datamap.count_ones() as usize;
    if h.datamap & bit != 0 {
        let i = index(h.datamap, bit);
        let same = matches!(&node[1 + i], Slot::Entry(k, _) if *k == key);
        if same {
            let slots = Arc::make_mut(node);
            header_mut(slots).identity = OnceLock::new();
            let Slot::Entry(_, v) = &mut slots[1 + i] else {
                unreachable!()
            };
            return Some(std::mem::replace(v, value));
        }
        // Two keys at one position: push both down one level.
        let (ek, ev) = {
            let (k, v) = entry_kv(node, i);
            (k.clone(), v.clone())
        };
        let eh = ek.key_hash();
        let sub = merge_two((ek, ev), eh, (key, value), hash, shift + BITS);
        let datamap = h.datamap & !bit;
        let nodemap = h.nodemap | bit;
        let mut slots: Vec<Slot<K, V>> = Vec::with_capacity(node.len() - 1);
        for (j, s) in node[1..].iter().enumerate() {
            if j != i {
                slots.push(s.clone());
            }
        }
        let child_at = entries - 1 + index(nodemap, bit);
        slots.insert(child_at, Slot::Child(sub));
        *node = build(datamap, nodemap, h.size + 1, None, slots);
        None
    } else if h.nodemap & bit != 0 {
        let at = 1 + entries + index(h.nodemap, bit);
        let slots = Arc::make_mut(node);
        let Slot::Child(c) = &mut slots[at] else {
            unreachable!()
        };
        let old = insert(c, key, value, hash, shift + BITS);
        let hm = header_mut(slots);
        hm.identity = OnceLock::new();
        if old.is_none() {
            hm.size += 1;
        }
        old
    } else {
        let datamap = h.datamap | bit;
        let mut slots: Vec<Slot<K, V>> = node[1..].to_vec();
        slots.insert(index(datamap, bit), Slot::Entry(key, value));
        *node = build(datamap, h.nodemap, h.size + 1, None, slots);
        None
    }
}

/// Removes a present key (the caller has checked presence), copying only
/// shared nodes. A sub-trie left holding one entry is re-inlined into its
/// parent, which keeps the shape canonical.
/// Mutable access to a present value (the caller has checked presence),
/// copying only shared nodes on the path and clearing their cached identities.
fn get_mut<'a, K, V>(node: &'a mut Node<K, V>, key: &K, hash: u64, shift: u32) -> &'a mut V
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    let slots = Arc::make_mut(node);
    let h = header_mut(slots);
    h.identity = OnceLock::new();
    let (datamap, nodemap, collision) = (h.datamap, h.nodemap, h.collision);
    let at = if collision.is_some() {
        (1..slots.len())
            .find(|&i| matches!(&slots[i], Slot::Entry(k, _) if k == key))
            .expect("present")
    } else {
        let bit = 1 << fragment(hash, shift);
        if datamap & bit != 0 {
            1 + index(datamap, bit)
        } else {
            1 + datamap.count_ones() as usize + index(nodemap, bit)
        }
    };
    match &mut slots[at] {
        Slot::Entry(_, v) => v,
        Slot::Child(c) => get_mut(c, key, hash, shift + BITS),
        Slot::Header(_) => unreachable!(),
    }
}

fn remove<K, V>(node: &mut Node<K, V>, key: &K, hash: u64, shift: u32) -> V
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    let h = header(node).clone();
    if h.collision.is_some() {
        let mut slots: Vec<_> = node[1..].to_vec();
        let p = slots
            .iter()
            .position(|s| matches!(s, Slot::Entry(k, _) if k == key))
            .expect("present");
        let Slot::Entry(_, v) = slots.remove(p) else {
            unreachable!()
        };
        *node = build(0, 0, h.size - 1, h.collision, slots);
        return v;
    }
    let bit = 1 << fragment(hash, shift);
    let entries = h.datamap.count_ones() as usize;
    if h.datamap & bit != 0 {
        let i = index(h.datamap, bit);
        let mut slots: Vec<_> = node[1..].to_vec();
        let Slot::Entry(_, v) = slots.remove(i) else {
            unreachable!()
        };
        *node = build(h.datamap & !bit, h.nodemap, h.size - 1, None, slots);
        return v;
    }
    let at = 1 + entries + index(h.nodemap, bit);
    let Slot::Child(child) = &node[at] else {
        unreachable!()
    };
    if size(child) == 2 {
        // The sub-trie will hold one entry, which canonical form keeps in
        // this node. Build the replacement completely (all user Clone and
        // comparison calls) before changing anything, so a panic in user
        // code cannot leave a non-canonical singleton behind.
        let mut pair = Vec::with_capacity(2);
        all_entries(child, &mut pair);
        let keep = if pair[0].0 == *key { 1 } else { 0 };
        let removed = pair[1 - keep].1.clone();
        let (k, v) = pair.swap_remove(keep);
        let datamap = h.datamap | bit;
        let nodemap = h.nodemap & !bit;
        let mut slots: Vec<Slot<K, V>> = Vec::with_capacity(node.len() - 1);
        for (j, s) in node[1..].iter().enumerate() {
            if 1 + j != at {
                slots.push(s.clone());
            }
        }
        slots.insert(index(datamap, bit), Slot::Entry(k, v));
        *node = build(datamap, nodemap, h.size - 1, None, slots);
        return removed;
    }
    // The sub-trie keeps at least two entries, so it stays a child. Only
    // nodes on the path are copied; their cached identities are cleared
    // after the change below them has succeeded.
    let slots = Arc::make_mut(node);
    let Slot::Child(c) = &mut slots[at] else {
        unreachable!()
    };
    let removed = remove(c, key, hash, shift + BITS);
    let hm = header_mut(slots);
    hm.identity = OnceLock::new();
    hm.size -= 1;
    removed
}

const BRANCH_DOMAIN: &[u8] = b"merkle-champ/branch/v1";
const COLLISION_DOMAIN: &[u8] = b"merkle-champ/collision/v1";

/// Writes a node's encoding (FORMAT.md, section 4): its identity preimage,
/// which is also its stored form. `child` supplies each child's identity.
fn write_node<K: Identify, V: Identify, S: Sink>(
    node: &[Slot<K, V>],
    sink: &mut S,
    mut child: impl FnMut(&Node<K, V>) -> Identity,
) {
    let h = header(node);
    match h.collision {
        Some(_) => {
            sink.update(COLLISION_DOMAIN);
            sink.update(&((node.len() - 1) as u64).to_le_bytes());
        }
        None => {
            sink.update(BRANCH_DOMAIN);
            sink.update(&h.datamap.to_le_bytes());
            sink.update(&h.nodemap.to_le_bytes());
        }
    }
    for slot in &node[1..] {
        match slot {
            Slot::Entry(k, v) => {
                k.identify(sink);
                v.identify(sink);
            }
            Slot::Child(c) => sink.update(&child(c)),
            Slot::Header(_) => unreachable!(),
        }
    }
}

fn identity_of<K: Identify, V: Identify>(node: &[Slot<K, V>]) -> Identity {
    **header(node).identity.get_or_init(|| {
        let mut s = Sha256::new();
        write_node(node, &mut s, |c| identity_of(c));
        Box::new(s.finalize().into())
    })
}

/// Adds `node`'s subtree to `objects`, children before parents, skipping any
/// subtree whose root is already there. Values' separately stored objects
/// (nested maps) are added too. Returns the node's identity.
fn save_node<K: Identify, V: Identify>(node: &Node<K, V>, objects: &mut Objects) -> Identity {
    if let Some(id) = cached_identity(node)
        && objects.contains(&id)
    {
        return id;
    }
    let mut children = Vec::new();
    for slot in &node[1..] {
        match slot {
            Slot::Entry(k, v) => {
                k.save_objects(objects);
                v.save_objects(objects);
            }
            Slot::Child(c) => children.push(save_node(c, objects)),
            Slot::Header(_) => unreachable!(),
        }
    }
    let mut bytes = Vec::new();
    let mut ids = children.into_iter();
    write_node(node, &mut bytes, |_| {
        ids.next().expect("one identity per child")
    });
    // A cached identity was computed from exactly these bytes, so there is no
    // need to hash them again.
    match cached_identity(node) {
        Some(id) => {
            objects.insert_known(id, bytes);
            id
        }
        None => {
            let id = objects.insert(bytes);
            let _ = header(node).identity.set(Box::new(id));
            id
        }
    }
}

fn read_u32(input: &mut &[u8]) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(
        read_bytes(input, 4)?.try_into().expect("4 bytes"),
    ))
}

/// Loads the node `id` found at trie depth `shift` below the hash prefix
/// `prefix`, checking that it is canonical there. Returns the node and its
/// subtree size.
fn load_node<K, V>(
    id: &Identity,
    loader: &mut Loader<'_>,
    shift: u32,
    prefix: u64,
    root: bool,
) -> Result<(Node<K, V>, usize), DecodeError>
where
    K: KeyHash + Ord + Decode,
    V: Decode,
{
    use DecodeError::{Malformed, Missing, NonCanonical};
    let bytes = loader.objects().get(id).ok_or(Missing(*id))?;
    let mut input = bytes;
    let (node, size) = if let Some(rest) = input.strip_prefix(BRANCH_DOMAIN) {
        input = rest;
        if shift >= HASH_BITS {
            return Err(NonCanonical("branch node below the last trie level"));
        }
        let datamap = read_u32(&mut input)?;
        let nodemap = read_u32(&mut input)?;
        if datamap & nodemap != 0 {
            return Err(NonCanonical("position used by both an entry and a child"));
        }
        // The last level has fewer than five hash bits left (4 at shift 60,
        // so 16 positions), and positions beyond them cannot be selected.
        if HASH_BITS - shift < BITS && (datamap | nodemap) >> (1u32 << (HASH_BITS - shift)) != 0 {
            return Err(NonCanonical("position beyond the remaining hash bits"));
        }
        let mask = if shift == 0 {
            0
        } else {
            (1u64 << shift.min(63)) - 1
        };
        let entries = datamap.count_ones() as usize;
        let children = nodemap.count_ones() as usize;
        if !root && children == 0 && entries < 2 {
            return Err(NonCanonical("singleton or empty node below the root"));
        }
        let mut slots = Vec::with_capacity(entries + children);
        for f in (0..32u32).filter(|f| datamap & (1 << f) != 0) {
            let k = K::decode(&mut input, loader)?;
            let v = V::decode(&mut input, loader)?;
            let kh = k.key_hash();
            if fragment(kh, shift) != f || (kh & mask) != (prefix & mask) {
                return Err(NonCanonical("entry stored at the wrong position"));
            }
            slots.push(Slot::Entry(k, v));
        }
        let mut size = entries;
        for f in (0..32u32).filter(|f| nodemap & (1 << f) != 0) {
            let child: Identity = read_bytes(&mut input, 32)?.try_into().expect("32 bytes");
            let (c, n) = load_node(
                &child,
                loader,
                shift + BITS,
                prefix | (u64::from(f) << shift),
                false,
            )?;
            size += n;
            slots.push(Slot::Child(c));
        }
        (build(datamap, nodemap, size, None, slots), size)
    } else if let Some(rest) = input.strip_prefix(COLLISION_DOMAIN) {
        input = rest;
        if shift < HASH_BITS {
            return Err(NonCanonical("collision node above the last trie level"));
        }
        let count = u64::from_le_bytes(read_bytes(&mut input, 8)?.try_into().expect("8 bytes"));
        if count < 2 {
            return Err(NonCanonical("collision node with fewer than two entries"));
        }
        // Each entry takes at least one byte, which bounds the allocation.
        if count > input.len() as u64 {
            return Err(Malformed("entry count exceeds input"));
        }
        let mut slots: Vec<Slot<K, V>> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let k = K::decode(&mut input, loader)?;
            let v = V::decode(&mut input, loader)?;
            if k.key_hash() != prefix {
                return Err(NonCanonical("collision entry with a different hash"));
            }
            if let Some(Slot::Entry(last, _)) = slots.last()
                && *last >= k
            {
                return Err(NonCanonical(
                    "collision entries not in strictly increasing order",
                ));
            }
            slots.push(Slot::Entry(k, v));
        }
        let size = count as usize;
        (build(0, 0, size, Some(prefix), slots), size)
    } else {
        return Err(Malformed("unknown node domain"));
    };
    if !input.is_empty() {
        return Err(Malformed("trailing bytes after a node"));
    }
    let _ = header(&node).identity.set(Box::new(*id));
    Ok((node, size))
}

fn cached_identity<K, V>(node: &[Slot<K, V>]) -> Option<Identity> {
    header(node).identity.get().map(|b| **b)
}

// -------------------------------------------------------------------- map

/// A persistent CHAMP hash map. `Clone` is O(1).
pub struct ChampMap<K, V> {
    root: Node<K, V>,
}

impl<K, V> Clone for ChampMap<K, V> {
    fn clone(&self) -> Self {
        ChampMap {
            root: self.root.clone(),
        }
    }
}

impl<K, V> Default for ChampMap<K, V> {
    fn default() -> Self {
        ChampMap { root: empty_node() }
    }
}

/// One difference between two versions of a map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change<K, V> {
    Added(K, V),
    Removed(K, V),
    Changed(K, V, V),
}

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        size(&self.root)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        get(&self.root, key, key.key_hash())
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Inserts or replaces, returning the previous value. Copies only the
    /// nodes on the path that are shared with another version.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = key.key_hash();
        insert(&mut self.root, key, value, hash, 0)
    }

    /// Persistent form of [`insert`](Self::insert): a new version, `self` unchanged.
    pub fn update(&self, key: K, value: V) -> Self {
        let mut next = self.clone();
        next.insert(key, value);
        next
    }

    /// Removes a key, returning its value. The resulting shape is exactly
    /// the shape the map would have if the key had never been inserted.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let hash = key.key_hash();
        get(&self.root, key, hash)?;
        Some(remove(&mut self.root, key, hash, 0))
    }

    /// Mutable access to a value, for example a nested map. Copies only the
    /// shared nodes on the path and invalidates their cached identities.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let hash = key.key_hash();
        get(&self.root, key, hash)?;
        Some(get_mut(&mut self.root, key, hash, 0))
    }

    /// Persistent form of [`remove`](Self::remove).
    pub fn without(&self, key: &K) -> Self {
        let mut next = self.clone();
        next.remove(key);
        next
    }

    /// Entries in trie order, which is deterministic for given contents.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            stack: vec![(&self.root[..], 1)],
        }
    }

    /// True if both versions share the same root node (a cheap sufficient
    /// test for equality).
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
    }
}

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Identify,
    V: Clone + Identify,
{
    /// The map's content identity. Computed lazily; nodes shared with an
    /// earlier version reuse their cached identities.
    pub fn identity(&self) -> Identity {
        identity_of(&self.root)
    }
}

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Identify,
    V: Clone + Identify + PartialEq,
{
    /// All differences from `self` to `other`. Shared sub-tries are skipped
    /// by pointer, and by identity when both identities are already cached;
    /// diffing never computes identities itself.
    pub fn diff(&self, other: &Self) -> Vec<Change<K, V>> {
        let mut out = Vec::new();
        diff_nodes(&self.root, &other.root, &mut out);
        out
    }
}

impl<K, V> Identify for ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Identify,
    V: Clone + Identify,
{
    /// Lets maps nest (for example one map per namespace level): a nested
    /// map contributes its own (cached) identity to its parent's.
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        write_tagged(sink, b'm', &self.identity());
    }

    /// A nested map is stored as its own tree; the parent holds its identity.
    fn save_objects(&self, objects: &mut Objects) {
        self.save(objects);
    }
}

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Identify,
    V: Clone + Identify,
{
    /// Adds every node of this map, and every nested map it holds, to
    /// `objects`, and returns the map's identity. A stored node is exactly the
    /// bytes its identity hashes (FORMAT.md, section 9).
    ///
    /// Subtrees whose roots are already in `objects` are skipped, so saving a
    /// new version into the same set costs only the nodes on changed paths.
    /// That relies on `objects` holding whole subtrees, which is what `save`
    /// always produces.
    pub fn save(&self, objects: &mut Objects) -> Identity {
        save_node(&self.root, objects)
    }
}

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Decode + 'static,
    V: Clone + Decode + 'static,
{
    /// Reads back the map whose identity is `root` from `objects`.
    ///
    /// Every node is checked to be canonical where it is found, so the result
    /// is a well-formed map whatever the bytes. The loaded map has its
    /// identities already cached. Nested maps that occur more than once are
    /// loaded once and shared.
    pub fn load(root: &Identity, objects: &Objects) -> Result<Self, DecodeError> {
        Self::load_with(root, &mut Loader::new(objects))
    }

    /// Like [`load`](Self::load), within an existing [`Loader`], so that
    /// nested maps are shared across several loads.
    pub fn load_with(root: &Identity, loader: &mut Loader<'_>) -> Result<Self, DecodeError> {
        let (root, _) = load_node(root, loader, 0, 0, true)?;
        Ok(ChampMap { root })
    }
}

impl<K, V> Decode for ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Decode + 'static,
    V: Clone + Decode + 'static,
{
    /// Reads a nested map reference (tag `m`) and loads the map it names.
    fn decode(input: &mut &[u8], loader: &mut Loader<'_>) -> Result<Self, DecodeError> {
        let id = read_identity(input, b'm')?;
        loader.nested(id, |l| Self::load_with(&id, l))
    }
}

/// Structural equality of two canonical tries: equal contents imply equal
/// shape, so nodes compare slot by slot. Shared nodes are skipped by pointer,
/// and by identity when both identities are already cached.
fn nodes_equal<K: PartialEq, V: PartialEq>(a: &Node<K, V>, b: &Node<K, V>) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    if let (Some(x), Some(y)) = (cached_identity(a), cached_identity(b)) {
        return x == y;
    }
    let (ha, hb) = (header(a), header(b));
    if ha.datamap != hb.datamap
        || ha.nodemap != hb.nodemap
        || ha.size != hb.size
        || ha.collision != hb.collision
        || a.len() != b.len()
    {
        return false;
    }
    a[1..].iter().zip(&b[1..]).all(|pair| match pair {
        (Slot::Entry(k1, v1), Slot::Entry(k2, v2)) => k1 == k2 && v1 == v2,
        (Slot::Child(c1), Slot::Child(c2)) => nodes_equal(c1, c2),
        _ => false,
    })
}

impl<K: PartialEq, V: PartialEq> PartialEq for ChampMap<K, V> {
    /// Content equality. Needs only `PartialEq` on keys and values; relies on
    /// the canonical shape, so `KeyHash` must agree with key equality. Shared
    /// nodes, and nodes whose cached identities are equal, compare equal
    /// without inspecting values, so a map equals itself even when a value's
    /// `PartialEq` is not reflexive (such as a float NaN).
    fn eq(&self, other: &Self) -> bool {
        nodes_equal(&self.root, &other.root)
    }
}

impl<K: Eq, V: Eq> Eq for ChampMap<K, V> {}

impl<K: fmt::Debug + KeyHash + Ord + Clone, V: fmt::Debug + Clone> fmt::Debug for ChampMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V> FromIterator<(K, V)> for ChampMap<K, V>
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = ChampMap::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

pub struct Iter<'a, K, V> {
    /// (node, next slot to visit)
    stack: Vec<(&'a [Slot<K, V>], usize)>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, at) = self.stack.last_mut()?;
            let node: &'a [Slot<K, V>] = node;
            if *at >= node.len() {
                self.stack.pop();
                continue;
            }
            let slot = &node[*at];
            *at += 1;
            match slot {
                Slot::Entry(k, v) => return Some((k, v)),
                Slot::Child(c) => self.stack.push((&c[..], 1)),
                Slot::Header(_) => unreachable!(),
            }
        }
    }
}

// ------------------------------------------------------------------- diff

fn all_entries<K: Clone, V: Clone>(node: &[Slot<K, V>], out: &mut Vec<(K, V)>) {
    for slot in &node[1..] {
        match slot {
            Slot::Entry(k, v) => out.push((k.clone(), v.clone())),
            Slot::Child(c) => all_entries(c, out),
            Slot::Header(_) => unreachable!(),
        }
    }
}

/// Differences between a single entry on one side and a whole sub-trie on
/// the other: everything in the sub-trie is added, except the entry's own
/// key, which is unchanged, changed, or removed.
fn diff_entry_node<K, V>(
    entry: (&K, &V),
    node: &[Slot<K, V>],
    entry_is_old: bool,
    out: &mut Vec<Change<K, V>>,
) where
    K: Ord + Clone,
    V: Clone + PartialEq,
{
    let mut others = Vec::new();
    all_entries(node, &mut others);
    let mut found = false;
    for (k, v) in others {
        if k == *entry.0 {
            found = true;
            if v != *entry.1 {
                out.push(if entry_is_old {
                    Change::Changed(k, entry.1.clone(), v)
                } else {
                    Change::Changed(k, v, entry.1.clone())
                });
            }
        } else if entry_is_old {
            out.push(Change::Added(k, v));
        } else {
            out.push(Change::Removed(k, v));
        }
    }
    if !found {
        let (k, v) = (entry.0.clone(), entry.1.clone());
        out.push(if entry_is_old {
            Change::Removed(k, v)
        } else {
            Change::Added(k, v)
        });
    }
}

fn diff_nodes<K, V>(a: &Node<K, V>, b: &Node<K, V>, out: &mut Vec<Change<K, V>>)
where
    K: Ord + Clone + Identify,
    V: Clone + PartialEq + Identify,
{
    if Arc::ptr_eq(a, b) {
        return;
    }
    if let (Some(x), Some(y)) = (cached_identity(a), cached_identity(b))
        && x == y
    {
        return;
    }
    let (ha, hb) = (header(a), header(b));
    if ha.collision.is_some() {
        // Both are collision nodes (they only occur past the last level).
        let mut x = Vec::new();
        let mut y = Vec::new();
        all_entries(a, &mut x);
        all_entries(b, &mut y);
        let (mut i, mut j) = (0, 0);
        while i < x.len() || j < y.len() {
            match (x.get(i), y.get(j)) {
                (Some(p), Some(q)) if p.0 == q.0 => {
                    if p.1 != q.1 {
                        out.push(Change::Changed(p.0.clone(), p.1.clone(), q.1.clone()));
                    }
                    i += 1;
                    j += 1;
                }
                (Some(p), Some(q)) if p.0 < q.0 => {
                    out.push(Change::Removed(p.0.clone(), p.1.clone()));
                    i += 1;
                }
                (Some(_) | None, Some(q)) => {
                    out.push(Change::Added(q.0.clone(), q.1.clone()));
                    j += 1;
                }
                (Some(p), None) => {
                    out.push(Change::Removed(p.0.clone(), p.1.clone()));
                    i += 1;
                }
                (None, None) => unreachable!(),
            }
        }
        return;
    }
    let (ea, eb) = (
        ha.datamap.count_ones() as usize,
        hb.datamap.count_ones() as usize,
    );
    let positions = ha.datamap | ha.nodemap | hb.datamap | hb.nodemap;
    for f in 0..32 {
        let bit = 1u32 << f;
        if positions & bit == 0 {
            continue;
        }
        let xe = (ha.datamap & bit != 0).then(|| entry_kv(a, index(ha.datamap, bit)));
        let ye = (hb.datamap & bit != 0).then(|| entry_kv(b, index(hb.datamap, bit)));
        let xc = (ha.nodemap & bit != 0).then(|| match &a[1 + ea + index(ha.nodemap, bit)] {
            Slot::Child(c) => c,
            _ => unreachable!(),
        });
        let yc = (hb.nodemap & bit != 0).then(|| match &b[1 + eb + index(hb.nodemap, bit)] {
            Slot::Child(c) => c,
            _ => unreachable!(),
        });
        match (xe, xc, ye, yc) {
            (Some(p), _, Some(q), _) => {
                if p.0 == q.0 {
                    if p.1 != q.1 {
                        out.push(Change::Changed(p.0.clone(), p.1.clone(), q.1.clone()));
                    }
                } else {
                    out.push(Change::Removed(p.0.clone(), p.1.clone()));
                    out.push(Change::Added(q.0.clone(), q.1.clone()));
                }
            }
            (Some(p), _, None, Some(n)) => diff_entry_node(p, n, true, out),
            (None, Some(n), Some(q), _) => diff_entry_node(q, n, false, out),
            (None, Some(m), None, Some(n)) => diff_nodes(m, n, out),
            (Some(p), _, None, None) => out.push(Change::Removed(p.0.clone(), p.1.clone())),
            (None, None, Some(q), _) => out.push(Change::Added(q.0.clone(), q.1.clone())),
            (None, Some(m), None, None) => {
                let mut gone = Vec::new();
                all_entries(m, &mut gone);
                out.extend(gone.into_iter().map(|(k, v)| Change::Removed(k, v)));
            }
            (None, None, None, Some(n)) => {
                let mut new = Vec::new();
                all_entries(n, &mut new);
                out.extend(new.into_iter().map(|(k, v)| Change::Added(k, v)));
            }
            (None, None, None, None) => unreachable!(),
        }
    }
}

// ------------------------------------------------------- structure checks

impl<K, V> ChampMap<K, V>
where
    K: KeyHash + Ord + Clone,
    V: Clone,
{
    /// Verifies the canonical-form invariants (for tests and debugging):
    /// no singleton below the root, no empty non-root node, sizes correct,
    /// every key in the position its hash selects, collision entries sorted.
    pub fn check_invariants(&self) -> Result<(), String> {
        check(&self.root, 0, true, 0).map(|_| ())
    }
}

fn check<K: KeyHash + Ord, V>(
    node: &[Slot<K, V>],
    shift: u32,
    root: bool,
    prefix: u64,
) -> Result<usize, String> {
    let h = header(node);
    if node[1..].iter().any(|s| matches!(s, Slot::Header(_))) {
        return Err("header slot in the body".into());
    }
    if let Some(hash) = h.collision {
        let keys: Vec<&K> = node[1..]
            .iter()
            .map(|s| match s {
                Slot::Entry(k, _) => Ok(k),
                _ => Err("collision node with a child".to_string()),
            })
            .collect::<Result<_, _>>()?;
        if keys.len() < 2 {
            return Err("collision node with fewer than two entries".into());
        }
        if !keys.windows(2).all(|w| w[0] < w[1]) {
            return Err("collision entries unsorted".into());
        }
        if keys.iter().any(|k| k.key_hash() != hash) {
            return Err("collision entry with a different hash".into());
        }
        if h.size != keys.len() {
            return Err("collision size mismatch".into());
        }
        return Ok(keys.len());
    }
    let mask = if shift == 0 {
        0
    } else {
        (1u64 << shift.min(63)) - 1
    };
    if h.datamap & h.nodemap != 0 {
        return Err("position used by both an entry and a child".into());
    }
    let entries = h.datamap.count_ones() as usize;
    let children = h.nodemap.count_ones() as usize;
    if node.len() != 1 + entries + children {
        return Err("bitmap and slot counts disagree".into());
    }
    if node[1..1 + entries]
        .iter()
        .any(|s| !matches!(s, Slot::Entry(..)))
        || node[1 + entries..]
            .iter()
            .any(|s| !matches!(s, Slot::Child(_)))
    {
        return Err("entries and children out of order".into());
    }
    if !root && children == 0 && entries < 2 {
        return Err("non-canonical: singleton or empty node below the root".into());
    }
    let mut size = entries;
    for f in 0..32u32 {
        let bit = 1 << f;
        if h.datamap & bit != 0 {
            let (k, _) = entry_kv(node, index(h.datamap, bit));
            let kh = k.key_hash();
            if fragment(kh, shift) != f || (kh & mask) != (prefix & mask) {
                return Err("entry stored at the wrong position".into());
            }
        }
        if h.nodemap & bit != 0 {
            let Slot::Child(c) = &node[1 + entries + index(h.nodemap, bit)] else {
                unreachable!()
            };
            size += check(c, shift + BITS, false, prefix | (u64::from(f) << shift))?;
        }
    }
    if size != h.size {
        return Err(format!("cached size {} but counted {}", h.size, size));
    }
    Ok(size)
}

#[doc(hidden)]
impl<K: KeyHash + Ord + Clone, V: Clone> ChampMap<K, V> {
    /// (entries by depth, nodes by depth, total slots) for layout diagnostics.
    pub fn layout_stats(&self) -> (Vec<usize>, Vec<usize>, usize) {
        fn walk<K, V>(
            n: &[Slot<K, V>],
            d: usize,
            e: &mut Vec<usize>,
            nodes: &mut Vec<usize>,
            slots: &mut usize,
        ) {
            if e.len() <= d {
                e.resize(d + 1, 0);
                nodes.resize(d + 1, 0);
            }
            nodes[d] += 1;
            *slots += n.len();
            for s in &n[1..] {
                match s {
                    Slot::Entry(..) => e[d] += 1,
                    Slot::Child(c) => walk(c, d + 1, e, nodes, slots),
                    Slot::Header(_) => {}
                }
            }
        }
        let (mut e, mut n, mut s) = (Vec::new(), Vec::new(), 0);
        walk(&self.root, 0, &mut e, &mut n, &mut s);
        (e, n, s)
    }
}
