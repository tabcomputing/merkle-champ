//! The persistent CHAMP map. See the crate documentation for its properties
//! and requirements, and FORMAT.md for the identity format.

use crate::{BITS, FANOUT_MASK, HASH_BITS, Identify, Identity, KeyHash, feed};
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

fn identity_of<K: Identify, V: Identify>(node: &[Slot<K, V>]) -> Identity {
    let h = header(node);
    **h.identity.get_or_init(|| {
        let mut s = Sha256::new();
        match h.collision {
            Some(_) => {
                s.update(b"merkle-champ/collision/v1");
                s.update(((node.len() - 1) as u64).to_le_bytes());
            }
            None => {
                s.update(b"merkle-champ/branch/v1");
                s.update(h.datamap.to_le_bytes());
                s.update(h.nodemap.to_le_bytes());
            }
        }
        for slot in &node[1..] {
            match slot {
                Slot::Entry(k, v) => {
                    k.identify(&mut s);
                    v.identify(&mut s);
                }
                Slot::Child(c) => s.update(identity_of(c)),
                Slot::Header(_) => unreachable!(),
            }
        }
        Box::new(s.finalize().into())
    })
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
    fn identify(&self, hasher: &mut Sha256) {
        feed(hasher, b'm', &self.identity());
    }
}

impl<K, V> PartialEq for ChampMap<K, V>
where
    K: KeyHash + Ord + Clone + Identify,
    V: Clone + Identify + PartialEq,
{
    /// Content equality (canonical shape makes this a structural walk).
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.diff(other).is_empty()
    }
}

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
