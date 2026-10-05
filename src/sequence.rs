//! A persistent sequence whose shape depends only on its contents, and whose
//! edits anywhere stay local: a content-defined chunked tree, known elsewhere
//! as a prolly tree (Noms, Dolt).
//!
//! **Prototype** (2026-10-05), to compare with [`Vector`](crate::Vector),
//! whose fixed leaf boundaries make an insert in the middle shift, and so
//! rewrite, every leaf after it. The format below is not yet in FORMAT.md
//! and may change.
//!
//! - **Leaves are cut by content.** A rolling hash runs over the elements'
//!   fingerprints, `h = (h << 1) + f(e)`, so each element falls out of it 64
//!   elements later. A leaf ends after an element where the top bits of `h`
//!   are zero, once it holds a quarter of its target size, or at four times
//!   its target. The target is 32 elements, or 1 KB of packed fixed-width
//!   numbers, as for `Vector`.
//! - **Branches are cut by the same hash.** A leaf end whose hash has 5 more
//!   zero bits also ends a level-1 branch, 10 more a level-2 branch, and so
//!   on: an expected fanout of 32. A branch holds 2 to 128 children. So the
//!   shape needs no SHA-256, and identities stay lazy and cached.
//! - **Edits re-chunk locally.** Every edit (insert, remove, set, splice,
//!   concat, slice) is a join: the elements before a point, new elements,
//!   and the elements after another point, possibly of another sequence. At
//!   each level, chunking restarts at the start of the node where the change
//!   begins, and stops once a new cut falls where an old one was, past the
//!   rolling hash's window; everything after is reused. So equal contents
//!   give the same tree however they were made, and an edit rewrites only a
//!   few nodes per level.
//! - **Branches store their children's lengths,** so the element at an index
//!   is found by descending, and a stored branch is enough to navigate.
use crate::{Identify, Identity, Sink, mix64};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::{Arc, OnceLock};

/// Each level above the leaves needs this many more zero bits to cut.
const LEVEL_BITS: u32 = 5;
const MIN_FANOUT: usize = 2;
const MAX_FANOUT: usize = 128;
/// The rolling hash forgets an element after this many more.
const WINDOW: usize = 64;

#[derive(Clone, Copy)]
struct Params {
    /// Leading zero bits of the rolling hash that cut a leaf.
    hit_bits: u32,
    min: usize,
    max: usize,
}

fn params<T: Identify>() -> Params {
    let target = match T::PACKED {
        None => 32,
        Some((_, width)) => 1024 / width as usize,
    };
    Params {
        hit_bits: target.trailing_zeros(),
        min: target / 4,
        max: target * 4,
    }
}

/// FNV-1a as a sink, to fingerprint an element's encoding.
struct Fnv(u64);
impl Sink for Fnv {
    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// A fixed-width number's little-endian bytes, as one word.
struct Word(u64);
impl Sink for Word {
    fn update(&mut self, bytes: &[u8]) {
        self.0 = match *bytes {
            [a] => u64::from(a),
            [a, b] => u64::from(u16::from_le_bytes([a, b])),
            [a, b, c, d] => u64::from(u32::from_le_bytes([a, b, c, d])),
            _ => {
                let mut w = [0u8; 8];
                let n = bytes.len().min(8);
                w[..n].copy_from_slice(&bytes[..n]);
                u64::from_le_bytes(w)
            }
        };
    }
}

/// A 64-bit fingerprint of an element: of a fixed-width number's bits, or of
/// any other element's encoding. Odd, so a run of equal elements cannot
/// drive the rolling hash to 0.
fn fingerprint<T: Identify>(item: &T) -> u64 {
    if T::PACKED.is_some() {
        let mut w = Word(0);
        T::pack(std::slice::from_ref(item), &mut w);
        return mix64(w.0 ^ 0x9e37_79b9_7f4a_7c15) | 1;
    }
    let mut f = Fnv(0xcbf2_9ce4_8422_2325);
    item.identify(&mut f);
    mix64(f.0) | 1
}

/// How strong a cut the rolling hash allows after an element: -1 for none,
/// 0 for a leaf, `k` for a branch `k` levels up as well.
fn cut_level(h: u64, hit_bits: u32) -> i8 {
    let z = h.leading_zeros();
    if z < hit_bits {
        -1
    } else {
        ((z - hit_bits) / LEVEL_BITS) as i8
    }
}

enum Node<T> {
    Leaf {
        items: Vec<T>,
        /// The cut level after the last element.
        end: i8,
        identity: OnceLock<Identity>,
    },
    Branch {
        children: Vec<Arc<Node<T>>>,
        /// Cumulative lengths: `ends[i]` elements are in children `0..=i`.
        ends: Vec<usize>,
        end: i8,
        height: u8,
        identity: OnceLock<Identity>,
    },
}

impl<T> Node<T> {
    fn len(&self) -> usize {
        match self {
            Node::Leaf { items, .. } => items.len(),
            Node::Branch { ends, .. } => *ends.last().expect("a branch has children"),
        }
    }
    fn end(&self) -> i8 {
        match self {
            Node::Leaf { end, .. } | Node::Branch { end, .. } => *end,
        }
    }
    fn height(&self) -> u8 {
        match self {
            Node::Leaf { .. } => 0,
            Node::Branch { height, .. } => *height,
        }
    }
    fn items(&self) -> &[T] {
        match self {
            Node::Leaf { items, .. } => items,
            Node::Branch { .. } => unreachable!("a branch where a leaf belongs"),
        }
    }
    fn children(&self) -> &[Arc<Node<T>>] {
        match self {
            Node::Branch { children, .. } => children,
            Node::Leaf { .. } => unreachable!("a leaf where a branch belongs"),
        }
    }
    /// The child holding element `index`, and the index within it.
    fn child_for(&self, index: usize) -> (usize, usize) {
        let Node::Branch { ends, .. } = self else {
            unreachable!("a leaf where a branch belongs")
        };
        let i = ends.partition_point(|&e| e <= index);
        let before = if i == 0 { 0 } else { ends[i - 1] };
        (i, index - before)
    }
}

fn leaf<T>(items: Vec<T>, end: i8) -> Arc<Node<T>> {
    Arc::new(Node::Leaf {
        items,
        end,
        identity: OnceLock::new(),
    })
}

fn branch<T>(children: Vec<Arc<Node<T>>>) -> Arc<Node<T>> {
    let mut ends = Vec::with_capacity(children.len());
    let mut total = 0;
    for c in &children {
        total += c.len();
        ends.push(total);
    }
    let end = children.last().expect("a branch has children").end();
    let height = children[0].height() + 1;
    Arc::new(Node::Branch {
        children,
        ends,
        end,
        height,
        identity: OnceLock::new(),
    })
}

fn node_identity<T: Identify>(node: &Node<T>) -> Identity {
    match node {
        Node::Leaf {
            items, identity, ..
        } => *identity.get_or_init(|| {
            let mut h = Sha256::new();
            match T::PACKED {
                None => {
                    Digest::update(&mut h, b"merkle-champ/sequence/leaf/v0");
                    Digest::update(&mut h, (items.len() as u16).to_le_bytes());
                    for item in items {
                        item.identify(&mut h);
                    }
                }
                Some((tag, width)) => {
                    Digest::update(&mut h, b"merkle-champ/sequence/packed-leaf/v0");
                    Digest::update(&mut h, [tag, width]);
                    Digest::update(&mut h, (items.len() as u16).to_le_bytes());
                    T::pack(items, &mut h);
                }
            }
            h.finalize().into()
        }),
        Node::Branch {
            children,
            identity,
            ..
        } => *identity.get_or_init(|| {
            let mut h = Sha256::new();
            Digest::update(&mut h, b"merkle-champ/sequence/branch/v0");
            Digest::update(&mut h, (children.len() as u16).to_le_bytes());
            for child in children {
                Digest::update(&mut h, (child.len() as u64).to_le_bytes());
                Digest::update(&mut h, node_identity(child));
            }
            h.finalize().into()
        }),
    }
}

/// Whether a branch being built at `level` ends after a child with cut
/// level `end`, as its `count`th child.
fn group_cut(count: usize, end: i8, level: u8) -> bool {
    (count >= MIN_FANOUT && i32::from(end) >= i32::from(level)) || count == MAX_FANOUT
}

/// Cuts elements into leaves.
struct Chunker<T> {
    p: Params,
    h: u64,
    items: Vec<T>,
    out: Vec<Arc<Node<T>>>,
}

impl<T: Identify> Chunker<T> {
    fn new() -> Self {
        Chunker {
            p: params::<T>(),
            h: 0,
            items: Vec::new(),
            out: Vec::new(),
        }
    }
    /// Feeds an element to the rolling hash without keeping it: the elements
    /// before the first one re-chunked.
    fn warm(&mut self, item: &T) {
        self.h = (self.h << 1).wrapping_add(fingerprint(item));
    }
    /// Adds an element; returns whether a leaf ended after it.
    fn push(&mut self, item: T) -> bool {
        self.h = (self.h << 1).wrapping_add(fingerprint(&item));
        self.items.push(item);
        let level = cut_level(self.h, self.p.hit_bits);
        let n = self.items.len();
        if (n >= self.p.min && level >= 0) || n == self.p.max {
            self.out.push(leaf(std::mem::take(&mut self.items), level));
            true
        } else {
            false
        }
    }
    /// Ends the last leaf, if any elements are left.
    fn finish(&mut self) {
        if !self.items.is_empty() {
            let level = cut_level(self.h, self.p.hit_bits);
            self.out.push(leaf(std::mem::take(&mut self.items), level));
        }
    }
}

/// Groups nodes into branches at one level.
struct Grouper<T> {
    level: u8,
    group: Vec<Arc<Node<T>>>,
    out: Vec<Arc<Node<T>>>,
}

impl<T> Grouper<T> {
    fn new(level: u8) -> Self {
        Grouper {
            level,
            group: Vec::new(),
            out: Vec::new(),
        }
    }
    /// Adds a node; returns whether a branch ended after it.
    fn push(&mut self, node: Arc<Node<T>>) -> bool {
        let end = node.end();
        self.group.push(node);
        if group_cut(self.group.len(), end, self.level) {
            self.out.push(branch(std::mem::take(&mut self.group)));
            true
        } else {
            false
        }
    }
    fn finish(&mut self) {
        if !self.group.is_empty() {
            self.out.push(branch(std::mem::take(&mut self.group)));
        }
    }
}

/// Groups a level's nodes into branches, level after level, until one root
/// remains.
fn build_up<T>(mut nodes: Vec<Arc<Node<T>>>) -> Option<Arc<Node<T>>> {
    let mut level = 1;
    while nodes.len() > 1 {
        let mut g = Grouper::new(level);
        for n in nodes {
            g.push(n);
        }
        g.finish();
        nodes = g.out;
        level += 1;
    }
    nodes.pop()
}

/// The path to the leaf holding an element: by level, the branch at that
/// level on the path and the index of the child taken (`frames[l - 1]` for
/// level `l`); then the leaf and the index of its first element.
struct Path<T> {
    frames: Vec<(Arc<Node<T>>, usize)>,
    leaf: Arc<Node<T>>,
    start: usize,
}

fn path_to<T>(root: &Arc<Node<T>>, mut index: usize) -> Path<T> {
    let mut frames = vec![None; root.height() as usize];
    let mut node = root.clone();
    let mut start = 0;
    while node.height() > 0 {
        let (i, rest) = node.child_for(index);
        start += index - rest;
        index = rest;
        let child = node.children()[i].clone();
        let level = node.height() as usize;
        frames[level - 1] = Some((node, i));
        node = child;
    }
    Path {
        frames: frames.into_iter().map(|f| f.expect("a frame per level")).collect(),
        leaf: node,
        start,
    }
}

/// A position among the nodes of one level of a tree, which can move right
/// through that level and up to the parent. `frames` run from a virtual
/// parent of the root down; the current node is the last frame's child.
struct Cursor<T> {
    frames: Vec<(Arc<Node<T>>, usize)>,
}

impl<T> Cursor<T> {
    /// At the leaf holding element `index`; also returns the index within it.
    fn at(root: &Arc<Node<T>>, mut index: usize) -> (Self, usize) {
        let top = branch(vec![root.clone()]);
        let mut frames = vec![(top, 0)];
        let mut node = root.clone();
        while node.height() > 0 {
            let (i, rest) = node.child_for(index);
            index = rest;
            let child = node.children()[i].clone();
            frames.push((node, i));
            node = child;
        }
        (Cursor { frames }, index)
    }
    fn current(&self) -> &Arc<Node<T>> {
        let (node, i) = self.frames.last().expect("a frame");
        &node.children()[*i]
    }
    /// Whether the current node ends its parent.
    fn last_child(&self) -> bool {
        let (node, i) = self.frames.last().expect("a frame");
        i + 1 == node.children().len()
    }
    /// Moves to the next node at this level; false at the end.
    fn advance(&mut self) -> bool {
        self.advance_at(self.frames.len() - 1)
    }
    fn advance_at(&mut self, depth: usize) -> bool {
        self.frames[depth].1 += 1;
        if self.frames[depth].1 < self.frames[depth].0.children().len() {
            return true;
        }
        if depth == 0 || !self.advance_at(depth - 1) {
            return false;
        }
        let (parent, i) = &self.frames[depth - 1];
        let next = parent.children()[*i].clone();
        self.frames[depth] = (next, 0);
        true
    }
    /// The node after the current node's parent, one level up, if any.
    fn after_parent(mut self) -> Option<Self> {
        self.frames.pop();
        if self.frames.len() < 2 {
            // The parent is the root: nothing follows it.
            return None;
        }
        self.advance().then_some(self)
    }
}

/// A persistent, content-defined sequence. See the module documentation.
pub struct Sequence<T> {
    root: Option<Arc<Node<T>>>,
}

impl<T> Clone for Sequence<T> {
    fn clone(&self) -> Self {
        Sequence {
            root: self.root.clone(),
        }
    }
}

impl<T> Default for Sequence<T> {
    fn default() -> Self {
        Sequence { root: None }
    }
}

impl<T: Clone + Identify> Sequence<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |r| r.len())
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// The height of the tree: 0 for one leaf.
    pub fn height(&self) -> usize {
        self.root.as_ref().map_or(0, |r| r.height() as usize)
    }

    pub fn get(&self, mut index: usize) -> Option<&T> {
        let mut node = self.root.as_ref()?;
        if index >= node.len() {
            return None;
        }
        while node.height() > 0 {
            let (i, rest) = node.child_for(index);
            node = &node.children()[i];
            index = rest;
        }
        node.items().get(index)
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.iter_from(0)
    }

    /// Iterates the elements from `index` on.
    pub fn iter_from(&self, mut index: usize) -> Iter<'_, T> {
        let mut stack = Vec::new();
        let mut leaf: &[T] = &[];
        if let Some(root) = self.root.as_ref().filter(|r| index < r.len()) {
            let mut node = &**root;
            while node.height() > 0 {
                let (i, rest) = node.child_for(index);
                if i + 1 < node.children().len() {
                    stack.push((node, i + 1));
                }
                node = &node.children()[i];
                index = rest;
            }
            leaf = &node.items()[index..];
        }
        Iter {
            stack,
            leaf: leaf.iter(),
        }
    }

    /// The elements `prefix[..p]`, then `middle`, then `suffix[q..]`, as a
    /// canonical sequence, re-chunking only around the two seams.
    pub fn join(prefix: &Self, p: usize, middle: impl IntoIterator<Item = T>, suffix: &Self, q: usize) -> Self {
        assert!(p <= prefix.len() && q <= suffix.len(), "join out of range");
        // Leaves: restart at the leaf holding the last kept prefix element,
        // after warming the rolling hash with the elements before it.
        let mut chunker = Chunker::new();
        let mut frames = Vec::new();
        if p > 0 {
            let root = prefix.root.as_ref().expect("a non-empty prefix");
            let path = path_to(root, p - 1);
            let warm_from = path.start.saturating_sub(WINDOW);
            for item in prefix.iter_from(warm_from).take(path.start - warm_from) {
                chunker.warm(item);
            }
            for item in &path.leaf.items()[..p - path.start] {
                chunker.push(item.clone());
            }
            frames = path.frames;
        }
        for item in middle {
            chunker.push(item);
        }
        // The suffix, until a cut falls where an old leaf ended, past the
        // window; the leaves after it are reused.
        let mut cursor = None;
        let mut resynced = false;
        if let Some(root) = suffix.root.as_ref().filter(|_| q < suffix.len()) {
            let (mut cur, mut offset) = Cursor::at(root, q);
            let mut k = 0;
            'leaves: loop {
                let items = cur.current().items();
                for (j, item) in items[offset..].iter().enumerate() {
                    let cut = chunker.push(item.clone());
                    if cut && offset + j + 1 == items.len() && k + 1 >= WINDOW {
                        resynced = true;
                        cursor = cur.advance().then_some(cur);
                        break 'leaves;
                    }
                    k += 1;
                }
                offset = 0;
                if !cur.advance() {
                    break;
                }
            }
        }
        if !resynced {
            chunker.finish();
        }
        let mut nodes = chunker.out;
        // Branches, level by level: restart at the first child of the old
        // branch where the change begins, and stop at an old branch end.
        let mut level: u8 = 1;
        loop {
            let at = level as usize - 1;
            let nothing_left = frames.iter().skip(at).all(|(_, i)| *i == 0);
            if nothing_left && cursor.is_none() {
                if nodes.len() <= 1 {
                    return Sequence { root: nodes.pop() };
                }
                return Sequence {
                    root: build_up_from(nodes, level),
                };
            }
            let mut g = Grouper::new(level);
            if let Some((node, i)) = frames.get(at) {
                for child in &node.children()[..*i] {
                    g.push(child.clone());
                }
            }
            for n in nodes {
                g.push(n);
            }
            let mut next = None;
            let mut resynced = false;
            if let Some(mut cur) = cursor.take() {
                loop {
                    let last = cur.last_child();
                    let cut = g.push(cur.current().clone());
                    if cut && last {
                        resynced = true;
                        next = cur.after_parent();
                        break;
                    }
                    if !cur.advance() {
                        break;
                    }
                }
            }
            if !resynced {
                g.finish();
            }
            nodes = g.out;
            cursor = next;
            level += 1;
        }
    }

    /// A new sequence with `items` in place of the elements in `range`.
    pub fn splice(&self, range: std::ops::Range<usize>, items: impl IntoIterator<Item = T>) -> Self {
        Self::join(self, range.start, items, self, range.end)
    }

    pub fn insert(&self, index: usize, item: T) -> Self {
        self.splice(index..index, [item])
    }

    pub fn remove(&self, index: usize) -> Self {
        self.splice(index..index + 1, [])
    }

    /// A new sequence with element `index` replaced. When the new value
    /// moves no cut, which the rolling hash's window decides, only the leaf
    /// and its path are copied; otherwise it is a splice.
    pub fn update(&self, index: usize, item: T) -> Self {
        assert!(index < self.len(), "index {index} out of range");
        let root = self.root.as_ref().expect("a non-empty sequence");
        let path = path_to(root, index);
        let items = path.leaf.items();
        let off = index - path.start;
        // The window after the change must end inside the leaf, before its
        // last element, whose cut decision then cannot change.
        if off + WINDOW < items.len() {
            let p = params::<T>();
            let mut h = 0u64;
            let warm_from = index.saturating_sub(WINDOW);
            for x in self.iter_from(warm_from).take(index - warm_from) {
                h = (h << 1).wrapping_add(fingerprint(x));
            }
            let mut moved = false;
            for (j, x) in std::iter::once(&item).chain(&items[off + 1..off + WINDOW]).enumerate() {
                h = (h << 1).wrapping_add(fingerprint(x));
                let count = off + j + 1;
                if (count >= p.min && cut_level(h, p.hit_bits) >= 0) || count == p.max {
                    moved = true;
                    break;
                }
            }
            if !moved {
                let mut new_items = items.to_vec();
                new_items[off] = item;
                let mut node = leaf(new_items, path.leaf.end());
                for (parent, i) in &path.frames {
                    let mut children = parent.children().to_vec();
                    children[*i] = node;
                    node = branch(children);
                }
                return Sequence { root: Some(node) };
            }
        }
        self.splice(index..index + 1, [item])
    }

    pub fn pushed(&self, item: T) -> Self {
        let n = self.len();
        self.splice(n..n, [item])
    }

    pub fn concat(&self, other: &Self) -> Self {
        Self::join(self, self.len(), [], other, 0)
    }

    pub fn slice(&self, range: std::ops::Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.len(), "slice out of range");
        let empty = Self::new();
        let tail = Self::join(&empty, 0, [], self, range.start);
        Self::join(&tail, range.end - range.start, [], &empty, 0)
    }

    /// The sequence's SHA-256 identity. Node identities are cached.
    pub fn identity(&self) -> Identity {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"merkle-champ/sequence/v0");
        Digest::update(&mut h, (self.len() as u64).to_le_bytes());
        if let Some(root) = &self.root {
            Digest::update(&mut h, node_identity(root));
        }
        h.finalize().into()
    }

    /// The nodes of the tree, for measuring how much two versions share.
    pub fn node_ids(&self) -> Vec<Identity> {
        fn walk<T: Identify>(node: &Node<T>, out: &mut Vec<Identity>) {
            out.push(node_identity(node));
            if let Node::Branch { children, .. } = node {
                for c in children {
                    walk(c, out);
                }
            }
        }
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            walk(root, &mut out);
        }
        out
    }

    /// Checks the structure, and that the tree is the one building from the
    /// elements gives. For tests.
    pub fn check_invariants(&self) -> Result<(), String> {
        fn check<T>(node: &Node<T>, p: Params) -> Result<(), String> {
            match node {
                Node::Leaf { items, .. } => {
                    if items.is_empty() || items.len() > p.max {
                        return Err(format!("a leaf of {}", items.len()));
                    }
                }
                Node::Branch {
                    children,
                    ends,
                    height,
                    ..
                } => {
                    if children.is_empty() || children.len() > MAX_FANOUT {
                        return Err(format!("a branch of {}", children.len()));
                    }
                    let mut total = 0;
                    for (c, &e) in children.iter().zip(ends) {
                        if c.height() + 1 != *height {
                            return Err("children of mixed heights".into());
                        }
                        total += c.len();
                        if total != e {
                            return Err("wrong lengths".into());
                        }
                        check(c, p)?;
                    }
                }
            }
            Ok(())
        }
        if let Some(root) = &self.root {
            check(root, params::<T>())?;
        }
        let rebuilt: Sequence<T> = self.iter().cloned().collect();
        if rebuilt.identity() != self.identity() {
            return Err("not the canonical tree for its elements".into());
        }
        Ok(())
    }
}

/// Groups nodes from `level` up to a root.
fn build_up_from<T>(mut nodes: Vec<Arc<Node<T>>>, mut level: u8) -> Option<Arc<Node<T>>> {
    while nodes.len() > 1 {
        let mut g = Grouper::new(level);
        for n in nodes {
            g.push(n);
        }
        g.finish();
        nodes = g.out;
        level += 1;
    }
    nodes.pop()
}

impl<T: Clone + Identify> FromIterator<T> for Sequence<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut chunker = Chunker::new();
        for item in iter {
            chunker.push(item);
        }
        chunker.finish();
        Sequence {
            root: build_up(chunker.out),
        }
    }
}

impl<T: Clone + Identify + PartialEq> PartialEq for Sequence<T> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<T: Clone + Identify + fmt::Debug> fmt::Debug for Sequence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterates a sequence's elements in order, a leaf at a time.
pub struct Iter<'a, T> {
    stack: Vec<(&'a Node<T>, usize)>,
    leaf: std::slice::Iter<'a, T>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(item) = self.leaf.next() {
                return Some(item);
            }
            let (node, i) = self.stack.pop()?;
            match node {
                Node::Leaf { items, .. } => self.leaf = items.iter(),
                Node::Branch { children, .. } => {
                    if i + 1 < children.len() {
                        self.stack.push((node, i + 1));
                    }
                    self.stack.push((&children[i], 0));
                }
            }
        }
    }
}
