//! A persistent vector for content-addressed systems, the companion of the
//! map: a 32-way vector trie (Bagwell's, as in Clojure) with the same two
//! properties this crate adds to its CHAMP.
//!
//! 1. **Canonical shape.** A vector's structure depends only on its length
//!    and element type: the last elements, up to a leaf's worth, are in a
//!    tail, the rest in full leaves under the fewest levels of branches of 32
//!    that hold them. Pushes, pops, updates and rebuilding all give the same
//!    tree. A leaf holds 32 elements, or, for fixed-width numbers, 1 KB of
//!    them packed: 1,024 `u8`, 128 `u64` or `f64`.
//! 2. **Lazily cached identities.** `identity()` is a SHA-256 identity of the
//!    contents. Each node computes its identity on first request and caches
//!    it; versions share unchanged nodes, so after a write only the changed
//!    path is rehashed.
//!
//! ```
//! use merkle_champ::Vector;
//!
//! let v1: Vector<u64> = (0..100).collect();
//! let v2 = v1.update(5, 50);              // v1 is unchanged
//! assert_eq!(v1.get(5), Some(&5));
//! assert_eq!(v2.get(5), Some(&50));
//!
//! // History does not matter: equal contents, equal identity.
//! let mut v3: Vector<u64> = (0..150).collect();
//! for _ in 0..50 { v3.pop(); }
//! assert_eq!(v1.identity(), v3.identity());
//! ```
//!
//! `get`, `set` and `update` take O(log₃₂ n) steps, effectively constant;
//! `push` and `pop` are amortised O(1). Cloning is O(1), and a write copies
//! only the nodes on its path, in place when a node is not shared.
//! `concat` and `slice` copy, O(n). [`Builder`] fills a new vector a leaf at a
//! time; collecting an iterator uses it.
//!
//! The identity format is specified in `FORMAT.md`, section 10. Elements are
//! encoded with [`Identify`], so a value has the same encoding in a map and in
//! a vector, and the same requirements apply: the encoding must be injective
//! and self-delimiting, and nothing identity-relevant may change while stored.

use crate::{Identify, Identity, Sink, write_tagged};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::{Arc, OnceLock};

/// Branches hold up to 32 children.
const BITS: u32 = 5;
const WIDTH: usize = 1 << BITS;
const MASK: usize = WIDTH - 1;
/// A packed leaf holds this many bytes of elements.
const LEAF_BYTES: usize = 1024;

/// The number of elements in a full leaf of `T`, as a power of two: 32, or
/// 1 KB of packed fixed-width numbers.
fn leaf_bits<T: Identify>() -> u32 {
    match T::PACKED {
        None => BITS,
        Some((_, width)) => (LEAF_BYTES / width as usize).trailing_zeros(),
    }
}

/// The level below a branch at `level`: the leaves (0) under the lowest
/// branches, whose level is `lb`.
fn below(level: u32, lb: u32) -> u32 {
    if level == lb { 0 } else { level - BITS }
}

enum Node<T> {
    Branch {
        children: Vec<Arc<Node<T>>>,
        identity: OnceLock<Identity>,
    },
    Leaf {
        items: Vec<T>,
        identity: OnceLock<Identity>,
    },
}

impl<T: Clone> Clone for Node<T> {
    fn clone(&self) -> Self {
        match self {
            Node::Branch { children, identity } => Node::Branch {
                children: children.clone(),
                identity: identity.clone(),
            },
            Node::Leaf { items, identity } => Node::Leaf {
                items: items.clone(),
                identity: identity.clone(),
            },
        }
    }
}

fn leaf<T>(items: Vec<T>) -> Arc<Node<T>> {
    Arc::new(Node::Leaf {
        items,
        identity: OnceLock::new(),
    })
}

fn branch<T>(children: Vec<Arc<Node<T>>>) -> Arc<Node<T>> {
    Arc::new(Node::Branch {
        children,
        identity: OnceLock::new(),
    })
}

impl<T> Node<T> {
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
}

/// A leaf's elements, copied first if the leaf is shared. Its cached identity
/// is cleared, since the caller is about to change it.
fn items_mut<T: Clone>(node: &mut Arc<Node<T>>) -> &mut Vec<T> {
    match Arc::make_mut(node) {
        Node::Leaf { items, identity } => {
            *identity = OnceLock::new();
            items
        }
        Node::Branch { .. } => unreachable!("a branch where a leaf belongs"),
    }
}

/// A branch's children, copied first if the branch is shared, with its cached
/// identity cleared.
fn children_mut<T: Clone>(node: &mut Arc<Node<T>>) -> &mut Vec<Arc<Node<T>>> {
    match Arc::make_mut(node) {
        Node::Branch { children, identity } => {
            *identity = OnceLock::new();
            children
        }
        Node::Leaf { .. } => unreachable!("a leaf where a branch belongs"),
    }
}

fn node_identity<T: Identify>(node: &Node<T>) -> Identity {
    match node {
        Node::Leaf { items, identity } => *identity.get_or_init(|| {
            let mut h = Sha256::new();
            match T::PACKED {
                None => {
                    Digest::update(&mut h, b"merkle-champ/vector/leaf/v1");
                    Digest::update(&mut h, [items.len() as u8]);
                    for item in items {
                        item.identify(&mut h);
                    }
                }
                Some((tag, width)) => {
                    Digest::update(&mut h, b"merkle-champ/vector/packed-leaf/v1");
                    Digest::update(&mut h, [tag, width]);
                    Digest::update(&mut h, (items.len() as u16).to_le_bytes());
                    T::pack(items, &mut h);
                }
            }
            h.finalize().into()
        }),
        Node::Branch { children, identity } => *identity.get_or_init(|| {
            let mut h = Sha256::new();
            Digest::update(&mut h, b"merkle-champ/vector/branch/v1");
            Digest::update(&mut h, [children.len() as u8]);
            for child in children {
                Digest::update(&mut h, node_identity(child));
            }
            h.finalize().into()
        }),
    }
}

/// The index of the first element in the tail, for leaves of `1 << lb`.
fn tailoff(len: usize, lb: u32) -> usize {
    if len == 0 { 0 } else { ((len - 1) >> lb) << lb }
}

/// A path of single-child branches from `level` down to `node`.
fn new_path<T>(level: u32, lb: u32, node: Arc<Node<T>>) -> Arc<Node<T>> {
    if level == 0 {
        node
    } else {
        branch(vec![new_path(below(level, lb), lb, node)])
    }
}

/// Adds a full leaf as the last leaf under `node`, a branch at `level`.
/// `index` is the index of the leaf's last element.
fn push_tail<T: Clone>(
    level: u32,
    lb: u32,
    node: &mut Arc<Node<T>>,
    full: Arc<Node<T>>,
    index: usize,
) {
    let children = children_mut(node);
    let sub = (index >> level) & MASK;
    if level == lb {
        children.push(full);
    } else if sub < children.len() {
        push_tail(level - BITS, lb, &mut children[sub], full, index);
    } else {
        children.push(new_path(level - BITS, lb, full));
    }
}

/// Removes the last leaf under `node`, a branch at `level`; `index` is an
/// index in that leaf. Returns whether `node` is left empty.
fn pop_tail<T: Clone>(level: u32, lb: u32, node: &mut Arc<Node<T>>, index: usize) -> bool {
    let children = children_mut(node);
    let sub = (index >> level) & MASK;
    if level > lb {
        if pop_tail(level - BITS, lb, &mut children[sub], index) {
            children.pop();
        }
    } else {
        children.pop();
    }
    children.is_empty()
}

fn set_in<T: Clone>(level: u32, lb: u32, node: &mut Arc<Node<T>>, index: usize, value: T) -> T {
    if level == 0 {
        std::mem::replace(&mut items_mut(node)[index & ((1 << lb) - 1)], value)
    } else {
        let sub = (index >> level) & MASK;
        set_in(below(level, lb), lb, &mut children_mut(node)[sub], index, value)
    }
}

/// A persistent vector. See the crate documentation.
pub struct Vector<T> {
    len: usize,
    /// The level of the root branch: `BITS` times the number of branch levels.
    shift: u32,
    /// The first `tailoff(len)` elements, or `None` when that is zero.
    root: Option<Arc<Node<T>>>,
    /// A leaf with the last elements: 1 to a full leaf of them, none when
    /// empty.
    tail: Arc<Node<T>>,
}

impl<T> Clone for Vector<T> {
    fn clone(&self) -> Self {
        Vector {
            len: self.len,
            shift: self.shift,
            root: self.root.clone(),
            tail: self.tail.clone(),
        }
    }
}

impl<T: Identify> Default for Vector<T> {
    fn default() -> Self {
        Vector {
            len: 0,
            shift: leaf_bits::<T>(),
            root: None,
            tail: leaf(Vec::new()),
        }
    }
}

impl<T> Vector<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T: Identify> Vector<T> {
    /// The empty vector.
    pub fn new() -> Self {
        Self::default()
    }

    /// The leaf holding element `index`, which must be in range.
    fn leaf_for(&self, index: usize) -> &[T] {
        let lb = leaf_bits::<T>();
        if index >= tailoff(self.len, lb) {
            return self.tail.items();
        }
        let mut node = self.root.as_ref().expect("a tree below the tail");
        let mut level = self.shift;
        while level > 0 {
            node = &node.children()[(index >> level) & MASK];
            level = below(level, lb);
        }
        node.items()
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        let mask = (1 << leaf_bits::<T>()) - 1;
        (index < self.len).then(|| &self.leaf_for(index)[index & mask])
    }

    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    pub fn last(&self) -> Option<&T> {
        self.len.checked_sub(1).and_then(|i| self.get(i))
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            vector: self,
            index: 0,
            end: self.len,
            leaf: &[],
            mask: (1 << leaf_bits::<T>()) - 1,
        }
    }

    /// Whether two vectors share their whole structure, so that they are
    /// equal without comparing elements.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        self.len == other.len
            && Arc::ptr_eq(&self.tail, &other.tail)
            && match (&self.root, &other.root) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }
}

impl<T: Clone + Identify> Vector<T> {
    /// Appends an element.
    pub fn push(&mut self, value: T) {
        let lb = leaf_bits::<T>();
        let in_tail = self.len - tailoff(self.len, lb);
        if in_tail < 1 << lb {
            items_mut(&mut self.tail).push(value);
            self.len += 1;
            return;
        }
        // The tail is full: it becomes the tree's last leaf.
        let full = std::mem::replace(&mut self.tail, leaf(vec![value]));
        match &mut self.root {
            None => {
                self.root = Some(branch(vec![full]));
                self.shift = lb;
            }
            Some(root) => {
                // The root's children cover 32 << shift elements.
                if (self.len >> BITS) > (1 << self.shift) {
                    let old = root.clone();
                    *root = branch(vec![old, new_path(self.shift, lb, full)]);
                    self.shift += BITS;
                } else {
                    push_tail(self.shift, lb, root, full, self.len - 1);
                }
            }
        }
        self.len += 1;
    }

    /// Removes and returns the last element.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let lb = leaf_bits::<T>();
        let in_tail = self.len - tailoff(self.len, lb);
        if in_tail > 1 || self.len == 1 {
            let value = items_mut(&mut self.tail).pop();
            self.len -= 1;
            return value;
        }
        // The tail's only element goes, and the tree's last leaf becomes the
        // tail.
        let value = items_mut(&mut self.tail).pop();
        let index = self.len - 2;
        let new_tail = {
            let mut node = self.root.as_ref().expect("a tree below the tail");
            let mut level = self.shift;
            while level > 0 {
                node = &node.children()[(index >> level) & MASK];
                level = below(level, lb);
            }
            node.clone()
        };
        let root = self.root.as_mut().expect("a tree below the tail");
        if pop_tail(self.shift, lb, root, index) {
            self.root = None;
            self.shift = lb;
        } else if self.shift > lb && root.children().len() == 1 {
            let only = root.children()[0].clone();
            *root = only;
            self.shift -= BITS;
        }
        self.tail = new_tail;
        self.len -= 1;
        value
    }

    /// Replaces element `index` and returns the old value, or gives `value`
    /// back if `index` is out of range.
    pub fn set(&mut self, index: usize, value: T) -> Result<T, T> {
        if index >= self.len {
            return Err(value);
        }
        let lb = leaf_bits::<T>();
        let off = tailoff(self.len, lb);
        if index >= off {
            return Ok(std::mem::replace(
                &mut items_mut(&mut self.tail)[index - off],
                value,
            ));
        }
        let root = self.root.as_mut().expect("a tree below the tail");
        Ok(set_in(self.shift, lb, root, index, value))
    }

    /// A new vector with element `index` replaced. Panics if `index` is out
    /// of range.
    pub fn update(&self, index: usize, value: T) -> Self {
        let mut v = self.clone();
        assert!(v.set(index, value).is_ok(), "index {index} out of range");
        v
    }

    /// A new vector with `value` appended.
    pub fn pushed(&self, value: T) -> Self {
        let mut v = self.clone();
        v.push(value);
        v
    }

    /// This vector followed by `other`. Copies `other`'s elements: O(n).
    pub fn concat(&self, other: &Self) -> Self {
        let mut v = self.clone();
        v.extend(other.iter().cloned());
        v
    }

    /// Elements `start` to `end - 1` as a new vector. Copies: O(n).
    pub fn slice(&self, range: std::ops::Range<usize>) -> Self {
        assert!(
            range.start <= range.end && range.end <= self.len,
            "slice out of range"
        );
        let mut iter = self.iter();
        iter.index = range.start;
        iter.end = range.end;
        iter.cloned().collect()
    }

    /// Checks the canonical shape (FORMAT.md, section 10.1). For tests.
    pub fn check_invariants(&self) -> Result<(), String> {
        let lb = leaf_bits::<T>();
        let off = tailoff(self.len, lb);
        let in_tail = self.tail.items().len();
        if in_tail != self.len - off {
            return Err(format!("tail holds {in_tail}, expected {}", self.len - off));
        }
        if self.len > 0 && !(1..=1 << lb).contains(&in_tail) {
            return Err(format!("tail holds {in_tail}"));
        }
        match &self.root {
            None if off == 0 => Ok(()),
            None => Err(format!("no tree for {off} elements")),
            Some(_) if off == 0 => Err("a tree with nothing in it".into()),
            Some(root) => {
                // The fewest branch levels, at least one, that hold `off`.
                let mut h = 1;
                while (1usize << lb) * WIDTH.pow(h) < off {
                    h += 1;
                }
                if self.shift != lb + BITS * (h - 1) {
                    return Err(format!("shift {} for {off} elements", self.shift));
                }
                let counted = check_node(root, self.shift, lb, true)?;
                if counted != off {
                    return Err(format!("tree holds {counted}, expected {off}"));
                }
                Ok(())
            }
        }
    }
}

/// Counts the elements under a node, checking that leaves are full and that
/// branches off the rightmost path are full.
fn check_node<T>(node: &Node<T>, level: u32, lb: u32, rightmost: bool) -> Result<usize, String> {
    if level == 0 {
        return match node {
            Node::Leaf { items, .. } if items.len() == 1 << lb => Ok(1 << lb),
            Node::Leaf { items, .. } => Err(format!("a leaf of {}", items.len())),
            Node::Branch { .. } => Err("a branch at leaf level".into()),
        };
    }
    let Node::Branch { children, .. } = node else {
        return Err(format!("a leaf at level {level}"));
    };
    if children.is_empty() || children.len() > WIDTH {
        return Err(format!("a branch of {}", children.len()));
    }
    if !rightmost && children.len() != WIDTH {
        return Err(format!("a branch of {} off the right edge", children.len()));
    }
    let mut total = 0;
    for (i, child) in children.iter().enumerate() {
        total += check_node(child, below(level, lb), lb, rightmost && i + 1 == children.len())?;
    }
    Ok(total)
}

impl<T: Identify> Vector<T> {
    /// The vector's SHA-256 identity (FORMAT.md, section 10). Node identities are cached,
    /// so after a write only the changed path is rehashed.
    pub fn identity(&self) -> Identity {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"merkle-champ/vector/v1");
        Digest::update(&mut h, (self.len as u64).to_le_bytes());
        if let Some(root) = &self.root {
            Digest::update(&mut h, node_identity(root));
        }
        if self.len > 0 {
            Digest::update(&mut h, node_identity(&self.tail));
        }
        h.finalize().into()
    }
}

impl<T: Identify> Identify for Vector<T> {
    /// Lets vectors nest in maps and vectors: a nested vector contributes its
    /// own (cached) identity.
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        write_tagged(sink, b'v', &self.identity());
    }
}

/// Builds a vector from elements in order, filling leaves in place and the
/// branches bottom-up once, which is faster than pushing one at a time. The
/// result has the same canonical shape as any other way of building it.
///
/// ```
/// use merkle_champ::vector::{Builder, Vector};
///
/// let mut b = Builder::new();
/// for i in 0..1_000u64 { b.push(i); }
/// let v: Vector<u64> = b.build();
/// assert_eq!(v, (0..1_000).collect());
/// ```
pub struct Builder<T> {
    leaves: Vec<Arc<Node<T>>>,
    chunk: Vec<T>,
}

impl<T: Identify> Default for Builder<T> {
    fn default() -> Self {
        Builder {
            leaves: Vec::new(),
            chunk: Vec::with_capacity(1 << leaf_bits::<T>()),
        }
    }
}

impl<T: Identify> Builder<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an element. A full chunk becomes a leaf only once another
    /// element follows it, since the last chunk is the vector's tail.
    pub fn push(&mut self, value: T) {
        let width = 1 << leaf_bits::<T>();
        if self.chunk.len() == width {
            let full = std::mem::replace(&mut self.chunk, Vec::with_capacity(width));
            self.leaves.push(leaf(full));
        }
        self.chunk.push(value);
    }

    pub fn len(&self) -> usize {
        (self.leaves.len() << leaf_bits::<T>()) + self.chunk.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty() && self.chunk.is_empty()
    }

    pub fn build(self) -> Vector<T> {
        let len = self.len();
        let lb = leaf_bits::<T>();
        let tail = leaf(self.chunk);
        if self.leaves.is_empty() {
            return Vector {
                len,
                shift: lb,
                root: None,
                tail,
            };
        }
        // Group leaves into branches of 32, then those, until one remains:
        // the fewest levels that hold them, and at least one.
        let mut level = self.leaves;
        let mut shift = 0;
        loop {
            let mut next = Vec::with_capacity(level.len().div_ceil(WIDTH));
            let mut nodes = level.into_iter().peekable();
            while nodes.peek().is_some() {
                next.push(branch(nodes.by_ref().take(WIDTH).collect()));
            }
            shift = if shift == 0 { lb } else { shift + BITS };
            if next.len() == 1 {
                return Vector {
                    len,
                    shift,
                    root: next.pop(),
                    tail,
                };
            }
            level = next;
        }
    }
}

impl<T: Identify> FromIterator<T> for Vector<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut b = Builder::new();
        for value in iter {
            b.push(value);
        }
        b.build()
    }
}

impl<T: Clone + Identify> Extend<T> for Vector<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for value in iter {
            self.push(value);
        }
    }
}

impl<T: PartialEq + Identify> PartialEq for Vector<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr_eq(other) || (self.len == other.len && self.iter().eq(other.iter()))
    }
}

impl<T: Eq + Identify> Eq for Vector<T> {}

impl<T: fmt::Debug + Identify> fmt::Debug for Vector<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T: Identify> IntoIterator for &'a Vector<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;
    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

/// Iterates a vector's elements in order, a leaf at a time.
pub struct Iter<'a, T> {
    vector: &'a Vector<T>,
    index: usize,
    end: usize,
    leaf: &'a [T],
    /// One less than the number of elements in a full leaf.
    mask: usize,
}

impl<'a, T: Identify> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        if self.index >= self.end {
            return None;
        }
        if self.leaf.is_empty() || self.index & self.mask == 0 {
            let offset = self.index & self.mask;
            self.leaf = &self.vector.leaf_for(self.index)[offset..];
        }
        let (first, rest) = self.leaf.split_first()?;
        self.leaf = rest;
        self.index += 1;
        Some(first)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.end - self.index;
        (n, Some(n))
    }
}

impl<T: Identify> ExactSizeIterator for Iter<'_, T> {}
