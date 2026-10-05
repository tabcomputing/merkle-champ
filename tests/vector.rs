//! The vector (`merkle_champ::vector`): against a `Vec` model through random
//! and boundary-crossing operations, with the canonical shape checked along
//! the way, and identities against an independent computation of FORMAT.md
//! section 10, which chunks a plain slice rather than walking the tree.
use merkle_champ::{Identify, Vector};
use sha2::{Digest, Sha256};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Elements for the tests: fixed-width numbers, whose leaves are packed 1 KB
/// at a time, and strings, 32 to a leaf.
trait Elem: Clone + PartialEq + std::fmt::Debug + Identify {
    /// Elements in a full leaf.
    const LEAF: usize;
    fn from(x: u64) -> Self;
}
impl Elem for u8 {
    const LEAF: usize = 1_024;
    fn from(x: u64) -> Self {
        x as u8
    }
}
impl Elem for u64 {
    const LEAF: usize = 128;
    fn from(x: u64) -> Self {
        x
    }
}
impl Elem for String {
    const LEAF: usize = 32;
    fn from(x: u64) -> Self {
        x.to_string()
    }
}

fn agrees<T: Elem>(v: &Vector<T>, model: &[T]) {
    assert_eq!(v.len(), model.len());
    assert!(v.iter().eq(model.iter()), "elements differ");
    v.check_invariants().unwrap();
}

/// Whether to check at length `i`: around the lengths where the tree gains
/// its root, a second branch level and a third, and every so often.
fn checkpoint(i: usize, leaf: usize, n: usize) -> bool {
    let near = [leaf, 2 * leaf, 32 * leaf, 33 * leaf, 1_025 * leaf]
        .iter()
        .any(|&b| i + 2 >= b && i <= b + 2);
    near || i.is_multiple_of(n / 40)
}

/// Pushes to `n` elements and pops back to none, comparing with a `Vec`.
fn grows_and_shrinks<T: Elem>(n: usize) {
    let mut v = Vector::new();
    let mut model = Vec::new();
    for i in 0..n {
        v.push(T::from(i as u64));
        model.push(T::from(i as u64));
        if checkpoint(i + 1, T::LEAF, n) {
            agrees(&v, &model);
        }
    }
    for i in (0..n).rev() {
        assert_eq!(v.pop(), model.pop());
        if checkpoint(i, T::LEAF, n) {
            agrees(&v, &model);
        }
    }
    assert_eq!(v.pop(), None);
    agrees(&v, &model);
}

#[test]
fn grows_and_shrinks_through_every_level() {
    // Past the first leaf, a second branch level (33 leaves) and a third
    // (1,025 leaves), for each kind of leaf; for bytes, only the second, since
    // the third needs a million elements.
    grows_and_shrinks::<String>(33_000);
    grows_and_shrinks::<u64>(131_400);
    grows_and_shrinks::<u8>(34_000);
}

fn random_operations<T: Elem>(seed: u64) {
    let mut rng = Rng(seed);
    let mut v: Vector<T> = Vector::new();
    let mut model: Vec<T> = Vec::new();
    for step in 0..60_000 {
        match rng.below(10) {
            0..=4 => {
                let x = T::from(rng.next());
                v.push(x.clone());
                model.push(x);
            }
            5 | 6 => assert_eq!(v.pop(), model.pop()),
            7 | 8 if !model.is_empty() => {
                let i = rng.below(model.len());
                let x = T::from(rng.next());
                assert_eq!(v.set(i, x.clone()), Ok(model[i].clone()));
                model[i] = x;
            }
            _ if !model.is_empty() => {
                let i = rng.below(model.len());
                assert_eq!(v.get(i), Some(&model[i]));
            }
            _ => {}
        }
        if step % 1_000 == 0 {
            agrees(&v, &model);
        }
    }
    agrees(&v, &model);
    assert_eq!(v.get(model.len()), None);
    assert_eq!(v.set(model.len(), T::from(0)), Err(T::from(0)));
}

#[test]
fn random_operations_match_a_vec() {
    random_operations::<u64>(2026);
    random_operations::<u8>(7);
    random_operations::<String>(11);
}

#[test]
fn old_versions_are_unchanged() {
    let base: Vector<u64> = (0..5_000).collect();
    let mut a = base.clone();
    a.set(17, 99).unwrap();
    a.set(4_990, 99).unwrap();
    let b = base.update(2_000, 7).pushed(1).pushed(2);
    let mut c = base.clone();
    for _ in 0..1_000 {
        c.pop();
    }
    assert!(base.iter().copied().eq(0..5_000));
    assert_eq!(a.get(17), Some(&99));
    assert_eq!(b.get(2_000), Some(&7));
    assert_eq!(b.len(), 5_002);
    assert_eq!(c.len(), 4_000);
    for v in [&base, &a, &b, &c] {
        v.check_invariants().unwrap();
    }
}

#[test]
fn concat_and_slice_copy_into_canonical_vectors() {
    let a: Vector<u64> = (0..1_000).collect();
    let b: Vector<u64> = (1_000..2_345).collect();
    let ab = a.concat(&b);
    assert!(ab.iter().copied().eq(0..2_345));
    ab.check_invariants().unwrap();
    let s = ab.slice(37..1_500);
    assert!(s.iter().copied().eq(37..1_500));
    s.check_invariants().unwrap();
    assert_eq!(ab.slice(5..5).len(), 0);
    assert_eq!(ab.first(), Some(&0));
    assert_eq!(ab.last(), Some(&2_344));
    let text: Vector<u8> = b"hello, ".iter().copied().collect();
    let world: Vector<u8> = b"world".iter().copied().collect();
    let joined = text.concat(&world);
    assert_eq!(joined.iter().copied().collect::<Vec<u8>>(), b"hello, world");
    assert_eq!(joined.slice(7..12), world);
}

fn builder_shapes<T: Elem>() {
    let l = T::LEAF;
    for len in [0, 1, l - 1, l, l + 1, 2 * l, 2 * l + 1, 32 * l, 33 * l, 33 * l + 1] {
        let built: Vector<T> = (0..len as u64).map(T::from).collect();
        let mut pushed = Vector::new();
        for i in 0..len as u64 {
            pushed.push(T::from(i));
        }
        built.check_invariants().unwrap();
        assert_eq!(built, pushed, "length {len}");
        assert_eq!(built.identity(), pushed.identity(), "length {len}");
        // Built vectors keep working: push and pop across the tail.
        let mut b = built.clone();
        b.push(T::from(7));
        assert_eq!(b.pop(), Some(T::from(7)));
        if len > 0 {
            assert_eq!(b.pop(), Some(T::from(len as u64 - 1)));
        }
        b.check_invariants().unwrap();
    }
}

#[test]
fn the_builder_makes_the_canonical_shape() {
    builder_shapes::<u8>();
    builder_shapes::<u64>();
    builder_shapes::<String>();
}

// ---------------------------------------------------------------- identity

fn branch(ids: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/branch/v1");
    h.update([ids.len() as u8]);
    for id in ids {
        h.update(id);
    }
    h.finalize().into()
}

/// A vector's identity from its leaves' identities: the last leaf is the
/// tail, and the others, if any, go under branches of up to 32, left-packed,
/// until one root remains (at least one branch level).
fn vector_id(len: usize, leaves: Vec<[u8; 32]>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/v1");
    h.update((len as u64).to_le_bytes());
    if let Some((tail, tree)) = leaves.split_last() {
        if !tree.is_empty() {
            let mut level = tree.to_vec();
            loop {
                level = level.chunks(32).map(branch).collect();
                if level.len() == 1 {
                    break;
                }
            }
            h.update(level[0]);
        }
        h.update(tail);
    }
    h.finalize().into()
}

/// Elements split into leaves of `leaf`: full ones, then a tail of 1 to
/// `leaf` (none when empty).
fn chunks<T>(xs: &[T], leaf: usize) -> Vec<&[T]> {
    if xs.is_empty() {
        return Vec::new();
    }
    let tailoff = (xs.len() - 1) / leaf * leaf;
    let mut out: Vec<&[T]> = xs[..tailoff].chunks(leaf).collect();
    out.push(&xs[tailoff..]);
    out
}

/// Section 10.2: a leaf of strings, each encoded as tag `s`, length, bytes.
fn string_leaf(xs: &[String]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/leaf/v1");
    h.update([xs.len() as u8]);
    for x in xs {
        h.update([b's']);
        h.update((x.len() as u64).to_le_bytes());
        h.update(x.as_bytes());
    }
    h.finalize().into()
}

/// Section 10.5: a packed leaf, its elements' little-endian bytes.
fn packed_leaf(tag: u8, width: u8, count: usize, bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/packed-leaf/v1");
    h.update([tag, width]);
    h.update((count as u16).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

fn reference_u64(xs: &[u64]) -> [u8; 32] {
    let leaves = chunks(xs, 128)
        .into_iter()
        .map(|c| {
            let bytes: Vec<u8> = c.iter().flat_map(|x| x.to_le_bytes()).collect();
            packed_leaf(b'u', 8, c.len(), &bytes)
        })
        .collect();
    vector_id(xs.len(), leaves)
}

fn reference_u8(xs: &[u8]) -> [u8; 32] {
    let leaves = chunks(xs, 1_024)
        .into_iter()
        .map(|c| packed_leaf(b'u', 1, c.len(), c))
        .collect();
    vector_id(xs.len(), leaves)
}

fn reference_strings(xs: &[String]) -> [u8; 32] {
    let leaves = chunks(xs, 32).into_iter().map(string_leaf).collect();
    vector_id(xs.len(), leaves)
}

#[test]
fn identities_follow_the_format() {
    for len in [
        0, 1, 31, 32, 33, 127, 128, 129, 1_023, 1_024, 1_025, 1_056, 1_057, 4_224, 4_225,
        4_353, 33_000, 33_793, 33_800,
    ] {
        let xs: Vec<u64> = (0..len as u64).map(|i| i * 7 + 3).collect();
        let v: Vector<u64> = xs.iter().copied().collect();
        assert_eq!(v.identity(), reference_u64(&xs), "u64, length {len}");
        let bs: Vec<u8> = xs.iter().map(|&x| x as u8).collect();
        let v: Vector<u8> = bs.iter().copied().collect();
        assert_eq!(v.identity(), reference_u8(&bs), "u8, length {len}");
        let ss: Vec<String> = xs.iter().take(1_100).map(|x| x.to_string()).collect();
        let v: Vector<String> = ss.iter().cloned().collect();
        assert_eq!(v.identity(), reference_strings(&ss), "strings, length {}", ss.len());
    }
}

#[test]
fn element_types_decide_identity() {
    // The same numbers in different types are different vectors.
    let a: Vector<u8> = [1u8, 2, 3].into_iter().collect();
    let b: Vector<u64> = [1u64, 2, 3].into_iter().collect();
    let c: Vector<i64> = [1i64, 2, 3].into_iter().collect();
    assert_ne!(a.identity(), b.identity());
    assert_ne!(b.identity(), c.identity());
    // Floats by their bits: 0.0 and -0.0 differ.
    let z: Vector<f64> = [0.0f64].into_iter().collect();
    let nz: Vector<f64> = [-0.0f64].into_iter().collect();
    assert_ne!(z.identity(), nz.identity());
    // The empty vector is one value, whatever its element type.
    assert_eq!(Vector::<u8>::new().identity(), Vector::<String>::new().identity());
}

#[test]
fn history_does_not_matter() {
    let direct: Vector<u64> = (0..1_500).collect();
    let mut grown: Vector<u64> = (0..2_100).collect();
    for _ in 0..600 {
        grown.pop();
    }
    let mut edited: Vector<u64> = (0..1_500).map(|_| 0).collect();
    for i in (0..1_500).rev() {
        edited.set(i, i as u64).unwrap();
    }
    assert_eq!(direct.identity(), grown.identity());
    assert_eq!(direct.identity(), edited.identity());
    // Cached identities are cleared by writes: changing and restoring an
    // element restores the identity.
    let mut v = direct.clone();
    let before = v.identity();
    v.set(700, 1).unwrap();
    assert_ne!(v.identity(), before);
    v.set(700, 700).unwrap();
    assert_eq!(v.identity(), before);
}

#[test]
fn contents_decide_identity() {
    let a: Vector<u64> = (0..100).collect();
    let b: Vector<u64> = (0..101).collect();
    let c = a.update(99, 100);
    assert_ne!(a.identity(), b.identity());
    assert_ne!(a.identity(), c.identity());
    assert_eq!(Vector::<u64>::new().identity(), reference_u64(&[]));
}

#[test]
fn vectors_nest_through_identify() {
    use merkle_champ::ChampMap;
    let inner: Vector<u64> = (0..40).collect();
    let outer: Vector<Vector<u64>> = vec![inner.clone(), Vector::new()].into_iter().collect();
    let again: Vector<Vector<u64>> = vec![(0..40).collect(), Vector::new()].into_iter().collect();
    assert_eq!(outer.identity(), again.identity());
    // In a merkle-champ map too: the encoding is the tag `v` and the identity.
    let mut encoding = Vec::new();
    inner.identify(&mut encoding);
    assert_eq!(encoding[0], b'v');
    assert_eq!(&encoding[9..], &inner.identity());
    let map: ChampMap<String, Vector<u64>> = [("xs".to_string(), inner)].into_iter().collect();
    let map2: ChampMap<String, Vector<u64>> = [("xs".to_string(), (0..40).collect())]
        .into_iter()
        .collect();
    assert_eq!(map.identity(), map2.identity());
}
