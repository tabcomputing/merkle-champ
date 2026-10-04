//! The vector (`merkle_champ::vector`): against a `Vec` model through random
//! and boundary-crossing operations, with the canonical shape checked along
//! the way, and identities against an independent computation of FORMAT.md
//! section 10, which chunks a plain slice rather than walking the tree.
use merkle_champ::Vector;
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

fn agrees(v: &Vector<u64>, model: &[u64]) {
    assert_eq!(v.len(), model.len());
    assert!(v.iter().eq(model.iter()), "elements differ");
    v.check_invariants().unwrap();
}

#[test]
fn grows_and_shrinks_through_every_level() {
    // Past 32 (the first leaf), 1,056 (a second branch level) and 32,800 (a
    // third), then all the way back down.
    let mut v = Vector::new();
    let mut model = Vec::new();
    for i in 0..40_000u64 {
        v.push(i);
        model.push(i);
        if i % 997 == 0 || (i as usize + 1).is_power_of_two() || (i + 1) % 32 <= 1 && i < 2_200 {
            agrees(&v, &model);
        }
    }
    agrees(&v, &model);
    for i in (0..40_000usize).rev() {
        assert_eq!(v.pop(), model.pop());
        if i % 991 == 0 || i.is_power_of_two() || i % 32 <= 1 && i < 2_200 {
            agrees(&v, &model);
        }
    }
    assert_eq!(v.pop(), None);
    agrees(&v, &model);
}

#[test]
fn random_operations_match_a_vec() {
    let mut rng = Rng(2026);
    let mut v: Vector<u64> = Vector::new();
    let mut model: Vec<u64> = Vec::new();
    for step in 0..60_000 {
        match rng.below(10) {
            0..=4 => {
                let x = rng.next();
                v.push(x);
                model.push(x);
            }
            5 | 6 => assert_eq!(v.pop(), model.pop()),
            7 | 8 if !model.is_empty() => {
                let i = rng.below(model.len());
                let x = rng.next();
                assert_eq!(v.set(i, x), Ok(model[i]));
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
    assert_eq!(v.set(model.len(), 0), Err(0));
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
}

#[test]
fn the_builder_makes_the_canonical_shape() {
    for len in [0, 1, 31, 32, 33, 64, 65, 1_024, 1_056, 1_057, 33_000] {
        let built: Vector<u64> = (0..len as u64).collect();
        let mut pushed = Vector::new();
        for i in 0..len as u64 {
            pushed.push(i);
        }
        built.check_invariants().unwrap();
        assert_eq!(built, pushed, "length {len}");
        // Built vectors keep working: push and pop across the tail.
        let mut b = built.clone();
        b.push(7);
        assert_eq!(b.pop(), Some(7));
        if len > 0 {
            assert_eq!(b.pop(), Some(len as u64 - 1));
        }
        b.check_invariants().unwrap();
    }
}

// ---------------------------------------------------------------- identity

/// merkle-champ's encoding of a `u64`: tag `u`, length 8, the bytes.
fn encode(x: u64) -> Vec<u8> {
    let mut e = vec![b'u'];
    e.extend(8u64.to_le_bytes());
    e.extend(x.to_le_bytes());
    e
}

fn leaf(xs: &[u64]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/leaf/v1");
    h.update([xs.len() as u8]);
    for &x in xs {
        h.update(encode(x));
    }
    h.finalize().into()
}

fn branch(ids: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/branch/v1");
    h.update([ids.len() as u8]);
    for id in ids {
        h.update(id);
    }
    h.finalize().into()
}

/// The tree over `xs`, a multiple of 32: leaves of 32, then branches of up to
/// 32, left-packed, until one root remains (at least one branch level).
fn tree(xs: &[u64]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = xs.chunks(32).map(leaf).collect();
    loop {
        level = level.chunks(32).map(branch).collect();
        if level.len() == 1 {
            return level[0];
        }
    }
}

fn reference(xs: &[u64]) -> [u8; 32] {
    let len = xs.len();
    let tailoff = if len == 0 { 0 } else { (len - 1) / 32 * 32 };
    let mut h = Sha256::new();
    h.update(b"merkle-champ/vector/v1");
    h.update((len as u64).to_le_bytes());
    if tailoff > 0 {
        h.update(tree(&xs[..tailoff]));
    }
    if len > 0 {
        h.update(leaf(&xs[tailoff..]));
    }
    h.finalize().into()
}

#[test]
fn identities_follow_the_format() {
    for len in [
        0, 1, 31, 32, 33, 63, 64, 65, 1_023, 1_024, 1_055, 1_056, 1_057, 2_000, 32_800, 32_801,
        33_000,
    ] {
        let xs: Vec<u64> = (0..len as u64).map(|i| i * 7 + 3).collect();
        let v: Vector<u64> = xs.iter().copied().collect();
        assert_eq!(v.identity(), reference(&xs), "length {len}");
    }
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
    assert_eq!(Vector::<u64>::new().identity(), reference(&[]));
}

#[test]
fn vectors_nest_through_identify() {
    use merkle_champ::{ChampMap, Identify};
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
