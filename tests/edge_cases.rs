//! Edge cases reviewed before release: extreme hashes, deep chains, large
//! collision nodes, every diff shape, concurrency, panics during identity,
//! encoding separation, and identity uniqueness.
use merkle_champ::{ChampMap, ChampSet, Change, Identify, KeyHash};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A key whose placement hash is chosen by the test.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct H(u64, u32);
impl KeyHash for H {
    fn key_hash(&self) -> u64 {
        self.0
    }
}
impl Identify for H {
    fn identify(&self, h: &mut Sha256) {
        h.update([b'H']);
        h.update(self.0.to_le_bytes());
        h.update(self.1.to_le_bytes());
    }
}

fn build(pairs: &[(H, u64)]) -> ChampMap<H, u64> {
    pairs.iter().cloned().collect()
}

#[test]
fn keys_differing_only_in_the_top_hash_bits_chain_to_the_last_level_and_collapse() {
    // Equal in bits 0..59, different in 60..63: a chain of branches down to
    // level 12, where the two entries finally separate.
    let a = H(0x0fff_ffff_ffff_ffff, 0);
    let b = H(0x1fff_ffff_ffff_ffff, 1);
    let c = H(0x8fff_ffff_ffff_ffff, 2); // differs only in bit 63
    let mut m = build(&[(a.clone(), 1), (b.clone(), 2), (c.clone(), 3)]);
    m.check_invariants().unwrap();
    assert_eq!(
        (m.get(&a), m.get(&b), m.get(&c)),
        (Some(&1), Some(&2), Some(&3))
    );
    // Removing down to one key collapses the whole chain back to the root.
    m.remove(&b);
    m.check_invariants().unwrap();
    m.remove(&c);
    m.check_invariants().unwrap();
    assert_eq!(m.identity(), build(&[(a.clone(), 1)]).identity());
    m.remove(&a);
    assert_eq!(m.identity(), ChampMap::<H, u64>::new().identity());
}

#[test]
fn extreme_placement_hashes_work() {
    let keys = [
        0u64,
        1,
        31,
        32,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) - 1,
    ];
    let m: ChampMap<H, u64> = keys
        .iter()
        .enumerate()
        .map(|(i, &h)| (H(h, 0), i as u64))
        .collect();
    m.check_invariants().unwrap();
    for (i, &h) in keys.iter().enumerate() {
        assert_eq!(m.get(&H(h, 0)), Some(&(i as u64)));
    }
    // Provided integer key hashes: fmix64 is a bijection, and 0 maps to 0.
    assert_eq!(0u64.key_hash(), 0);
    let ints: ChampMap<u64, u64> = [0u64, 1, u64::MAX].into_iter().map(|k| (k, k)).collect();
    assert_eq!(ints.get(&u64::MAX), Some(&u64::MAX));
    let signed: ChampMap<i64, u64> = [i64::MIN, -1, 0, i64::MAX]
        .into_iter()
        .map(|k| (k, 1))
        .collect();
    signed.check_invariants().unwrap();
    assert_eq!(signed.len(), 4);
}

#[test]
fn a_large_collision_node_supports_every_operation() {
    let full = 0x5555_aaaa_5555_aaaa;
    let mut model = BTreeMap::new();
    let mut m = ChampMap::new();
    for i in (0..200u32).rev() {
        m.insert(H(full, i), u64::from(i));
        model.insert(i, u64::from(i));
    }
    m.insert(H(full ^ 1, 0), 7); // a neighbour outside the collision node
    m.check_invariants().unwrap();
    // Replace, get_mut, and remove inside the collision node.
    assert_eq!(m.insert(H(full, 50), 5_000), Some(50));
    *m.get_mut(&H(full, 51)).unwrap() += 1;
    let before = m.clone();
    for i in 0..199 {
        m.remove(&H(full, i));
        if i % 37 == 0 {
            m.check_invariants().unwrap();
        }
    }
    // One collision entry left: it must be inlined, as if inserted alone.
    m.check_invariants().unwrap();
    assert_eq!(
        m.identity(),
        build(&[(H(full, 199), 199), (H(full ^ 1, 0), 7)]).identity()
    );
    assert_eq!(before.get(&H(full, 50)), Some(&5_000));
    assert_eq!(before.get(&H(full, 51)), Some(&52));
    assert_eq!(before.len(), 201);
}

fn sorted(d: Vec<Change<H, u64>>) -> Vec<String> {
    let mut v: Vec<String> = d.into_iter().map(|c| format!("{c:?}")).collect();
    v.sort();
    v
}

#[test]
fn diff_covers_entry_versus_subtrie_in_both_directions() {
    // Keys sharing fragment 3 at level 0.
    let x = H(3, 0);
    let y = H(3 | (1 << 5), 1);
    let z = H(3 | (2 << 5), 2);
    let entry_only = build(&[(x.clone(), 1)]);
    let cases: Vec<(ChampMap<H, u64>, ChampMap<H, u64>)> = vec![
        // entry -> sub-trie containing the same key unchanged, plus others
        (
            entry_only.clone(),
            build(&[(x.clone(), 1), (y.clone(), 2), (z.clone(), 3)]),
        ),
        // entry -> sub-trie containing the key with a changed value
        (entry_only.clone(), build(&[(x.clone(), 9), (y.clone(), 2)])),
        // entry -> sub-trie without the key
        (entry_only.clone(), build(&[(y.clone(), 2), (z.clone(), 3)])),
        // different single entries at one position
        (entry_only, build(&[(y.clone(), 2)])),
        // empty -> anything
        (ChampMap::new(), build(&[(x.clone(), 1), (y.clone(), 2)])),
    ];
    for (i, (a, b)) in cases.into_iter().enumerate() {
        let model_a: BTreeMap<H, u64> = a.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let model_b: BTreeMap<H, u64> = b.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let mut want = Vec::new();
        for (k, v) in &model_a {
            match model_b.get(k) {
                None => want.push(Change::Removed(k.clone(), *v)),
                Some(w) if w != v => want.push(Change::Changed(k.clone(), *v, *w)),
                _ => {}
            }
        }
        for (k, w) in &model_b {
            if !model_a.contains_key(k) {
                want.push(Change::Added(k.clone(), *w));
            }
        }
        let mirror: Vec<Change<H, u64>> = want
            .iter()
            .map(|c| match c.clone() {
                Change::Added(k, v) => Change::Removed(k, v),
                Change::Removed(k, v) => Change::Added(k, v),
                Change::Changed(k, v, w) => Change::Changed(k, w, v),
            })
            .collect();
        assert_eq!(sorted(a.diff(&b)), sorted(want), "case {i} forward");
        assert_eq!(sorted(b.diff(&a)), sorted(mirror), "case {i} backward");
    }
}

#[test]
fn maps_and_sets_are_send_and_sync_and_identity_is_race_free() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ChampMap<String, u64>>();
    assert_send_sync::<ChampSet<String>>();
    let m: ChampMap<String, u64> = (0..20_000u64).map(|i| (format!("k{i}"), i)).collect();
    let expected = m.clone().identity();
    // Many threads request the identity of the SAME uncached nodes at once.
    let fresh: ChampMap<String, u64> = (0..20_000u64).map(|i| (format!("k{i}"), i)).collect();
    let ids: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8).map(|_| s.spawn(|| fresh.identity())).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(ids.iter().all(|id| *id == expected));
    // Threads updating their own clones never affect each other or the base.
    std::thread::scope(|s| {
        for t in 0..4u64 {
            let mut mine = fresh.clone();
            s.spawn(move || {
                for i in 0..1_000 {
                    mine.insert(format!("t{t}.{i}"), i);
                }
                assert_eq!(mine.len(), 21_000);
                mine.check_invariants().unwrap();
            });
        }
    });
    assert_eq!(fresh.len(), 20_000);
    assert_eq!(fresh.identity(), expected);
}

thread_local! {
    static PANIC_IN_IDENTIFY: Cell<bool> = const { Cell::new(false) };
}
#[derive(Clone, Debug, PartialEq)]
struct Flaky(u64);
impl Identify for Flaky {
    fn identify(&self, h: &mut Sha256) {
        if PANIC_IN_IDENTIFY.with(Cell::get) {
            panic!("identify");
        }
        self.0.identify(h);
    }
}

#[test]
fn a_panic_while_computing_an_identity_caches_nothing_wrong() {
    let m: ChampMap<String, Flaky> = (0..2_000u64).map(|i| (format!("k{i}"), Flaky(i))).collect();
    let good: ChampMap<String, Flaky> =
        (0..2_000u64).map(|i| (format!("k{i}"), Flaky(i))).collect();
    let expected = good.identity();
    PANIC_IN_IDENTIFY.with(|c| c.set(true));
    assert!(catch_unwind(AssertUnwindSafe(|| m.identity())).is_err());
    PANIC_IN_IDENTIFY.with(|c| c.set(false));
    assert_eq!(m.identity(), expected);
}

#[test]
fn encodings_keep_types_and_nesting_apart() {
    // The same bytes as a string key and as a byte-string key.
    let s: ChampMap<String, u64> = [("ab".to_string(), 1)].into_iter().collect();
    let b: ChampMap<Vec<u8>, u64> = [(b"ab".to_vec(), 1)].into_iter().collect();
    assert_ne!(s.identity(), b.identity());
    // u64 versus i64 values with the same bits.
    let u: ChampMap<String, u64> = [("k".to_string(), 5u64)].into_iter().collect();
    let i: ChampMap<String, i64> = [("k".to_string(), 5i64)].into_iter().collect();
    assert_ne!(u.identity(), i.identity());
    // A set equals its unit map at top level, but not when nested.
    let set: ChampSet<String> = ["x".to_string()].into_iter().collect();
    let unit: ChampMap<String, ()> = [("x".to_string(), ())].into_iter().collect();
    assert_eq!(set.identity(), unit.identity());
    let outer_set: ChampMap<String, ChampSet<String>> =
        [("n".to_string(), set)].into_iter().collect();
    let outer_map: ChampMap<String, ChampMap<String, ()>> =
        [("n".to_string(), unit)].into_iter().collect();
    assert_ne!(outer_set.identity(), outer_map.identity());
    // Swapping values between two keys changes the identity.
    let ab: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)]
        .into_iter()
        .collect();
    let ba: ChampMap<String, u64> = [("a".to_string(), 2), ("b".into(), 1)]
        .into_iter()
        .collect();
    assert_ne!(ab.identity(), ba.identity());
    // Empty keys and values are fine and distinct from absence.
    let empty_key: ChampMap<String, u64> = [(String::new(), 0)].into_iter().collect();
    assert_ne!(
        empty_key.identity(),
        ChampMap::<String, u64>::new().identity()
    );
    assert_eq!(empty_key.get(&String::new()), Some(&0));
}

#[test]
fn distinct_small_contents_never_share_an_identity() {
    // Every subset of 12 keys, each with value 0 or 1 for a few keys:
    // thousands of distinct small maps, all identities distinct.
    let mut seen = HashSet::new();
    let mut count = 0;
    for mask in 0u32..(1 << 12) {
        let m: ChampMap<String, u64> = (0..12)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| (format!("k{i}"), u64::from(mask.count_ones() % 2)))
            .collect();
        assert!(
            seen.insert(m.identity()),
            "identity collision at mask {mask}"
        );
        count += 1;
    }
    assert_eq!(count, 4096);
}

#[test]
fn iteration_visits_each_entry_once_and_stays_finished() {
    let m: ChampMap<String, u64> = (0..5_000u64).map(|i| (format!("k{i}"), i)).collect();
    let mut it = m.iter();
    let mut keys = HashSet::new();
    for (k, _) in it.by_ref() {
        assert!(keys.insert(k.clone()), "duplicate {k}");
    }
    assert_eq!(keys.len(), 5_000);
    assert!(it.next().is_none());
    assert!(it.next().is_none());
    // Iteration order is a function of contents only.
    let other: ChampMap<String, u64> = (0..5_000u64).rev().map(|i| (format!("k{i}"), i)).collect();
    assert!(m.iter().map(|(k, _)| k).eq(other.iter().map(|(k, _)| k)));
}

#[test]
fn equality_and_debug_behave() {
    let a: ChampMap<String, u64> = (0..50u64).map(|i| (format!("k{i}"), i)).collect();
    let b: ChampMap<String, u64> = (0..50u64).rev().map(|i| (format!("k{i}"), i)).collect();
    assert_eq!(a, b);
    assert_ne!(a, b.update("k1".into(), 99));
    assert_ne!(a, b.without(&"k1".to_string()));
    assert_eq!(ChampMap::<String, u64>::new(), ChampMap::new());
    let small: ChampMap<String, u64> = [("only".to_string(), 1)].into_iter().collect();
    assert_eq!(format!("{small:?}"), "{\"only\": 1}");
    let set: ChampSet<u64> = [7u64].into_iter().collect();
    assert_eq!(format!("{set:?}"), "{7}");
}

#[test]
fn very_large_keys_and_values_are_handled() {
    let big = "k".repeat(1 << 20);
    let m: ChampMap<String, Vec<u8>> = [
        (big.clone(), vec![7u8; 1 << 20]),
        ("small".to_string(), vec![]),
    ]
    .into_iter()
    .collect();
    assert_eq!(m.get(&big).map(Vec::len), Some(1 << 20));
    let again: ChampMap<String, Vec<u8>> = [
        ("small".to_string(), vec![]),
        (big.clone(), vec![7u8; 1 << 20]),
    ]
    .into_iter()
    .collect();
    assert_eq!(m.identity(), again.identity());
}

/// Long randomized differential run: every operation, snapshots, nested maps,
/// diffs and identities checked against a model. Ignored by default;
/// run with `cargo test --release -- --ignored soak`.
#[test]
#[ignore]
fn soak() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }
    let mut rng = Rng(99);
    let mut m: ChampMap<H, ChampMap<H, u64>> = ChampMap::new();
    let mut model: BTreeMap<H, BTreeMap<H, u64>> = BTreeMap::new();
    type Snapshot = (ChampMap<H, ChampMap<H, u64>>, BTreeMap<H, BTreeMap<H, u64>>);
    let mut snaps: Vec<Snapshot> = Vec::new();
    let to_champ = |inner: &BTreeMap<H, u64>| {
        inner
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<ChampMap<H, u64>>()
    };
    for step in 0..2_000_000u64 {
        // Small hash spaces force collisions and shared prefixes at both levels.
        let outer = H(rng.next() % 40, (rng.next() % 2) as u32);
        let inner = H(
            (rng.next() % 256) | ((rng.next() % 3) << 61),
            (rng.next() % 2) as u32,
        );
        match rng.next() % 6 {
            0 => {
                if m.remove(&outer).is_some() {
                    model.remove(&outer);
                }
            }
            1 | 2 => {
                let v = rng.next();
                match m.get_mut(&outer) {
                    Some(map) => {
                        map.insert(inner.clone(), v);
                    }
                    None => {
                        m.insert(outer.clone(), ChampMap::new().update(inner.clone(), v));
                    }
                }
                model.entry(outer).or_default().insert(inner, v);
            }
            3 => {
                if let Some(map) = m.get_mut(&outer) {
                    map.remove(&inner);
                    model.get_mut(&outer).unwrap().remove(&inner);
                }
            }
            4 => {
                if step % 50 == 0 {
                    m.identity();
                }
            }
            _ => {
                if step % 9_973 == 0 {
                    snaps.push((m.clone(), model.clone()));
                }
            }
        }
        if step % 20_011 == 0 {
            m.check_invariants().unwrap();
        }
    }
    let rebuild = |model: &BTreeMap<H, BTreeMap<H, u64>>| -> ChampMap<H, ChampMap<H, u64>> {
        model
            .iter()
            .map(|(k, inner)| (k.clone(), to_champ(inner)))
            .collect()
    };
    for (i, (snap, snap_model)) in snaps.iter().enumerate() {
        snap.check_invariants().unwrap();
        assert_eq!(
            snap.identity(),
            rebuild(snap_model).identity(),
            "snapshot {i}"
        );
        if i > 0 {
            let prev = &snaps[i - 1].0;
            // Diff between consecutive snapshots matches the models.
            let d = prev.diff(snap).len();
            let pm = &snaps[i - 1].1;
            let expect = pm
                .keys()
                .chain(snap_model.keys())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|k| pm.get(*k) != snap_model.get(*k))
                .count();
            assert_eq!(d, expect, "diff between snapshots {} and {i}", i - 1);
        }
    }
    assert_eq!(m.identity(), rebuild(&model).identity());
}

#[test]
fn equality_needs_no_identity_and_matches_content() {
    // A value type with equality but no Identify implementation.
    #[derive(Clone, Debug, PartialEq)]
    struct Plain(f64);
    let a: ChampMap<String, Plain> = (0..300)
        .map(|i| (format!("k{i}"), Plain(f64::from(i))))
        .collect();
    let b: ChampMap<String, Plain> = (0..300)
        .rev()
        .map(|i| (format!("k{i}"), Plain(f64::from(i))))
        .collect();
    assert_eq!(a, b);
    assert_ne!(a, b.update("k3".into(), Plain(-1.0)));
    assert_ne!(a, b.without(&"k3".to_string()));
    // NaN follows PartialEq: a map holding NaN is not equal to itself by
    // content, but a shared version is equal by pointer (documented shortcut).
    let nan: ChampMap<String, Plain> = [("x".to_string(), Plain(f64::NAN))].into_iter().collect();
    let rebuilt: ChampMap<String, Plain> =
        [("x".to_string(), Plain(f64::NAN))].into_iter().collect();
    assert_ne!(nan, rebuilt);
    assert_eq!(nan, nan.clone());
}
