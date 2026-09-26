//! Canonical shape, identity, persistence, and diff properties.
use merkle_champ::{ChampMap, Change, KeyHash};
use std::collections::BTreeMap;

/// Small deterministic PRNG (splitmix64), so tests need no dependencies.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn key(i: u64) -> String {
    format!("ns{}.word{}", i % 17, i)
}

/// A key type whose hash is chosen by the test, to force collisions and
/// shared prefixes deterministically.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Forced(u64, u32);
impl KeyHash for Forced {
    fn key_hash(&self) -> u64 {
        self.0
    }
}
impl merkle_champ::Identify for Forced {
    fn identify(&self, h: &mut sha2::Sha256) {
        use sha2::Digest;
        h.update(self.0.to_le_bytes());
        h.update(self.1.to_le_bytes());
    }
}

#[test]
fn matches_a_model_under_random_operations() {
    let mut rng = Rng(1);
    let mut map = ChampMap::new();
    let mut model = BTreeMap::new();
    for step in 0..20_000 {
        let k = key(rng.below(3_000));
        if rng.below(3) == 0 {
            assert_eq!(map.remove(&k), model.remove(&k), "step {step}");
        } else {
            let v = rng.next();
            assert_eq!(map.insert(k.clone(), v), model.insert(k, v), "step {step}");
        }
        if step % 997 == 0 {
            map.check_invariants().unwrap();
        }
    }
    map.check_invariants().unwrap();
    assert_eq!(map.len(), model.len());
    for (k, v) in &model {
        assert_eq!(map.get(k), Some(v));
    }
    let mut seen: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    seen.sort();
    assert_eq!(seen, model.into_iter().collect::<Vec<_>>());
}

#[test]
fn shape_and_identity_are_independent_of_history() {
    let mut rng = Rng(2);
    let contents: Vec<_> = (0..2_000u64).map(|i| (key(i), i)).collect();
    let direct: ChampMap<String, u64> = contents.iter().cloned().collect();
    let id = direct.identity();
    for round in 0..5 {
        // Insert in a shuffled order, with noise keys inserted and removed.
        let mut order = contents.clone();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let mut map = ChampMap::new();
        for (i, (k, v)) in order.into_iter().enumerate() {
            map.insert(format!("noise{round}.{i}"), 0);
            map.insert(k, v + 1); // wrong value, fixed below
            if i % 3 == 0 {
                map.remove(&format!("noise{round}.{i}"));
            }
        }
        for i in 0..contents.len() {
            map.remove(&format!("noise{round}.{i}"));
        }
        for (k, v) in &contents {
            map.insert(k.clone(), *v);
        }
        map.check_invariants().unwrap();
        assert_eq!(map.identity(), id, "round {round}");
    }
}

#[test]
fn deleting_everything_returns_to_the_empty_identity() {
    let empty = ChampMap::<String, u64>::new().identity();
    let mut map: ChampMap<String, u64> = (0..5_000u64).map(|i| (key(i), i)).collect();
    assert_ne!(map.identity(), empty);
    for i in 0..5_000 {
        map.remove(&key(i));
        if i % 500 == 0 {
            map.check_invariants().unwrap();
        }
    }
    assert!(map.is_empty());
    assert_eq!(map.identity(), empty);
}

#[test]
fn collisions_and_deep_shared_prefixes_stay_canonical() {
    // Same full hash (collision node), and hashes sharing the low 60 bits.
    let a = Forced(0xdead_beef, 1);
    let b = Forced(0xdead_beef, 2);
    let c = Forced(0xdead_beef, 3);
    let d = Forced(0xdead_beef | (1 << 62), 4);
    let direct: ChampMap<Forced, u64> = [(a.clone(), 1), (d.clone(), 4)].into_iter().collect();
    let mut map: ChampMap<Forced, u64> = [
        (c.clone(), 3),
        (b.clone(), 2),
        (a.clone(), 1),
        (d.clone(), 4),
    ]
    .into_iter()
    .collect();
    map.check_invariants().unwrap();
    assert_eq!(map.get(&b), Some(&2));
    map.remove(&b);
    map.check_invariants().unwrap();
    map.remove(&c);
    map.check_invariants().unwrap();
    assert_eq!(map.identity(), direct.identity());
    assert_eq!(map.get(&a), Some(&1));
    assert_eq!(map.get(&d), Some(&4));
    assert_eq!(map.get(&b), None);
}

#[test]
fn versions_are_persistent_and_share_structure() {
    let base: ChampMap<String, u64> = (0..1_000u64).map(|i| (key(i), i)).collect();
    let base_id = base.identity();
    let next = base
        .update(key(5), 999)
        .without(&key(6))
        .update("new".into(), 1);
    assert_eq!(base.get(&key(5)), Some(&5));
    assert_eq!(base.get(&key(6)), Some(&6));
    assert_eq!(base.identity(), base_id);
    assert_eq!(next.get(&key(5)), Some(&999));
    assert_eq!(next.get(&key(6)), None);
    assert_eq!(next.len(), 1_000);
    let clone = base.clone();
    assert!(clone.ptr_eq(&base));
}

#[test]
fn identity_is_content_equality() {
    let a: ChampMap<String, u64> = (0..300u64).map(|i| (key(i), i)).collect();
    let b: ChampMap<String, u64> = (0..300u64).rev().map(|i| (key(i), i)).collect();
    assert_eq!(a.identity(), b.identity());
    assert_ne!(a.identity(), a.update(key(1), 2).identity());
    assert_ne!(a.identity(), a.without(&key(1)).identity());
}

#[test]
fn diff_reports_exactly_the_changes() {
    let mut rng = Rng(3);
    let base: ChampMap<String, u64> = (0..3_000u64).map(|i| (key(i), i)).collect();
    for changes in [0usize, 1, 10, 300, 2_500] {
        let mut next = base.clone();
        let mut model = BTreeMap::new();
        for _ in 0..changes {
            let i = rng.below(4_000);
            let k = key(i);
            if rng.below(2) == 0 {
                next.remove(&k);
            } else {
                next.insert(k, rng.next());
            }
        }
        // Expected changes from a model comparison.
        let old: BTreeMap<_, _> = base.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let new: BTreeMap<_, _> = next.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for (k, v) in &old {
            match new.get(k) {
                None => {
                    model.insert(k.clone(), Change::Removed(k.clone(), *v));
                }
                Some(w) if w != v => {
                    model.insert(k.clone(), Change::Changed(k.clone(), *v, *w));
                }
                _ => {}
            }
        }
        for (k, w) in &new {
            if !old.contains_key(k) {
                model.insert(k.clone(), Change::Added(k.clone(), *w));
            }
        }
        let mut got: Vec<_> = base.diff(&next);
        let key_of = |c: &Change<String, u64>| match c {
            Change::Added(k, _) | Change::Removed(k, _) | Change::Changed(k, _, _) => k.clone(),
        };
        got.sort_by_key(key_of);
        assert_eq!(
            got,
            model.into_values().collect::<Vec<_>>(),
            "{changes} changes"
        );
        // And the reverse direction is the mirror image.
        assert_eq!(next.diff(&base).len(), got.len());
    }
}

#[test]
fn nested_maps_give_each_namespace_an_identity() {
    let io: ChampMap<String, u64> = [("print".to_string(), 1), ("read".into(), 2)]
        .into_iter()
        .collect();
    let math: ChampMap<String, u64> = [("add".to_string(), 3)].into_iter().collect();
    let root: ChampMap<String, ChampMap<String, u64>> = [
        ("io".to_string(), io.clone()),
        ("math".into(), math.clone()),
    ]
    .into_iter()
    .collect();
    let io2 = io.update("print".into(), 9);
    let root2 = root.update("io".into(), io2.clone());
    assert_ne!(root.identity(), root2.identity());
    assert_eq!(
        root2.get(&"math".to_string()).unwrap().identity(),
        math.identity()
    );
    assert_eq!(
        root2.get(&"io".to_string()).unwrap().identity(),
        io2.identity()
    );
}

/// The layered identity used for imbl in the benchmark (sort + hash every
/// entry) is also history-independent; this pins that both candidates'
/// identity schemes agree on equal contents reached through different histories.
#[test]
fn both_identity_schemes_are_history_independent() {
    use sha2::{Digest, Sha256};
    fn layered(m: &imbl::HashMap<String, u64>) -> [u8; 32] {
        let mut all: Vec<_> = m.iter().collect();
        all.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut h = Sha256::new();
        for (k, v) in all {
            h.update((k.len() as u64).to_le_bytes());
            h.update(k.as_bytes());
            h.update(v.to_le_bytes());
        }
        h.finalize().into()
    }
    let mut rng = Rng(9);
    let mut champ_ids = Vec::new();
    let mut imbl_ids = Vec::new();
    for round in 0..4 {
        let mut c = ChampMap::new();
        let mut i = imbl::HashMap::new();
        let mut order: Vec<u64> = (0..1_500).collect();
        for j in (1..order.len()).rev() {
            order.swap(j, rng.below(j as u64 + 1) as usize);
        }
        for &n in &order {
            c.insert(format!("noise{round}.{n}"), n);
            i.insert(format!("noise{round}.{n}"), n);
            c.insert(key(n), n);
            i.insert(key(n), n);
        }
        for &n in &order {
            c.remove(&format!("noise{round}.{n}"));
            i.remove(&format!("noise{round}.{n}"));
        }
        champ_ids.push(c.identity());
        imbl_ids.push(layered(&i));
    }
    assert!(champ_ids.windows(2).all(|w| w[0] == w[1]));
    assert!(imbl_ids.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn get_mut_updates_nested_maps_and_invalidates_identities() {
    let inner: ChampMap<String, u64> = (0..200u64).map(|i| (key(i), i)).collect();
    let mut root: ChampMap<String, ChampMap<String, u64>> = (0..50u64)
        .map(|i| (format!("ns{i}"), inner.clone()))
        .collect();
    let before = root.identity();
    let snapshot = root.clone();
    root.get_mut(&"ns7".to_string())
        .unwrap()
        .insert("x".into(), 1);
    assert_ne!(root.identity(), before);
    assert_eq!(snapshot.identity(), before);
    assert_eq!(
        snapshot
            .get(&"ns7".to_string())
            .unwrap()
            .get(&"x".to_string()),
        None
    );
    // Same contents built directly give the same identity.
    let mut direct: ChampMap<String, ChampMap<String, u64>> = (0..50u64)
        .map(|i| (format!("ns{i}"), inner.clone()))
        .collect();
    direct.insert("ns7".into(), inner.update("x".into(), 1));
    assert_eq!(direct.identity(), root.identity());
    root.check_invariants().unwrap();
    assert!(root.get_mut(&"absent".to_string()).is_none());
}
