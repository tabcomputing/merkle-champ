//! ChampSet: behaviour against a model, canonical shape, identity and diff.
use merkle_champ::{ChampMap, ChampSet, SetChange};
use std::collections::BTreeSet;

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

fn name(i: u64) -> String {
    format!("mod{}.word{}", i % 11, i)
}

#[test]
fn matches_a_model_under_random_operations() {
    let mut rng = Rng(21);
    let mut set = ChampSet::new();
    let mut model = BTreeSet::new();
    for step in 0..20_000 {
        let k = name(rng.next() % 2_000);
        if rng.next().is_multiple_of(3) {
            assert_eq!(set.remove(&k), model.remove(&k), "step {step}");
        } else {
            assert_eq!(set.insert(k.clone()), model.insert(k), "step {step}");
        }
    }
    set.check_invariants().unwrap();
    assert_eq!(set.len(), model.len());
    let mut seen: Vec<_> = set.iter().cloned().collect();
    seen.sort();
    assert_eq!(seen, model.iter().cloned().collect::<Vec<_>>());
    assert!(model.iter().all(|k| set.contains(k)));
    assert!(!set.contains(&"absent".to_string()));
}

#[test]
fn identity_is_history_independent_and_equals_the_unit_map() {
    let direct: ChampSet<String> = (0..1_000).map(name).collect();
    let mut shuffled: ChampSet<String> = (0..1_500).rev().map(name).collect();
    for i in 1_000..1_500 {
        shuffled.remove(&name(i));
    }
    shuffled.check_invariants().unwrap();
    assert_eq!(direct.identity(), shuffled.identity());
    assert_eq!(direct, shuffled);
    let units: ChampMap<String, ()> = (0..1_000).map(|i| (name(i), ())).collect();
    assert_eq!(direct.identity(), units.identity());
    // Removing everything returns to the empty identity.
    for i in 0..1_000 {
        shuffled.remove(&name(i));
    }
    assert!(shuffled.is_empty());
    assert_eq!(shuffled.identity(), ChampSet::<String>::new().identity());
}

#[test]
fn versions_are_persistent_and_diff_reports_added_and_removed() {
    let a: ChampSet<String> = (0..500).map(name).collect();
    let b = a.with("new.one".into()).without(&name(3)).without(&name(4));
    assert!(a.contains(&name(3)));
    assert!(!b.contains(&name(3)));
    let mut d: Vec<_> = a.diff(&b).into_iter().map(|c| format!("{c:?}")).collect();
    d.sort();
    let mut want = vec![
        format!("{:?}", SetChange::Added("new.one".to_string())),
        format!("{:?}", SetChange::Removed(name(3))),
        format!("{:?}", SetChange::Removed(name(4))),
    ];
    want.sort();
    assert_eq!(d, want);
    assert!(a.diff(&a.clone()).is_empty());
    // Inserting an existing element reports false and changes nothing.
    let mut c = a.clone();
    assert!(!c.insert(name(1)));
    assert!(c.ptr_eq(&a));
}

#[test]
fn sets_nest_inside_maps_with_their_own_identity() {
    let exports: ChampSet<String> = ["print".to_string(), "read".into()].into_iter().collect();
    let effects: ChampSet<String> = ["io".to_string()].into_iter().collect();
    let module: ChampMap<String, ChampSet<String>> = [
        ("exports".to_string(), exports.clone()),
        ("effects".to_string(), effects.clone()),
    ]
    .into_iter()
    .collect();
    let changed = module.update("exports".into(), exports.with("write".into()));
    assert_ne!(module.identity(), changed.identity());
    assert_eq!(
        changed.get(&"effects".to_string()).unwrap().identity(),
        effects.identity()
    );
}

#[test]
fn golden_set_identity() {
    let s: ChampSet<String> = ["a".to_string(), "b".into()].into_iter().collect();
    let hex: String = s.identity().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, GOLDEN_SET_AB,
        "set identity vector changed: format change?"
    );
}

// Pinned 2026-09-26; format v1.
const GOLDEN_SET_AB: &str = "d3a5a262791b2c4375a672eb218dcb5c4b29cf61318f49e00dc3af92450280ec";

/// A one-element set recomputed from FORMAT.md: a branch holding the element
/// with the `()` encoding (a lone `0` tag) as its value.
#[test]
fn one_element_set_follows_the_written_specification() {
    use merkle_champ::KeyHash;
    use sha2::{Digest, Sha256};
    let frag = ("a".key_hash() & 31) as u32;
    let mut h = Sha256::new();
    h.update(b"merkle-champ/branch/v1");
    h.update((1u32 << frag).to_le_bytes());
    h.update(0u32.to_le_bytes());
    h.update([b's']);
    h.update(1u64.to_le_bytes());
    h.update(b"a");
    h.update([b'0']);
    let want: [u8; 32] = h.finalize().into();
    let s: ChampSet<String> = ["a".to_string()].into_iter().collect();
    assert_eq!(s.identity(), want);
}
