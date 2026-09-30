//! Robustness: collision diffs, independent construction with cold and warm
//! identities, historical snapshots, no-op changes, and panics in user code.
use merkle_champ::{ChampMap, Change, Identify, KeyHash, Sink};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

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

thread_local! {
    static PANIC_ON_CLONE: Cell<bool> = const { Cell::new(false) };
    /// Clones remaining before PANIC_ON_CLONE takes effect.
    static CLONES_BEFORE_PANIC: Cell<u32> = const { Cell::new(0) };
    static PANIC_ON_CMP: Cell<bool> = const { Cell::new(false) };
}

/// A key with a chosen placement hash, whose Clone and comparisons can be
/// made to panic.
#[derive(Debug)]
struct K(u64, u32);
impl Clone for K {
    fn clone(&self) -> Self {
        if PANIC_ON_CLONE.with(Cell::get) {
            let left = CLONES_BEFORE_PANIC.with(Cell::get);
            if left == 0 {
                panic!("clone");
            }
            CLONES_BEFORE_PANIC.with(|c| c.set(left - 1));
        }
        K(self.0, self.1)
    }
}
impl PartialEq for K {
    fn eq(&self, o: &Self) -> bool {
        if PANIC_ON_CMP.with(Cell::get) {
            panic!("eq");
        }
        (self.0, self.1) == (o.0, o.1)
    }
}
impl Eq for K {}
impl PartialOrd for K {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for K {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        if PANIC_ON_CMP.with(Cell::get) {
            panic!("cmp");
        }
        (self.0, self.1).cmp(&(o.0, o.1))
    }
}
impl KeyHash for K {
    fn key_hash(&self) -> u64 {
        self.0
    }
}
impl Identify for K {
    fn identify<S: Sink + ?Sized>(&self, h: &mut S) {
        h.update(b"K");
        h.update(&self.0.to_le_bytes());
        h.update(&self.1.to_le_bytes());
    }
}

type Model = BTreeMap<(u64, u32), u64>;
type Operation<'a> = Box<dyn Fn(&mut ChampMap<K, u64>) + 'a>;

fn model_of(m: &ChampMap<K, u64>) -> BTreeMap<(u64, u32), u64> {
    m.iter().map(|(k, v)| ((k.0, k.1), *v)).collect()
}

fn build(model: &BTreeMap<(u64, u32), u64>) -> ChampMap<K, u64> {
    model.iter().map(|(&(h, i), &v)| (K(h, i), v)).collect()
}

fn sorted(mut d: Vec<Change<K, u64>>) -> Vec<String> {
    let mut out: Vec<String> = d.drain(..).map(|c| format!("{c:?}")).collect();
    out.sort();
    out
}

/// Expected changes from two models.
fn expected(a: &BTreeMap<(u64, u32), u64>, b: &BTreeMap<(u64, u32), u64>) -> Vec<String> {
    let mut out = Vec::new();
    for (&(h, i), &v) in a {
        match b.get(&(h, i)) {
            None => out.push(format!("{:?}", Change::Removed(K(h, i), v))),
            Some(&w) if w != v => out.push(format!("{:?}", Change::Changed(K(h, i), v, w))),
            _ => {}
        }
    }
    for (&(h, i), &w) in b {
        if !a.contains_key(&(h, i)) {
            out.push(format!("{:?}", Change::Added(K(h, i), w)));
        }
    }
    out.sort();
    out
}

#[test]
fn collision_node_diffs_in_both_directions() {
    let full = 0x1234_5678_9abc_def0;
    let mut a: BTreeMap<(u64, u32), u64> = (0..5).map(|i| ((full, i), u64::from(i))).collect();
    for i in 0..50 {
        a.insert((u64::from(i) * 0x9e37_79b9, 100 + i), 7);
    }
    let mut b = a.clone();
    b.insert((full, 1), 99); // changed inside the collision node
    b.remove(&(full, 3)); // removed from it
    b.insert((full, 9), 9); // added to it
    b.remove(&(full, 0));
    let (ma, mb) = (build(&a), build(&b));
    ma.check_invariants().unwrap();
    mb.check_invariants().unwrap();
    assert_eq!(sorted(ma.diff(&mb)), expected(&a, &b));
    assert_eq!(sorted(mb.diff(&ma)), expected(&b, &a));
    // Shrinking a collision node to one entry inlines it (canonical form).
    let mut c: BTreeMap<(u64, u32), u64> = [((full, 1), 1), ((full, 2), 2)].into_iter().collect();
    let mut mc = build(&c);
    mc.remove(&K(full, 1));
    c.remove(&(full, 1));
    mc.check_invariants().unwrap();
    assert_eq!(mc.identity(), build(&c).identity());
}

#[test]
fn independently_built_maps_diff_the_same_whatever_is_cached() {
    let mut rng = Rng(5);
    let a: BTreeMap<(u64, u32), u64> = (0..3_000u32)
        .map(|i| ((rng.next(), i), u64::from(i)))
        .collect();
    let mut b = a.clone();
    let keys: Vec<_> = a.keys().copied().collect();
    for _ in 0..40 {
        let k = keys[rng.below(keys.len() as u64) as usize];
        if rng.below(2) == 0 {
            b.remove(&k);
        } else {
            b.insert(k, rng.next());
        }
    }
    let want = expected(&a, &b);
    for (warm_a, warm_b) in [(false, false), (true, false), (false, true), (true, true)] {
        let ma = build(&a);
        // Build b in the opposite order, so no node is shared or equal by history.
        let mb: ChampMap<K, u64> = b.iter().rev().map(|(&(h, i), &v)| (K(h, i), v)).collect();
        if warm_a {
            ma.identity();
        }
        if warm_b {
            mb.identity();
        }
        assert_eq!(sorted(ma.diff(&mb)), want, "cached a={warm_a} b={warm_b}");
        assert_eq!(ma.identity() == mb.identity(), want.is_empty());
    }
    // Equal contents built independently: empty diff, equal identity.
    let x = build(&a);
    let y: ChampMap<K, u64> = a.iter().rev().map(|(&(h, i), &v)| (K(h, i), v)).collect();
    assert!(!x.ptr_eq(&y));
    assert!(x.diff(&y).is_empty());
    assert_eq!(x.identity(), y.identity());
}

#[test]
fn historical_snapshots_keep_their_contents_and_identities() {
    let mut rng = Rng(6);
    let mut map: ChampMap<K, u64> = ChampMap::new();
    let mut model: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let mut history: Vec<(ChampMap<K, u64>, Model)> = Vec::new();
    for step in 0..6_000u32 {
        // Small hash space, so collisions and deep prefixes occur.
        let h = rng.below(64) | (rng.below(4) << 40);
        let k = (h, (rng.below(3)) as u32);
        match rng.below(4) {
            0 => {
                map.remove(&K(k.0, k.1));
                model.remove(&k);
            }
            1 => {
                if let Some(v) = map.get_mut(&K(k.0, k.1)) {
                    *v += 1;
                    *model.get_mut(&k).unwrap() += 1;
                }
            }
            _ => {
                let v = rng.next();
                map.insert(K(k.0, k.1), v);
                model.insert(k, v);
            }
        }
        if step % 200 == 0 {
            map.identity(); // warm some snapshots, leave others cold
        }
        if step % 97 == 0 {
            history.push((map.clone(), model.clone()));
        }
    }
    for (i, (snap, snap_model)) in history.iter().enumerate() {
        snap.check_invariants().unwrap();
        assert_eq!(&model_of(snap), snap_model, "snapshot {i} contents");
        assert_eq!(
            snap.identity(),
            build(snap_model).identity(),
            "snapshot {i} identity"
        );
    }
}

#[test]
fn no_op_changes_preserve_content_identity_and_old_snapshots() {
    let base: ChampMap<String, u64> = (0..500u64).map(|i| (format!("k{i}"), i)).collect();
    let id = base.identity();
    // Removing an absent key does not copy anything.
    let mut m = base.clone();
    assert_eq!(m.remove(&"absent".to_string()), None);
    assert!(m.ptr_eq(&base));
    // Re-inserting an equal value copies the path but keeps the identity.
    assert_eq!(m.insert("k7".into(), 7), Some(7));
    assert!(!m.ptr_eq(&base));
    assert_eq!(m.identity(), id);
    // get_mut without a change clears caches but recomputes the same identity.
    let _ = m.get_mut(&"k8".to_string()).unwrap();
    assert_eq!(m.identity(), id);
    assert!(m.diff(&base).is_empty());
    // A real change, then undone, returns to the same identity; base untouched.
    *m.get_mut(&"k8".to_string()).unwrap() = 1_000;
    assert_ne!(m.identity(), id);
    *m.get_mut(&"k8".to_string()).unwrap() = 8;
    assert_eq!(m.identity(), id);
    assert_eq!(base.get(&"k8".to_string()), Some(&8));
    assert_eq!(base.identity(), id);
}

fn check_unchanged(m: &ChampMap<K, u64>, model: &BTreeMap<(u64, u32), u64>, id: [u8; 32]) {
    PANIC_ON_CLONE.with(|c| c.set(false));
    PANIC_ON_CMP.with(|c| c.set(false));
    m.check_invariants().unwrap();
    assert_eq!(&model_of(m), model);
    assert_eq!(m.identity(), id);
}

#[test]
fn a_panic_in_user_code_leaves_the_map_unchanged_and_canonical() {
    let full = 0xabcd_0000_0000_0001;
    // Entries arranged to reach every update path: inline entries, a
    // two-entry sub-trie (removal collapses it), and a collision node.
    let model: BTreeMap<(u64, u32), u64> = [
        ((1, 0), 1),
        ((2, 0), 2),
        ((33, 0), 3), // shares fragment 1 with key hash 1 -> sub-trie of two
        ((full, 0), 4),
        ((full, 1), 5), // collision node
    ]
    .into_iter()
    .collect();
    let operations: Vec<(&str, Operation)> = vec![
        (
            "insert pushing an entry down",
            Box::new(|m| {
                m.insert(K(65, 0), 9);
            }),
        ),
        (
            "insert into collision",
            Box::new(|m| {
                m.insert(K(full, 7), 9);
            }),
        ),
        (
            "replace",
            Box::new(|m| {
                m.insert(K(2, 0), 9);
            }),
        ),
        (
            "remove collapsing a sub-trie",
            Box::new(|m| {
                m.remove(&K(33, 0));
            }),
        ),
        (
            "remove from collision",
            Box::new(|m| {
                m.remove(&K(full, 1));
            }),
        ),
        (
            "remove inline",
            Box::new(|m| {
                m.remove(&K(2, 0));
            }),
        ),
        (
            "get_mut",
            Box::new(|m| {
                if let Some(v) = m.get_mut(&K(33, 0)) {
                    *v = 0;
                }
            }),
        ),
    ];
    let mut panics = 0;
    let mut collapse_panicked = false;
    for (name, op) in &operations {
        let cases = (0..6u32)
            .flat_map(|n| [("clone", false, n), ("clone", true, n)])
            .chain([("cmp", false, 0), ("cmp", true, 0)]);
        for (flag, shared, after) in cases {
            let mut m = build(&model);
            let id = m.identity();
            // With a snapshot alive, updates must copy (and so clone) nodes.
            let snapshot = shared.then(|| m.clone());
            match flag {
                "clone" => {
                    CLONES_BEFORE_PANIC.with(|c| c.set(after));
                    PANIC_ON_CLONE.with(|c| c.set(true));
                }
                _ => PANIC_ON_CMP.with(|c| c.set(true)),
            }
            let result = catch_unwind(AssertUnwindSafe(|| op(&mut m)));
            PANIC_ON_CLONE.with(|c| c.set(false));
            PANIC_ON_CMP.with(|c| c.set(false));
            if result.is_err() {
                panics += 1;
                if *name == "remove collapsing a sub-trie" && flag == "clone" && !shared {
                    collapse_panicked = true;
                }
                check_unchanged(&m, &model, id);
            } else {
                // The operation did not reach user code under this flag
                // (for example no clone was needed); the map must still be valid.
                m.check_invariants().unwrap();
            }
            if let Some(s) = snapshot {
                check_unchanged(&s, &model, id);
            }
        }
    }
    // The interesting paths really did panic mid-operation.
    assert!(collapse_panicked, "collapse path did not reach user Clone");
    assert!(panics >= 30, "only {panics} operations panicked");
}
