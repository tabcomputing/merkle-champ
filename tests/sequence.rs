//! The content-defined sequence prototype (`merkle_champ::sequence`): every
//! edit against a `Vec` model, with the tree checked to be exactly the one
//! building from the elements gives, and how many nodes an edit rewrites.
use merkle_champ::{Identify, Identity, Sequence};
use std::collections::HashSet;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

trait Elem: Clone + PartialEq + std::fmt::Debug + Identify {
    fn from(x: u64) -> Self;
}
impl Elem for u8 {
    fn from(x: u64) -> Self {
        x as u8
    }
}
impl Elem for u64 {
    fn from(x: u64) -> Self {
        x
    }
}
impl Elem for String {
    fn from(x: u64) -> Self {
        format!("s{}", x % 1_000)
    }
}

fn agrees<T: Elem>(s: &Sequence<T>, model: &[T], what: &str) {
    assert_eq!(s.len(), model.len(), "{what}: length");
    assert!(s.iter().eq(model.iter()), "{what}: elements");
    if !model.is_empty() {
        let i = model.len() / 3;
        assert_eq!(s.get(i), Some(&model[i]), "{what}: get");
    }
    s.check_invariants().unwrap_or_else(|e| panic!("{what}: {e}"));
}

/// Random edits of every kind, each checked against the model and against
/// a fresh build of the same elements.
fn edits<T: Elem>(seed: u64, start: usize, steps: usize) {
    let mut rng = Rng(seed);
    let mut model: Vec<T> = (0..start as u64).map(|i| T::from(rng.next() ^ i)).collect();
    let mut s: Sequence<T> = model.iter().cloned().collect();
    agrees(&s, &model, "built");
    for step in 0..steps {
        let n = model.len();
        let what = match rng.below(8) {
            0 => {
                let i = rng.below(n + 1);
                let x = T::from(rng.next());
                s = s.insert(i, x.clone());
                model.insert(i, x);
                "insert"
            }
            1 if n > 0 => {
                let i = rng.below(n);
                s = s.remove(i);
                model.remove(i);
                "remove"
            }
            2 if n > 0 => {
                let i = rng.below(n);
                let x = T::from(rng.next());
                s = s.update(i, x.clone());
                model[i] = x;
                "update"
            }
            3 => {
                let a = rng.below(n + 1);
                let b = a + rng.below(n - a + 1).min(200);
                let new: Vec<T> = (0..rng.below(300)).map(|_| T::from(rng.next())).collect();
                s = s.splice(a..b, new.iter().cloned());
                model.splice(a..b, new);
                "splice"
            }
            4 => {
                let extra: Vec<T> = (0..rng.below(2_000)).map(|_| T::from(rng.next())).collect();
                let other: Sequence<T> = extra.iter().cloned().collect();
                if rng.below(2) == 0 {
                    s = s.concat(&other);
                    model.extend(extra);
                } else {
                    s = other.concat(&s);
                    model.splice(0..0, extra);
                }
                "concat"
            }
            5 if n > 0 => {
                // Trim up to 200 from each end, so the tree stays large.
                let a = rng.below(n.min(200));
                let b = n - rng.below((n - a).min(200));
                s = s.slice(a..b);
                model = model[a..b].to_vec();
                "slice"
            }
            _ => {
                let x = T::from(rng.next());
                s = s.pushed(x.clone());
                model.push(x);
                "push"
            }
        };
        agrees(&s, &model, &format!("step {step}, {what}"));
    }
    // The sequence stayed about as large as it started.
    assert!(model.len() >= start / 2, "shrank to {}", model.len());
}

#[test]
fn every_edit_gives_the_canonical_tree() {
    // Trees of heights 1 to 3 for each kind of leaf.
    edits::<String>(1, 3_000, 300);
    edits::<String>(4, 40_000, 100);
    edits::<u64>(2, 20_000, 200);
    edits::<u64>(5, 250_000, 60);
    edits::<u8>(3, 40_000, 200);
    edits::<u8>(6, 1_200_000, 30);
}

#[test]
fn small_and_empty_sequences() {
    let empty: Sequence<u64> = Sequence::new();
    assert!(empty.is_empty());
    assert_eq!(empty.identity(), Sequence::<u64>::new().identity());
    let one = empty.pushed(7);
    agrees(&one, &[7], "one");
    assert!(one.remove(0).is_empty());
    assert_eq!(one.remove(0).identity(), empty.identity());
    let s: Sequence<u64> = (0..100).collect();
    assert!(s.slice(10..10).is_empty());
    agrees(&s.slice(0..100), &(0..100).collect::<Vec<_>>(), "whole slice");
}

/// How many of `new`'s nodes `old` does not have.
fn fresh<T: Elem>(old: &Sequence<T>, new: &Sequence<T>) -> usize {
    let old: HashSet<Identity> = old.node_ids().into_iter().collect();
    new.node_ids().iter().filter(|id| !old.contains(*id)).count()
}

#[test]
fn edits_rewrite_few_nodes() {
    // A million bytes: an insert, remove or update anywhere rewrites a few
    // nodes per level, not everything after it.
    let mut rng = Rng(11);
    let bytes: Vec<u8> = (0..1_000_000).map(|_| rng.next() as u8).collect();
    let s: Sequence<u8> = bytes.iter().copied().collect();
    let total = s.node_ids().len();
    let height = s.height();
    for i in [0, 1_000, 500_000, 999_999] {
        for (what, t) in [
            ("insert", s.insert(i, 42)),
            ("remove", s.remove(i)),
            ("update", s.update(i, 42)),
        ] {
            let n = fresh(&s, &t);
            assert!(n <= 4 * (height + 1), "{what} at {i}: {n} new nodes of {total}, height {height}");
        }
    }
    // Joining two halves and slicing share nearly everything too.
    let a = s.slice(0..600_000);
    let b = s.slice(600_000..1_000_000);
    let joined = a.concat(&b);
    assert_eq!(joined.identity(), s.identity());
    assert!(fresh(&a, &s.slice(0..600_000)) == 0);
    assert!(fresh(&s, &a) <= 4 * (height + 1));
}

#[test]
fn history_does_not_matter() {
    // Built in one go, grown by inserts in random places, and assembled from
    // pieces: one tree.
    let mut rng = Rng(9);
    let model: Vec<u64> = (0..5_000).map(|_| rng.next()).collect();
    let direct: Sequence<u64> = model.iter().copied().collect();
    let mut grown: Sequence<u64> = Sequence::new();
    let mut order: Vec<usize> = (0..model.len()).collect();
    // Insert elements in a shuffled order, each at its rank among those
    // already present, so the final order is the model's.
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i + 1));
    }
    let mut present: Vec<usize> = Vec::new();
    for &k in &order {
        let at = present.partition_point(|&p| p < k);
        present.insert(at, k);
        grown = grown.insert(at, model[k]);
    }
    assert_eq!(grown.identity(), direct.identity());
    let pieces = model
        .chunks(777)
        .map(|c| c.iter().copied().collect::<Sequence<u64>>())
        .fold(Sequence::new(), |acc, p| acc.concat(&p));
    assert_eq!(pieces.identity(), direct.identity());
}
