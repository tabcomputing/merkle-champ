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

// ------------------------------------------------- an independent reference

/// FORMAT.md section 10, written plainly: the rolling hash at every
/// position, then leaves, then branch levels, then identities. It shares no
/// code with `src/sequence.rs`.
mod reference {
    use sha2::{Digest, Sha256};

    pub fn mix64(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^ (h >> 33)
    }

    /// What the reference needs of an element type.
    pub trait Item {
        /// Elements in a leaf, before the minimum and maximum.
        const TARGET: usize;
        fn print(&self) -> u64;
        /// The leaf's identity preimage after its domain.
        fn leaf(items: &[Self]) -> (&'static [u8], Vec<u8>)
        where
            Self: Sized;
    }

    fn word_print(w: u64) -> u64 {
        mix64(w ^ 0x9e37_79b9_7f4a_7c15) | 1
    }

    fn packed(tag: u8, width: u8, count: usize, bytes: Vec<u8>) -> (&'static [u8], Vec<u8>) {
        let mut out = vec![tag, width];
        out.extend((count as u16).to_le_bytes());
        out.extend(bytes);
        (b"merkle-champ/sequence/packed-leaf/v1", out)
    }

    impl Item for u64 {
        const TARGET: usize = 128;
        fn print(&self) -> u64 {
            word_print(*self)
        }
        fn leaf(items: &[u64]) -> (&'static [u8], Vec<u8>) {
            packed(b'u', 8, items.len(), items.iter().flat_map(|x| x.to_le_bytes()).collect())
        }
    }

    impl Item for u8 {
        const TARGET: usize = 1_024;
        fn print(&self) -> u64 {
            word_print(u64::from(*self))
        }
        fn leaf(items: &[u8]) -> (&'static [u8], Vec<u8>) {
            packed(b'u', 1, items.len(), items.to_vec())
        }
    }

    /// A string's encoding: tag `s`, its length as u64, its bytes.
    fn encode(s: &str) -> Vec<u8> {
        let mut e = vec![b's'];
        e.extend((s.len() as u64).to_le_bytes());
        e.extend(s.as_bytes());
        e
    }

    impl Item for String {
        const TARGET: usize = 32;
        fn print(&self) -> u64 {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in encode(self) {
                h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            mix64(h) | 1
        }
        fn leaf(items: &[String]) -> (&'static [u8], Vec<u8>) {
            let mut out = (items.len() as u16).to_le_bytes().to_vec();
            for s in items {
                out.extend(encode(s));
            }
            (b"merkle-champ/sequence/leaf/v1", out)
        }
    }

    fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn level(h: u64, hit_bits: u32) -> i32 {
        let z = h.leading_zeros();
        if z < hit_bits { -1 } else { ((z - hit_bits) / 5) as i32 }
    }

    /// (identity, length, end level) of each node of the tree, by level.
    pub fn levels<T: Item>(xs: &[T]) -> Vec<Vec<([u8; 32], u64, i32)>> {
        let (min, max) = (T::TARGET / 4, T::TARGET * 4);
        let hit_bits = T::TARGET.trailing_zeros();
        let mut h = 0u64;
        let lv: Vec<i32> = xs
            .iter()
            .map(|x| {
                h = (h << 1).wrapping_add(x.print());
                level(h, hit_bits)
            })
            .collect();
        let mut nodes = Vec::new();
        let mut start = 0;
        for i in 0..xs.len() {
            let count = i - start + 1;
            if (count >= min && lv[i] >= 0) || count == max || i + 1 == xs.len() {
                let (domain, body) = T::leaf(&xs[start..=i]);
                nodes.push((sha(&[domain, &body]), count as u64, lv[i]));
                start = i + 1;
            }
        }
        let mut all = vec![nodes.clone()];
        let mut level_no = 1;
        while nodes.len() > 1 {
            let mut next = Vec::new();
            let mut group: Vec<([u8; 32], u64, i32)> = Vec::new();
            for (k, node) in nodes.iter().enumerate() {
                group.push(*node);
                let n = group.len();
                if (n >= 2 && node.2 >= level_no) || n == 128 || k + 1 == nodes.len() {
                    let mut body = (n as u16).to_le_bytes().to_vec();
                    for (id, len, _) in &group {
                        body.extend(len.to_le_bytes());
                        body.extend(id);
                    }
                    let id = sha(&[b"merkle-champ/sequence/branch/v1", &body]);
                    let len = group.iter().map(|g| g.1).sum();
                    next.push((id, len, node.2));
                    group.clear();
                }
            }
            nodes = next;
            all.push(nodes.clone());
            level_no += 1;
        }
        all
    }

    pub fn identity<T: Item>(xs: &[T]) -> [u8; 32] {
        let len = (xs.len() as u64).to_le_bytes();
        match levels(xs).last().and_then(|top| top.first()) {
            Some((root, _, _)) => sha(&[b"merkle-champ/sequence/v1", &len, root]),
            None => sha(&[b"merkle-champ/sequence/v1", &len]),
        }
    }
}

use reference::Item;

fn matches_reference<T: Elem + Item>(xs: &[T], what: &str) {
    let s: Sequence<T> = xs.iter().cloned().collect();
    assert_eq!(s.identity(), reference::identity(xs), "{what}: built");
}

#[test]
fn identities_follow_the_reference() {
    let mut rng = Rng(77);
    for len in [0, 1, 2, 7, 8, 31, 32, 33, 64, 65, 127, 128, 129, 1_000, 4_000, 20_000, 300_000] {
        let xs: Vec<u64> = (0..len).map(|_| rng.next()).collect();
        matches_reference(&xs, &format!("u64 x {len}"));
        let bs: Vec<u8> = xs.iter().map(|&x| x as u8).collect();
        matches_reference(&bs, &format!("u8 x {len}"));
        let ss: Vec<String> = xs.iter().take(40_000).map(|x| (x % 977).to_string()).collect();
        matches_reference(&ss, &format!("strings x {}", ss.len()));
    }
}

/// The values the rolling hash settles to in a long repetition of
/// `pattern`, one per position of the pattern.
fn settled<T: Item>(pattern: &[T]) -> Vec<u64> {
    let mut h = 0u64;
    let mut out = Vec::new();
    for k in 0..64 + 2 * pattern.len() {
        h = (h << 1).wrapping_add(pattern[k % pattern.len()].print());
        if k >= 64 + pattern.len() {
            out.push(h);
        }
    }
    out
}

/// A repeating pattern, among `candidates`, whose run cuts at least
/// `min_level` levels above the leaves at some position of each repetition.
fn hot_pattern<T: Item + Elem>(candidates: impl Iterator<Item = Vec<T>>, min_level: u32) -> Vec<T> {
    let need = T::TARGET.trailing_zeros() + 5 * min_level;
    candidates
        .take(1 << 22)
        .find(|p| settled(p).iter().any(|h| h.leading_zeros() >= need))
        .expect("a hot pattern among the candidates")
}

/// A value whose run never cuts: leaves end only at the maximum size.
fn cold_value<T: Item + Elem>() -> T {
    let hit_bits = T::TARGET.trailing_zeros();
    (0u64..1 << 20)
        .map(T::from)
        .find(|v| settled(std::slice::from_ref(v))[0].leading_zeros() < hit_bits)
        .expect("a cold value")
}

/// Runs of `v` between random stretches, edited at the seams and inside.
fn runs<T: Elem + Item>(pattern: Vec<T>, run: usize, what: &str) {
    let mut rng = Rng(5);
    let mut model: Vec<T> = (0..500).map(|_| T::from(rng.next())).collect();
    model.extend(pattern.iter().cycle().take(run).cloned());
    model.extend((0..500).map(|_| T::from(rng.next())));
    model.extend(pattern.iter().cycle().take(run / 3).cloned());
    matches_reference(&model, what);
    let s: Sequence<T> = model.iter().cloned().collect();
    // The height stays logarithmic, even where every position cuts.
    assert!(s.height() <= 2 * (usize::BITS - model.len().leading_zeros()) as usize);
    for i in [0, 499, 500, 501, 500 + run / 2, 500 + run - 1, 500 + run, model.len() - 1] {
        let x = T::from(rng.next());
        let mut m = model.clone();
        m.insert(i, x.clone());
        let t = s.insert(i, x.clone());
        assert_eq!(t.identity(), reference::identity(&m), "{what}: insert at {i}");
        let mut m = model.clone();
        m.remove(i);
        assert_eq!(s.remove(i).identity(), reference::identity(&m), "{what}: remove at {i}");
        let mut m = model.clone();
        m[i] = x.clone();
        assert_eq!(s.update(i, x).identity(), reference::identity(&m), "{what}: update at {i}");
    }
}

#[test]
fn runs_of_equal_elements() {
    // Never cutting, so leaves end at the maximum; cutting at every position,
    // at the leaf level and two branch levels above.
    runs(vec![cold_value::<u64>()], 20_000, "cold u64");
    runs(hot_pattern::<u64>((0u64..).map(|x| vec![x]), 2), 20_000, "hot u64");
    runs(vec![cold_value::<u8>()], 60_000, "cold u8");
    // A byte has only 256 values, so the hot pattern is two bytes long, and
    // cuts leaves at every chance; a branch level too would need 15 zero
    // bits, which no pair reaches.
    let pairs = (0u64..65_536).map(|x| vec![x as u8, (x >> 8) as u8]);
    runs(hot_pattern::<u8>(pairs, 0), 60_000, "hot u8");
    runs(vec![cold_value::<String>()], 3_000, "cold strings");
    // Distinct candidates: the test's strings repeat every thousand.
    let strings = (0u64..).map(|x| vec![format!("hot {x}")]);
    runs(hot_pattern::<String>(strings, 2), 3_000, "hot strings");
}

#[test]
fn periodic_contents() {
    // Repeating patterns of every short period, which line up with the
    // rolling hash's window in different ways.
    for period in [1, 2, 3, 7, 32, 63, 64, 65, 128, 1_000] {
        let xs: Vec<u64> = (0..30_000u64).map(|i| (i % period) * 0x9E37_79B9).collect();
        matches_reference(&xs, &format!("period {period}"));
        let s: Sequence<u64> = xs.iter().copied().collect();
        let mut m = xs.clone();
        m.insert(15_000, 1);
        assert_eq!(s.insert(15_000, 1).identity(), reference::identity(&m), "period {period}");
    }
}

#[test]
fn golden_identities() {
    // Pinned, so any change to the format shows; FORMAT.md 10.6 gives them.
    let xs: Vec<u64> = (0..1_000).collect();
    let bytes: Vec<u8> = (0..5_000u32).map(|i| (i * 7 % 256) as u8).collect();
    let strings: Vec<String> = (0..100).map(|i| format!("item {i}")).collect();
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let got = [
        hex(xs.iter().copied().collect::<Sequence<u64>>().identity()),
        hex(bytes.iter().copied().collect::<Sequence<u8>>().identity()),
        hex(strings.iter().cloned().collect::<Sequence<String>>().identity()),
        hex(Sequence::<u64>::new().identity()),
    ];
    assert_eq!(got, GOLDEN);
    // The reference agrees.
    assert_eq!(hex(reference::identity(&xs)), GOLDEN[0]);
    assert_eq!(hex(reference::identity(&bytes)), GOLDEN[1]);
    assert_eq!(hex(reference::identity(&strings)), GOLDEN[2]);
    assert_eq!(hex(reference::identity::<u64>(&[])), GOLDEN[3]);
}

const GOLDEN: [&str; 4] = [
    "7a25cee465767ef587d2a0dd984ccf06fb5ec95d94504665282822413c972970",
    "dba099dab8dd20cde67d061f0558ebf40bfd1925a7ed03259d80c55bab9d8ec0",
    "19dc2f35f57068d900061e75043868be820242dd773aa5057cae757db6e18266",
    "06b6c643f3db9aaa0a211a969915be4d471aa54a0f3af8202570dc23ac0a0b20",
];

#[test]
fn sequences_nest_through_identify() {
    use merkle_champ::ChampMap;
    let inner: Sequence<u64> = (0..40).collect();
    let outer: Sequence<Sequence<u64>> = [inner.clone(), Sequence::new()].into_iter().collect();
    let again: Sequence<Sequence<u64>> =
        [(0..40).collect(), Sequence::new()].into_iter().collect();
    assert_eq!(outer.identity(), again.identity());
    // In a map too: the encoding is the tag `v` and the identity.
    let mut encoding = Vec::new();
    inner.identify(&mut encoding);
    assert_eq!(encoding[0], b'v');
    assert_eq!(&encoding[9..], &inner.identity());
    let map: ChampMap<String, Sequence<u64>> = [("xs".to_string(), inner)].into_iter().collect();
    let map2: ChampMap<String, Sequence<u64>> =
        [("xs".to_string(), (0..40).collect())].into_iter().collect();
    assert_eq!(map.identity(), map2.identity());
}

#[test]
fn the_builder_is_collect() {
    let mut b = merkle_champ::sequence::Builder::new();
    for i in 0..10_000u64 {
        b.push(i);
    }
    let s = b.build();
    assert_eq!(s.identity(), (0..10_000u64).collect::<Sequence<u64>>().identity());
}
