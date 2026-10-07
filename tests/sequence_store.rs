//! Storing sequences as their identity preimages and loading them back
//! (FORMAT.md, section 10.8).

use merkle_champ::{
    ChampMap, Decode, DecodeError, Identify, Identity, Loader, Objects, Sequence, Sink, pack,
    read_tagged, write_tagged,
};
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
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A file chunk's reference, as transfs keeps a version's chunk list: one
/// measure, the chunk's length, so a stored branch finds the chunk holding a
/// byte offset.
#[derive(Clone, Debug, PartialEq)]
struct ChunkRef {
    id: Identity,
    len: u64,
}

impl Identify for ChunkRef {
    fn identify<S: Sink + ?Sized>(&self, sink: &mut S) {
        let mut b = self.id.to_vec();
        b.extend_from_slice(&self.len.to_le_bytes());
        write_tagged(sink, b'C', &b);
    }
    const MEASURES: usize = 1;
    fn measure(&self, sums: &mut [u64]) {
        sums[0] += self.len;
    }
}

impl Decode for ChunkRef {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        let b = read_tagged(input, b'C')?;
        if b.len() != 40 {
            return Err(DecodeError::Malformed(
                "a chunk reference of the wrong length",
            ));
        }
        Ok(ChunkRef {
            id: b[..32].try_into().unwrap(),
            len: u64::from_le_bytes(b[32..].try_into().unwrap()),
        })
    }
}

fn chunks(n: usize, seed: u64) -> Sequence<ChunkRef> {
    let mut rng = Rng(seed);
    (0..n)
        .map(|_| ChunkRef {
            id: Sha256::digest(rng.next().to_le_bytes()).into(),
            len: 4096 + rng.next() % 12288,
        })
        .collect()
}

/// Saves, loads, and checks that the loaded sequence is the saved one.
fn round_trip<T: Clone + Identify + Decode + PartialEq + std::fmt::Debug>(
    s: &Sequence<T>,
) -> Sequence<T> {
    let mut objects = Objects::new();
    let id = s.save(&mut objects);
    assert_eq!(id, s.identity());
    let loaded = Sequence::<T>::load(&id, &objects).unwrap();
    assert_eq!(loaded.identity(), s.identity());
    assert_eq!(loaded.len(), s.len());
    assert_eq!(loaded.height(), s.height());
    assert_eq!(loaded.measures(), s.measures());
    assert!(loaded.iter().eq(s.iter()));
    loaded.check_invariants().unwrap();
    loaded
}

#[test]
fn round_trips_preserve_contents_identity_and_shape() {
    let mut rng = Rng(1);
    for n in [0, 1, 100, 10_000, 200_000] {
        let s: Sequence<u64> = (0..n).map(|_| rng.next()).collect();
        round_trip(&s);
    }
    for n in [0, 5_000, 300_000] {
        let s: Sequence<u8> = (0..n).map(|_| rng.next() as u8).collect();
        round_trip(&s);
    }
    for n in [1, 40, 5_000] {
        let s: Sequence<String> = (0..n).map(|i| format!("item {i}")).collect();
        round_trip(&s);
    }
    let s: Sequence<f64> = (0..3_000).map(|i| i as f64 / 7.0).collect();
    round_trip(&s);
    let text: String = (0..2_000).map(|i| format!("line {i} é中😀\n")).collect();
    let loaded = round_trip(&Sequence::text(&text));
    assert_eq!(loaded.to_text().unwrap(), text);
    assert_eq!(loaded.char_at(12_345), text.chars().nth(12_345));
    round_trip(&chunks(50_000, 2));
}

#[test]
fn edits_to_a_loaded_sequence_match_edits_to_the_saved_one() {
    // Loading recomputes each node's cut level, which the stored bytes leave
    // out and edits rely on.
    let mut rng = Rng(3);
    let s: Sequence<u64> = (0..50_000).map(|_| rng.next() % 1000).collect();
    let loaded = round_trip(&s);
    for _ in 0..30 {
        let i = rng.below(s.len());
        let j = i + rng.below(s.len() - i);
        let x = rng.next();
        assert_eq!(loaded.insert(i, x).identity(), s.insert(i, x).identity());
        assert_eq!(loaded.remove(i).identity(), s.remove(i).identity());
        assert_eq!(loaded.update(i, x).identity(), s.update(i, x).identity());
        assert_eq!(loaded.slice(i..j).identity(), s.slice(i..j).identity());
        assert_eq!(loaded.concat(&s).identity(), s.concat(&s).identity());
    }
    let c = chunks(20_000, 4);
    let loaded = round_trip(&c);
    let extra = ChunkRef {
        id: [7; 32],
        len: 100,
    };
    assert_eq!(
        loaded.insert(9_999, extra.clone()).identity(),
        c.insert(9_999, extra).identity()
    );
    // A byte offset finds its chunk through the stored measures.
    assert_eq!(loaded.locate(0, 50_000_000), c.locate(0, 50_000_000));
}

#[test]
fn saving_a_new_version_adds_only_the_nodes_an_edit_rewrote() {
    let mut rng = Rng(5);
    let s: Sequence<u64> = (0..100_000).map(|_| rng.next()).collect();
    let mut objects = Objects::new();
    s.save(&mut objects);
    let before = objects.len();
    let t = s.insert(50_000, 7);
    let id = t.save(&mut objects);
    // The new header, and a few nodes on each level near the insert.
    let added = objects.len() - before;
    assert!(added <= 3 * (t.height() + 1) + 1, "added {added}");
    assert_eq!(
        Sequence::<u64>::load(&id, &objects).unwrap().identity(),
        t.identity()
    );
}

#[test]
fn repeated_chunks_are_stored_and_loaded_once() {
    // A million equal bytes: equal leaves, equal branches.
    let s: Sequence<u8> = std::iter::repeat_n(0u8, 1_000_000).collect();
    let mut objects = Objects::new();
    let id = s.save(&mut objects);
    assert!(objects.len() < 10, "{} objects", objects.len());
    let loaded = Sequence::<u8>::load(&id, &objects).unwrap();
    assert_eq!(loaded.len(), 1_000_000);
    assert_eq!(loaded.identity(), s.identity());
    assert_eq!(loaded.pushed(1).identity(), s.pushed(1).identity());
}

#[test]
fn sequences_nest_in_maps_and_sequences() {
    let mut map: ChampMap<String, Sequence<u64>> = ChampMap::new();
    for k in 0..50u64 {
        map.insert(format!("file {k}"), (0..k * 100).collect());
    }
    let mut objects = Objects::new();
    let id = map.save(&mut objects);
    let loaded = ChampMap::<String, Sequence<u64>>::load(&id, &objects).unwrap();
    assert_eq!(loaded.identity(), map.identity());
    assert_eq!(
        loaded.get(&"file 7".to_string()).unwrap().get(699),
        Some(&699)
    );

    // Sequences of sequences, with repeats.
    let inner: Vec<Sequence<u8>> = (0..10)
        .map(|k| (0..k * 300).map(|i| i as u8).collect())
        .collect();
    let s: Sequence<Sequence<u8>> = (0..200).map(|i| inner[i % 10].clone()).collect();
    let loaded = round_trip(&s);
    assert_eq!(loaded.get(57).unwrap().len(), 7 * 300);
}

#[test]
fn a_saved_sequence_travels_in_a_pack() {
    let s = chunks(30_000, 6);
    let mut objects = Objects::new();
    let id = s.save(&mut objects);
    let bytes = pack::encode(&[id], &objects).unwrap();
    let p = pack::decode(&bytes).unwrap();
    assert_eq!(p.objects, objects);
    assert_eq!(
        Sequence::<ChunkRef>::load(&id, &p.objects)
            .unwrap()
            .identity(),
        s.identity()
    );
}

fn header(len: u64, root: Option<Identity>) -> Vec<u8> {
    let mut b = b"merkle-champ/sequence/v1".to_vec();
    b.extend_from_slice(&len.to_le_bytes());
    if let Some(r) = root {
        b.extend_from_slice(&r);
    }
    b
}

#[test]
fn malformed_and_non_canonical_trees_are_rejected() {
    use DecodeError::{Malformed, Missing, NonCanonical};
    // The elements of a canonical tree of several leaves, stored as one leaf.
    let items: Vec<String> = (0..100).map(|i| format!("item {i}")).collect();
    let s: Sequence<String> = items.iter().cloned().collect();
    assert!(s.height() > 0);
    let mut leaf = b"merkle-champ/sequence/leaf/v1".to_vec();
    leaf.extend_from_slice(&100u16.to_le_bytes());
    for item in &items {
        item.identify(&mut leaf);
    }
    let mut objects = Objects::new();
    let leaf_id = objects.insert(leaf);
    let id = objects.insert(header(100, Some(leaf_id)));
    assert!(matches!(
        Sequence::<String>::load(&id, &objects),
        Err(NonCanonical(_))
    ));

    // A recorded length that differs from the tree's.
    let mut objects = Objects::new();
    let good = s.save(&mut objects);
    let root = objects.get(&good).unwrap()[32..].try_into().unwrap();
    let id = objects.insert(header(101, Some(root)));
    assert!(matches!(
        Sequence::<String>::load(&id, &objects),
        Err(NonCanonical(_))
    ));
    // Trailing bytes, a missing node, another element type.
    let mut bytes = header(100, Some(root));
    bytes.push(0);
    let id = objects.insert(bytes);
    assert!(matches!(
        Sequence::<String>::load(&id, &objects),
        Err(Malformed(_))
    ));
    let id = objects.insert(header(100, Some([9; 32])));
    assert_eq!(
        Sequence::<String>::load(&id, &objects).err(),
        Some(Missing([9; 32]))
    );
    assert!(matches!(
        Sequence::<u64>::load(&good, &objects),
        Err(Malformed(_))
    ));
    let mut objects = Objects::new();
    let numbers = (0..1000u64).collect::<Sequence<u64>>().save(&mut objects);
    assert!(matches!(
        Sequence::<u32>::load(&numbers, &objects),
        Err(Malformed(_))
    ));
    assert!(matches!(
        Sequence::<String>::load(&numbers, &objects),
        Err(Malformed(_))
    ));

    // A root branch over a single leaf.
    let small: Sequence<u64> = (0..5).collect();
    let mut objects = Objects::new();
    let small_id = small.save(&mut objects);
    let leaf_id: Identity = objects.get(&small_id).unwrap()[32..].try_into().unwrap();
    let mut branch = b"merkle-champ/sequence/branch/v1".to_vec();
    branch.extend_from_slice(&1u16.to_le_bytes());
    branch.extend_from_slice(&5u64.to_le_bytes());
    branch.extend_from_slice(&leaf_id);
    let branch_id = objects.insert(branch);
    let id = objects.insert(header(5, Some(branch_id)));
    assert!(matches!(
        Sequence::<u64>::load(&id, &objects),
        Err(NonCanonical(_))
    ));

    // The empty sequence, and something that is not a sequence.
    let mut objects = Objects::new();
    let empty = Sequence::<u64>::new().save(&mut objects);
    assert!(Sequence::<u64>::load(&empty, &objects).unwrap().is_empty());
    let other = objects.insert(b"not a sequence".to_vec());
    assert!(matches!(
        Sequence::<u64>::load(&other, &objects),
        Err(Malformed(_))
    ));
}
