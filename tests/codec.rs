//! Storing maps as their identity preimages and loading them back
//! (FORMAT.md, section 9).

use merkle_champ::{
    ChampMap, ChampSet, Decode, DecodeError, Identify, Identity, KeyHash, Loader, Objects,
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
}

fn random_map(n: usize, seed: u64) -> ChampMap<String, u64> {
    let mut rng = Rng(seed);
    let mut map = ChampMap::new();
    for i in 0..n {
        map.insert(format!("k{}", rng.next() % (n as u64 * 2 + 1)), i as u64);
        if rng.next().is_multiple_of(5) {
            map.remove(&format!("k{}", rng.next() % (n as u64 * 2 + 1)));
        }
    }
    map
}

fn node_count<K: KeyHash + Ord + Clone, V: Clone>(map: &ChampMap<K, V>) -> usize {
    map.layout_stats().1.iter().sum()
}

#[test]
fn round_trips_preserve_contents_identity_and_shape() {
    for (n, seed) in [(0, 1), (1, 2), (2, 3), (33, 4), (1_000, 5), (20_000, 6)] {
        let map = random_map(n, seed);
        let mut objects = Objects::new();
        let root = map.save(&mut objects);
        assert_eq!(root, map.identity());
        assert_eq!(objects.len(), node_count(&map), "one object per node");
        let loaded: ChampMap<String, u64> = ChampMap::load(&root, &objects).unwrap();
        loaded.check_invariants().unwrap();
        assert_eq!(loaded, map);
        assert_eq!(loaded.len(), map.len());
        assert_eq!(loaded.identity(), root);
        assert!(loaded.iter().eq(map.iter()), "same trie order");
    }
}

#[test]
fn every_provided_type_round_trips() {
    let a: ChampMap<u64, Vec<u8>> = (0..500u64)
        .map(|i| (i, vec![i as u8; i as usize % 7]))
        .collect();
    let b: ChampMap<i64, ()> = (-250..250i64).map(|i| (i, ())).collect();
    let c: ChampMap<String, Identity> = (0..300u16)
        .map(|i| (format!("é{i}"), [i as u8; 32]))
        .collect();
    let mut objects = Objects::new();
    let (ra, rb, rc) = (
        a.save(&mut objects),
        b.save(&mut objects),
        c.save(&mut objects),
    );
    assert_eq!(ChampMap::<u64, Vec<u8>>::load(&ra, &objects).unwrap(), a);
    assert_eq!(ChampMap::<i64, ()>::load(&rb, &objects).unwrap(), b);
    assert_eq!(
        ChampMap::<String, Identity>::load(&rc, &objects).unwrap(),
        c
    );
}

#[test]
fn stored_bytes_are_the_identity_preimage() {
    let mut objects = Objects::new();
    let empty: ChampMap<String, u64> = ChampMap::new();
    let root = empty.save(&mut objects);
    let mut preimage = b"merkle-champ/branch/v1".to_vec();
    preimage.extend([0u8; 8]);
    assert_eq!(preimage.len(), 30);
    assert_eq!(objects.get(&root), Some(&preimage[..]));
    assert_eq!(root, <[u8; 32]>::from(Sha256::digest(&preimage)));
    // Every object's key is the hash of its bytes.
    random_map(2_000, 7).save(&mut objects);
    for (id, bytes) in objects.iter() {
        assert_eq!(*id, <[u8; 32]>::from(Sha256::digest(bytes)));
    }
}

#[test]
fn equal_maps_save_identical_object_sets() {
    let forward: ChampMap<u64, u64> = (0..3_000).map(|i| (i, i * i)).collect();
    let backward: ChampMap<u64, u64> = (0..3_000).rev().map(|i| (i, i * i)).collect();
    let (mut a, mut b) = (Objects::new(), Objects::new());
    forward.save(&mut a);
    backward.save(&mut b);
    assert_eq!(a, b);
    assert!(a.iter().map(|(id, _)| id).is_sorted(), "identity order");
}

#[test]
fn saving_a_new_version_adds_only_changed_paths() {
    let v1: ChampMap<u64, u64> = (0..50_000).map(|i| (i, i)).collect();
    let mut objects = Objects::new();
    v1.save(&mut objects);
    let before = objects.len();
    assert_eq!(
        v1.save(&mut objects),
        v1.identity(),
        "saving again is a no-op"
    );
    assert_eq!(objects.len(), before);
    let v2 = v1.update(12_345, 0);
    let r2 = v2.save(&mut objects);
    let added = objects.len() - before;
    assert!((1..=5).contains(&added), "added {added} objects");
    // Both versions remain loadable from the shared set.
    assert_eq!(ChampMap::<u64, u64>::load(&r2, &objects).unwrap(), v2);
    assert_eq!(
        ChampMap::<u64, u64>::load(&v1.identity(), &objects).unwrap(),
        v1
    );
}

#[test]
fn nested_maps_and_sets_are_stored_as_their_own_trees() {
    let inner: ChampMap<String, u64> = [("x".to_string(), 1), ("y".into(), 2)]
        .into_iter()
        .collect();
    let tags: ChampSet<String> = ["red".to_string(), "blue".into()].into_iter().collect();
    let mut outer: ChampMap<String, ChampMap<String, u64>> = ChampMap::new();
    outer.insert("a".into(), inner.clone());
    outer.insert("b".into(), inner.clone());
    outer.insert("c".into(), ChampMap::new());
    let mut objects = Objects::new();
    let root = outer.save(&mut objects);
    assert!(objects.contains(&inner.identity()));
    let loaded: ChampMap<String, ChampMap<String, u64>> = ChampMap::load(&root, &objects).unwrap();
    assert_eq!(loaded, outer);
    // A nested map referenced twice is loaded once and shared.
    let (a, b) = (
        &loaded.get(&"a".into()).unwrap(),
        &loaded.get(&"b".into()).unwrap(),
    );
    assert!(a.ptr_eq(b));

    let mut with_sets: ChampMap<u64, ChampSet<String>> = ChampMap::new();
    with_sets.insert(1, tags.clone());
    with_sets.insert(2, ChampSet::new());
    let root = with_sets.save(&mut objects);
    assert_eq!(
        ChampMap::<u64, ChampSet<String>>::load(&root, &objects).unwrap(),
        with_sets
    );
    let set_root = tags.save(&mut objects);
    assert_eq!(ChampSet::<String>::load(&set_root, &objects).unwrap(), tags);
}

/// A value that is either a number or another map, so maps can nest to any
/// depth. It reuses the provided encodings (`u` and `m`).
#[derive(Clone, PartialEq, Debug)]
enum Tree {
    Leaf(u64),
    Map(ChampMap<String, Tree>),
}
impl Identify for Tree {
    fn identify<S: merkle_champ::Sink + ?Sized>(&self, sink: &mut S) {
        match self {
            Tree::Leaf(n) => n.identify(sink),
            Tree::Map(m) => m.identify(sink),
        }
    }
    fn save_objects(&self, objects: &mut Objects) {
        if let Tree::Map(m) = self {
            m.save(objects);
        }
    }
}
impl Decode for Tree {
    fn decode(input: &mut &[u8], loader: &mut Loader<'_>) -> Result<Self, DecodeError> {
        match input.first() {
            Some(b'u') => u64::decode(input, loader).map(Tree::Leaf),
            Some(b'm') => ChampMap::decode(input, loader).map(Tree::Map),
            _ => Err(DecodeError::Malformed("unexpected type tag")),
        }
    }
}

/// Nests `depth` maps, each holding the next one under two keys.
fn doubling_chain(depth: usize) -> ChampMap<String, Tree> {
    let mut map: ChampMap<String, Tree> =
        [("leaf".to_string(), Tree::Leaf(7))].into_iter().collect();
    for _ in 0..depth {
        map = [
            ("l".to_string(), Tree::Map(map.clone())),
            ("r".into(), Tree::Map(map)),
        ]
        .into_iter()
        .collect();
    }
    map
}

#[test]
fn shared_nested_maps_load_once_even_when_referenced_exponentially() {
    // 2^60 paths through 61 distinct maps: loading must follow identities,
    // not paths.
    let map = doubling_chain(60);
    let mut objects = Objects::new();
    let root = map.save(&mut objects);
    assert!(objects.len() < 200, "{} objects", objects.len());
    let loaded: ChampMap<String, Tree> = ChampMap::load(&root, &objects).unwrap();
    assert_eq!(loaded.identity(), root);
    let (Tree::Map(l), Tree::Map(r)) = (
        loaded.get(&"l".into()).unwrap(),
        loaded.get(&"r".into()).unwrap(),
    ) else {
        panic!("expected maps")
    };
    assert!(l.ptr_eq(r));
}

#[test]
fn nesting_deeper_than_the_limit_is_rejected() {
    let mut objects = Objects::new();
    let ok = doubling_chain(merkle_champ::codec::MAX_NESTING).save(&mut objects);
    assert!(ChampMap::<String, Tree>::load(&ok, &objects).is_ok());
    let deep = doubling_chain(merkle_champ::codec::MAX_NESTING + 1).save(&mut objects);
    assert_eq!(
        ChampMap::<String, Tree>::load(&deep, &objects).unwrap_err(),
        DecodeError::TooDeep
    );
}

#[test]
fn a_missing_object_is_reported_by_identity() {
    let map: ChampMap<u64, u64> = (0..2_000).map(|i| (i, i)).collect();
    let mut all = Objects::new();
    let root = map.save(&mut all);
    let dropped = *all
        .iter()
        .map(|(id, _)| id)
        .find(|id| **id != root)
        .unwrap();
    let mut partial = Objects::new();
    for (id, bytes) in all.iter() {
        if *id != dropped {
            partial.insert(bytes.to_vec());
        }
    }
    assert_eq!(
        ChampMap::<u64, u64>::load(&root, &partial).unwrap_err(),
        DecodeError::Missing(dropped)
    );
}

#[test]
fn loading_as_the_wrong_type_is_rejected() {
    let map: ChampMap<String, u64> = [("a".to_string(), 1)].into_iter().collect();
    let mut objects = Objects::new();
    let root = map.save(&mut objects);
    assert!(matches!(
        ChampMap::<String, i64>::load(&root, &objects),
        Err(DecodeError::Malformed(_))
    ));
    assert!(matches!(
        ChampMap::<Vec<u8>, u64>::load(&root, &objects),
        Err(DecodeError::Malformed(_))
    ));
}

// ------------------------------------------------------ crafted objects

const BRANCH: &[u8] = b"merkle-champ/branch/v1";
const COLLISION: &[u8] = b"merkle-champ/collision/v1";

fn branch(datamap: u32, nodemap: u32, body: &[u8]) -> Vec<u8> {
    let mut b = BRANCH.to_vec();
    b.extend(datamap.to_le_bytes());
    b.extend(nodemap.to_le_bytes());
    b.extend(body);
    b
}

fn entry<K: Identify, V: Identify>(k: &K, v: &V) -> Vec<u8> {
    let mut b = Vec::new();
    k.identify(&mut b);
    v.identify(&mut b);
    b
}

fn fragment(hash: u64, shift: u32) -> u32 {
    ((hash >> shift) & 0x1f) as u32
}

/// Wraps the object `bottom`, which sits at trie depth `bottom_shift`, in
/// single-child branches following `hash` up to the root.
fn chain_to(objects: &mut Objects, hash: u64, bottom: Vec<u8>, bottom_shift: u32) -> Identity {
    let mut id = objects.insert(bottom);
    let mut shift = bottom_shift;
    while shift > 0 {
        shift -= 5;
        id = objects.insert(branch(0, 1 << fragment(hash, shift), &id));
    }
    id
}

fn load_err(objects: &Objects, root: &Identity) -> DecodeError {
    ChampMap::<String, u64>::load(root, objects).unwrap_err()
}

#[test]
fn malformed_bytes_are_rejected() {
    let mut objects = Objects::new();
    let good = [("a".to_string(), 1u64)]
        .into_iter()
        .collect::<ChampMap<String, u64>>();
    let root = good.save(&mut objects);
    let bytes = objects.get(&root).unwrap().to_vec();

    let unknown = objects.insert(b"hello".to_vec());
    assert_eq!(
        load_err(&objects, &unknown),
        DecodeError::Malformed("unknown node domain")
    );
    let mut longer = bytes.clone();
    longer.push(0);
    let trailing = objects.insert(longer);
    assert_eq!(
        load_err(&objects, &trailing),
        DecodeError::Malformed("trailing bytes after a node")
    );
    let truncated = objects.insert(bytes[..bytes.len() - 1].to_vec());
    assert_eq!(
        load_err(&objects, &truncated),
        DecodeError::Malformed("truncated input")
    );

    let key = "a".to_string();
    let f = fragment(key.key_hash(), 0);
    let mut bad_utf8 = vec![b's'];
    bad_utf8.extend(1u64.to_le_bytes());
    bad_utf8.push(0xff);
    let not_utf8 = objects.insert(branch(1 << f, 0, &bad_utf8));
    assert_eq!(
        load_err(&objects, &not_utf8),
        DecodeError::Malformed("invalid UTF-8")
    );
}

#[test]
fn non_canonical_branches_are_rejected() {
    let mut objects = Objects::new();
    let (a, b) = ("a".to_string(), "b".to_string());
    let (ha, hb) = (a.key_hash(), b.key_hash());

    // An entry at a position its hash does not select.
    let wrong = (fragment(ha, 0) + 1) % 32;
    let misplaced = objects.insert(branch(1 << wrong, 0, &entry(&a, &1u64)));
    assert_eq!(
        load_err(&objects, &misplaced),
        DecodeError::NonCanonical("entry stored at the wrong position")
    );

    // The same position used by an entry and a child.
    let overlap = objects.insert(branch(1, 1, &[]));
    assert_eq!(
        load_err(&objects, &overlap),
        DecodeError::NonCanonical("position used by both an entry and a child")
    );

    // A single entry below the root must be inlined into its parent.
    let single = branch(1 << fragment(ha, 5), 0, &entry(&a, &1u64));
    let root = chain_to(&mut objects, ha, single, 5);
    assert_eq!(
        load_err(&objects, &root),
        DecodeError::NonCanonical("singleton or empty node below the root")
    );

    // A child whose keys belong under a different position of the parent.
    assert_ne!(
        fragment(ha, 0),
        fragment(hb, 0),
        "test keys must differ at the root"
    );
    let (lo, hi) = if fragment(ha, 5) < fragment(hb, 5) {
        ((&a, ha), (&b, hb))
    } else {
        ((&b, hb), (&a, ha))
    };
    let mut body = entry(lo.0, &1u64);
    body.extend(entry(hi.0, &2u64));
    let pair = objects.insert(branch(
        (1 << fragment(lo.1, 5)) | (1 << fragment(hi.1, 5)),
        0,
        &body,
    ));
    let foreign = objects.insert(branch(0, 1 << fragment(ha, 0), &pair));
    assert_eq!(
        load_err(&objects, &foreign),
        DecodeError::NonCanonical("entry stored at the wrong position")
    );

    // At the last branch level (shift 60) only 4 hash bits remain.
    let beyond = chain_to(&mut objects, 0, branch(1 << 17, 0, &[]), 60);
    assert_eq!(
        load_err(&objects, &beyond),
        DecodeError::NonCanonical("position beyond the remaining hash bits")
    );

    // Branches cannot occur past the last level, nor collision nodes above it.
    let deep = chain_to(&mut objects, 0, branch(0, 0, &[]), 65);
    assert_eq!(
        load_err(&objects, &deep),
        DecodeError::NonCanonical("branch node below the last trie level")
    );
    let mut shallow = COLLISION.to_vec();
    shallow.extend(2u64.to_le_bytes());
    let shallow = objects.insert(shallow);
    assert_eq!(
        load_err(&objects, &shallow),
        DecodeError::NonCanonical("collision node above the last trie level")
    );
}

/// A key whose placement hash is chosen by the test, to force collisions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct H(u64, u64);
impl KeyHash for H {
    fn key_hash(&self) -> u64 {
        self.0
    }
}
impl Identify for H {
    fn identify<S: merkle_champ::Sink + ?Sized>(&self, sink: &mut S) {
        let mut b = self.0.to_le_bytes().to_vec();
        b.extend(self.1.to_le_bytes());
        write_tagged(sink, b'H', &b);
    }
}
impl Decode for H {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        let b = read_tagged(input, b'H')?;
        if b.len() != 16 {
            return Err(DecodeError::Malformed("wrong payload length"));
        }
        Ok(H(
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        ))
    }
}

fn collision(entries: &[(H, u64)], count: u64) -> Vec<u8> {
    let mut b = COLLISION.to_vec();
    b.extend(count.to_le_bytes());
    for (k, v) in entries {
        b.extend(entry(k, v));
    }
    b
}

fn load_h(objects: &Objects, root: &Identity) -> Result<ChampMap<H, u64>, DecodeError> {
    ChampMap::load(root, objects)
}

#[test]
fn collision_nodes_round_trip_and_are_checked() {
    let hash = 0xdead_beef_0123_4567;
    let map: ChampMap<H, u64> = (0..5)
        .map(|i| (H(hash, i), i))
        .chain([(H(7, 0), 9)])
        .collect();
    let mut objects = Objects::new();
    let root = map.save(&mut objects);
    assert_eq!(load_h(&objects, &root).unwrap(), map);

    let (x, y) = ((H(hash, 1), 1u64), (H(hash, 2), 2u64));
    let sorted = chain_to(
        &mut objects,
        hash,
        collision(&[x.clone(), y.clone()], 2),
        65,
    );
    assert!(load_h(&objects, &sorted).is_ok());

    let unsorted = chain_to(
        &mut objects,
        hash,
        collision(&[y.clone(), x.clone()], 2),
        65,
    );
    assert_eq!(
        load_h(&objects, &unsorted).unwrap_err(),
        DecodeError::NonCanonical("collision entries not in strictly increasing order")
    );
    let duplicate = chain_to(
        &mut objects,
        hash,
        collision(&[x.clone(), x.clone()], 2),
        65,
    );
    assert!(matches!(
        load_h(&objects, &duplicate),
        Err(DecodeError::NonCanonical(_))
    ));
    let one = chain_to(
        &mut objects,
        hash,
        collision(std::slice::from_ref(&x), 1),
        65,
    );
    assert_eq!(
        load_h(&objects, &one).unwrap_err(),
        DecodeError::NonCanonical("collision node with fewer than two entries")
    );
    let stranger = chain_to(
        &mut objects,
        hash,
        collision(&[x.clone(), (H(hash ^ 1, 3), 3)], 2),
        65,
    );
    assert_eq!(
        load_h(&objects, &stranger).unwrap_err(),
        DecodeError::NonCanonical("collision entry with a different hash")
    );
    let huge = chain_to(&mut objects, hash, collision(&[x, y], u64::MAX), 65);
    assert_eq!(
        load_h(&objects, &huge).unwrap_err(),
        DecodeError::Malformed("entry count exceeds input")
    );
}

#[test]
fn the_deepest_levels_round_trip() {
    // Hashes that agree on their low 60 bits meet in a branch at shift 60,
    // where only positions 0-15 exist; equal hashes meet in a collision node.
    let low = 0x0abc_def0_1234_5678;
    let keys = [
        H(low, 0),
        H(low | (1 << 60), 0),
        H(low | (0xf << 60), 0),
        H(low | (0xf << 60), 1),
    ];
    let map: ChampMap<H, u64> = keys.iter().cloned().zip(0..).collect();
    map.check_invariants().unwrap();
    let mut objects = Objects::new();
    let root = map.save(&mut objects);
    let loaded = load_h(&objects, &root).unwrap();
    loaded.check_invariants().unwrap();
    assert_eq!(loaded, map);
}

#[test]
fn random_colliding_keys_round_trip() {
    let mut rng = Rng(99);
    for round in 0..50 {
        let mut map: ChampMap<H, u64> = ChampMap::new();
        for i in 0..(round * 7) {
            // Few distinct hashes, many shared bit patterns.
            let hash = (rng.next() % 8) << (rng.next() % 64) | (rng.next() % 4);
            map.insert(H(hash, rng.next() % 3), i);
            if rng.next().is_multiple_of(4) {
                map.remove(&H(hash, rng.next() % 3));
            }
        }
        let mut objects = Objects::new();
        let root = map.save(&mut objects);
        let loaded = load_h(&objects, &root).unwrap();
        loaded.check_invariants().unwrap();
        assert_eq!(loaded, map);
        assert_eq!(loaded.identity(), map.identity());
    }
}
