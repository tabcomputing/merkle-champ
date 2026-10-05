//! MCHPACK2 (`merkle_champ::pack::v2`, FORMAT.md section 11): round trips of
//! real maps with blobs, the canonical order against a naive independent
//! computation on random object graphs, lazy reads through the index, every
//! rejection, and a golden pack.
use merkle_champ::pack::{self, BLOB_DOMAIN, v2};
use merkle_champ::{ChampMap, Identity, Objects};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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

fn sha(bytes: &[u8]) -> Identity {
    Sha256::digest(bytes).into()
}

/// The objects in a pack's data area, in order, by sorting index entries by
/// offset.
fn data_order(pack: &[u8]) -> Vec<Identity> {
    let index = v2::Index::parse(pack).unwrap();
    let mut entries: Vec<(u64, Identity)> =
        index.ids().map(|id| (index.locate(id).unwrap().0, *id)).collect();
    entries.sort();
    entries.into_iter().map(|(_, id)| id).collect()
}

// ------------------------------------------------------- the naive reference

/// FORMAT.md 11.2, written as plainly as possible: references by checking
/// every 32-byte window, and a recursive preorder.
fn naive_order(roots: &[Identity], objects: &BTreeMap<Identity, Vec<u8>>) -> Vec<Identity> {
    fn refs(id: &Identity, objects: &BTreeMap<Identity, Vec<u8>>) -> Vec<Identity> {
        let bytes = &objects[id];
        let mut out = Vec::new();
        if bytes.starts_with(b"merkle-champ/blob/v1") {
            return out;
        }
        for w in bytes.windows(32) {
            let w: Identity = w.try_into().unwrap();
            if w != *id && objects.contains_key(&w) && !out.contains(&w) {
                out.push(w);
            }
        }
        out
    }
    fn visit(
        id: &Identity,
        objects: &BTreeMap<Identity, Vec<u8>>,
        order: &mut Vec<Identity>,
    ) {
        if order.contains(id) {
            return;
        }
        order.push(*id);
        for r in refs(id, objects) {
            visit(&r, objects, order);
        }
    }
    let mut order = Vec::new();
    for root in roots {
        visit(root, objects, &mut order);
    }
    order
}

/// A random object graph: each object is noise with identities of earlier
/// objects embedded at random places, some objects are blobs (which may embed
/// identities too, but are never scanned), and the roots are the last object
/// plus whatever it does not reach, in a random order.
fn random_graph(rng: &mut Rng, n: usize) -> (Vec<Identity>, BTreeMap<Identity, Vec<u8>>) {
    let mut ids: Vec<Identity> = Vec::new();
    let mut objects = BTreeMap::new();
    for _ in 0..n {
        let mut bytes = if rng.below(5) == 0 {
            BLOB_DOMAIN.to_vec()
        } else {
            b"test/node/v1".to_vec()
        };
        for _ in 0..rng.below(6) {
            for _ in 0..rng.below(40) {
                bytes.push(rng.next() as u8);
            }
            if !ids.is_empty() {
                let target = ids[rng.below(ids.len())];
                bytes.extend_from_slice(&target);
            }
        }
        let id = sha(&bytes);
        if objects.insert(id, bytes).is_none() {
            ids.push(id);
        }
    }
    let mut roots = vec![*ids.last().unwrap()];
    loop {
        let reached = naive_order(&roots, &objects);
        let missing: Vec<Identity> =
            ids.iter().filter(|id| !reached.contains(id)).copied().collect();
        if missing.is_empty() {
            break;
        }
        roots.push(missing[rng.below(missing.len())]);
    }
    (roots, objects)
}

fn objects_of(map: &BTreeMap<Identity, Vec<u8>>) -> Objects {
    let mut objects = Objects::new();
    for bytes in map.values() {
        objects.insert(bytes.clone());
    }
    objects
}

#[test]
fn the_order_matches_a_naive_computation() {
    let mut rng = Rng(2026);
    for round in 0..60 {
        let (roots, map) = random_graph(&mut rng, 1 + round);
        let objects = objects_of(&map);
        let pack = v2::encode(&roots, &objects).unwrap();
        assert_eq!(data_order(&pack), naive_order(&roots, &map), "round {round}");
        let decoded = v2::decode(&pack).unwrap();
        assert_eq!(decoded.roots, roots);
        assert_eq!(decoded.objects, objects);
        assert_eq!(v2::encode(&decoded.roots, &decoded.objects).unwrap(), pack);
    }
}

// ------------------------------------------------------- maps and blobs

type Pages = ChampMap<String, Identity>;

fn build(names: impl Iterator<Item = u64>) -> (ChampMap<String, Pages>, Objects) {
    let mut objects = Objects::new();
    let mut outer = ChampMap::new();
    for i in names {
        let mut pages = Pages::new();
        for j in 0..3 {
            let page = objects.insert(pack::blob(format!("page {i}.{j}").as_bytes()));
            pages.insert(format!("p{j}"), page);
        }
        outer.insert(format!("doc{i}"), pages);
    }
    (outer, objects)
}

#[test]
fn maps_with_blobs_round_trip() {
    let (map, mut objects) = build(0..200);
    let root = map.save(&mut objects);
    let pack = v2::encode(&[root], &objects).unwrap();
    let decoded = v2::decode(&pack).unwrap();
    assert_eq!(decoded.roots, [root]);
    let loaded = ChampMap::<String, Pages>::load(&root, &decoded.objects).unwrap();
    assert_eq!(loaded, map);
    // Each blob comes right after the first object that refers to it: a page
    // after the inner-map node holding it.
    let order = data_order(&pack);
    for (i, id) in order.iter().enumerate() {
        let bytes = decoded.objects.get(id).unwrap();
        if bytes.starts_with(BLOB_DOMAIN) {
            let previous = &order[..i];
            let first_referrer = order
                .iter()
                .position(|o| {
                    let b = decoded.objects.get(o).unwrap();
                    !b.starts_with(BLOB_DOMAIN) && b.windows(32).any(|w| w == id)
                })
                .unwrap();
            assert!(first_referrer < i);
            // Everything between the referrer and the blob is a blob too:
            // the referrer's earlier blobs.
            assert!(previous[first_referrer + 1..]
                .iter()
                .all(|o| decoded.objects.get(o).unwrap().starts_with(BLOB_DOMAIN)));
        }
    }
}

#[test]
fn equal_contents_give_identical_packs() {
    // The same map built in two insertion orders, and objects inserted in
    // different orders, give byte-identical packs.
    let (a, mut oa) = build(0..120);
    let (b, mut ob) = build((0..120).rev());
    let ra = a.save(&mut oa);
    let rb = b.save(&mut ob);
    assert_eq!(ra, rb);
    assert_eq!(v2::encode(&[ra], &oa).unwrap(), v2::encode(&[rb], &ob).unwrap());
}

// ------------------------------------------------------- lazy reading

#[test]
fn the_index_reads_objects_by_range() {
    let (map, mut objects) = build(0..50);
    let root = map.save(&mut objects);
    let pack = v2::encode(&[root], &objects).unwrap();
    // One read for the header, one for the index, then any object.
    let needed = v2::Index::needed(&pack[..24]).unwrap();
    let index = v2::Index::parse(&pack[..needed]).unwrap();
    assert_eq!(index.roots(), [root]);
    assert_eq!(index.len(), objects.len());
    for (id, bytes) in objects.iter() {
        let (offset, length) = index.locate(id).unwrap();
        let fetched = &pack[offset as usize..(offset + length) as usize];
        assert_eq!(fetched, bytes);
        assert!(v2::Index::verify(id, fetched));
    }
    assert_eq!(index.locate(&[0; 32]), None);
    // The root's top levels come first: the root is the first object.
    assert_eq!(index.locate(&root).unwrap().0, needed as u64);
}

// ------------------------------------------------------- rejection

fn small() -> (Vec<Identity>, Objects) {
    let mut objects = Objects::new();
    let page = objects.insert(pack::blob(b"page"));
    let mut leaf = b"example/leaf/v1".to_vec();
    leaf.extend_from_slice(&page);
    let leaf = objects.insert(leaf);
    let other = objects.insert(b"example/leaf/v1c".to_vec());
    let mut root = b"example/root/v1".to_vec();
    root.extend_from_slice(&other);
    root.extend_from_slice(&leaf);
    let root = objects.insert(root);
    (vec![root], objects)
}

#[test]
fn the_golden_pack() {
    let (roots, objects) = small();
    let pack = v2::encode(&roots, &objects).unwrap();
    // The root, then what it refers to in order of appearance: the other
    // leaf, the leaf, and the leaf's page right after it.
    let names: Vec<&[u8]> = data_order(&pack)
        .iter()
        .map(|id| &objects.get(id).unwrap()[..15])
        .collect();
    assert_eq!(
        names,
        [
            b"example/root/v1".as_slice(),
            b"example/leaf/v1",
            b"example/leaf/v1",
            b"merkle-champ/bl",
        ]
    );
    // The same bytes laid out by hand from FORMAT.md 11.2.
    let page = pack::blob(b"page");
    let mut leaf = b"example/leaf/v1".to_vec();
    leaf.extend_from_slice(&sha(&page));
    let other = b"example/leaf/v1c".to_vec();
    let mut root = b"example/root/v1".to_vec();
    root.extend_from_slice(&sha(&other));
    root.extend_from_slice(&sha(&leaf));
    let data = [&root, &other, &leaf, &page];
    let start = 24 + 32 + 4 * 48;
    let mut expected = b"MCHPACK2".to_vec();
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&4u64.to_le_bytes());
    expected.extend_from_slice(&sha(&root));
    let mut entries: Vec<(Identity, u64, u64)> = Vec::new();
    let mut offset = start as u64;
    for d in data {
        entries.push((sha(d), offset, d.len() as u64));
        offset += d.len() as u64;
    }
    entries.sort();
    for (id, offset, length) in entries {
        expected.extend_from_slice(&id);
        expected.extend_from_slice(&offset.to_le_bytes());
        expected.extend_from_slice(&length.to_le_bytes());
    }
    for d in data {
        expected.extend_from_slice(d);
    }
    assert_eq!(pack, expected);
    assert_eq!(
        hex(&sha(&pack)),
        GOLDEN,
        "the golden pack changed; FORMAT.md 11.2 gives its hash"
    );
}

const GOLDEN: &str = "2930478cf38da08f57e5c04ee04bcb47206ac28a83a2c54c963a5484e9d2b9d0";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn bad_packs_are_rejected() {
    let (roots, objects) = small();
    let pack = v2::encode(&roots, &objects).unwrap();
    let err = |p: &[u8]| v2::decode(p).unwrap_err().to_string();

    // A changed byte in an object.
    let mut p = pack.clone();
    *p.last_mut().unwrap() ^= 1;
    assert_eq!(err(&p), "pack object identity mismatch");
    // Unknown flags, a bad magic, a short header, a truncated index.
    let mut p = pack.clone();
    p[8] = 1;
    assert_eq!(err(&p), "unknown pack flags");
    let mut p = pack.clone();
    p[7] = b'1';
    assert_eq!(err(&p), "invalid pack header");
    assert_eq!(err(&pack[..20]), "invalid pack header");
    assert_eq!(err(&pack[..100]), "pack index incomplete");
    // Trailing bytes.
    let mut p = pack.clone();
    p.push(0);
    assert_eq!(err(&p), "unused bytes in pack data area");
    // Data in identity order instead of canonical order: same objects, same
    // index layout otherwise.
    let needed = v2::Index::needed(&pack).unwrap();
    let mut p = pack[..needed].to_vec();
    let mut offset = needed as u64;
    for (k, (_, bytes)) in objects.iter().enumerate() {
        let e = 24 + 32 + 48 * k;
        p[e + 32..e + 40].copy_from_slice(&offset.to_le_bytes());
        offset += bytes.len() as u64;
    }
    for (_, bytes) in objects.iter() {
        p.extend_from_slice(bytes);
    }
    assert_eq!(err(&p), "pack data not in canonical order");

    // The writer refuses what a reader would.
    let (root, mut more) = (roots[0], objects.clone());
    more.insert(b"unreferenced".to_vec());
    assert_eq!(
        v2::encode(&[root], &more).unwrap_err().to_string(),
        "pack object not reachable from its roots"
    );
    assert_eq!(
        v2::encode(&[root, root], &objects).unwrap_err().to_string(),
        "pack roots must be unique"
    );
    assert_eq!(
        v2::encode(&[[7; 32]], &objects).unwrap_err().to_string(),
        "pack root is not in the pack"
    );
    // A blob's bytes are not scanned: an object only a blob mentions is
    // unreachable.
    let mut lone = objects.clone();
    let hidden = lone.insert(b"hidden".to_vec());
    let mut page = BLOB_DOMAIN.to_vec();
    page.extend_from_slice(&hidden);
    let page = lone.insert(page);
    assert!(v2::encode(&[root, page], &lone).is_err());
    assert!(v2::encode(&[root, page, hidden], &lone).is_ok());
}

#[test]
fn the_empty_pack() {
    let pack = v2::encode(&[], &Objects::new()).unwrap();
    assert_eq!(pack.len(), 24);
    let decoded = v2::decode(&pack).unwrap();
    assert!(decoded.roots.is_empty() && decoded.objects.is_empty());
}

#[test]
fn mchpack1_is_unchanged() {
    let bytes = b"node".to_vec();
    let id = sha(&bytes);
    let p = pack::encode(&[(id, bytes.clone())]).unwrap();
    assert_eq!(&p[..8], b"MCHPACK1");
    assert_eq!(pack::decode(&p).unwrap(), [(id, bytes)]);
    assert!(v2::decode(&p).is_err());
}
