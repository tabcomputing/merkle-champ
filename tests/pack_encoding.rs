//! Packs with encoded members: blobs stored as zstd frames, keeping the
//! identity of their content (FORMAT.md, section 11.3). Writing needs no
//! feature; reading compressed members needs `zstd` or `ruzstd`, so run these
//! with each: `cargo test --features zstd`, `cargo test --features ruzstd`.

use merkle_champ::pack::{self, Encoding, Member};
use merkle_champ::{Identity, Objects};
use sha2::{Digest, Sha256};

fn id(bytes: &[u8]) -> Identity {
    Sha256::digest(bytes).into()
}

/// Chunk contents that compress, alike enough for a dictionary to help.
fn contents(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut c = Vec::new();
            for line in 0..200 {
                c.extend_from_slice(
                    format!("row {line} of chunk {i}: status=ok kind=page\n").as_bytes(),
                );
            }
            c
        })
        .collect()
}

fn compress(content: &[u8]) -> Vec<u8> {
    let mut c = zstd::bulk::Compressor::new(3).unwrap();
    c.set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(true))
        .unwrap();
    c.compress(content).unwrap()
}

/// A root naming every chunk, the chunks as zstd members, and the same
/// objects raw.
struct Fixture {
    root: Identity,
    objects: Objects,
    root_bytes: Vec<u8>,
    chunks: Vec<(Identity, Vec<u8>)>,
}

fn fixture(n: usize) -> Fixture {
    let mut objects = Objects::new();
    let mut root_bytes = b"example/root/v1".to_vec();
    let mut chunks = Vec::new();
    for c in contents(n) {
        let cid = objects.insert(pack::blob(&c));
        root_bytes.extend_from_slice(&cid);
        chunks.push((cid, compress(&c)));
    }
    let root = objects.insert(root_bytes.clone());
    Fixture {
        root,
        objects,
        root_bytes,
        chunks,
    }
}

fn members(f: &Fixture) -> Vec<(Identity, Member<'_>)> {
    let mut m = vec![(f.root, Member::Raw(&f.root_bytes))];
    for (cid, frame) in &f.chunks {
        m.push((
            *cid,
            Member::Zstd {
                frame,
                dictionary: None,
            },
        ));
    }
    m
}

#[test]
fn raw_members_write_the_unique_pack() {
    let f = fixture(5);
    let raw: Vec<(Identity, Member<'_>)> = f
        .objects
        .iter()
        .map(|(i, b)| (*i, Member::Raw(b)))
        .collect();
    let bytes = pack::encode_members(&[f.root], &raw).unwrap();
    assert_eq!(bytes, pack::encode(&[f.root], &f.objects).unwrap());
    assert!(!pack::Index::parse(&bytes).unwrap().is_encoded());
}

#[test]
fn zstd_members_are_indexed_with_their_decoded_lengths() {
    let f = fixture(20);
    let bytes = pack::encode_members(&[f.root], &members(&f)).unwrap();
    let raw = pack::encode(&[f.root], &f.objects).unwrap();
    assert!(
        bytes.len() * 3 < raw.len(),
        "{} against {}",
        bytes.len(),
        raw.len()
    );
    let index = pack::Index::parse(&bytes).unwrap();
    assert!(index.is_encoded());
    for (cid, frame) in &f.chunks {
        let e = index.entry(cid).unwrap();
        assert_eq!(e.encoding, Encoding::Zstd);
        assert_eq!(e.length, frame.len() as u64);
        assert_eq!(e.decoded_length, f.objects.get(cid).unwrap().len() as u64);
    }
    // The canonical order is the raw pack's: the root, then the chunks it
    // names, in order.
    let mut by_offset: Vec<_> = index.entries().iter().map(|e| (e.offset, e.id)).collect();
    by_offset.sort();
    let order: Vec<Identity> = by_offset.into_iter().map(|(_, i)| i).collect();
    let mut expected = vec![f.root];
    expected.extend(f.chunks.iter().map(|(c, _)| *c));
    assert_eq!(order, expected);
}

#[test]
fn the_writer_checks_frames_and_dictionaries() {
    let f = fixture(2);
    let content = &contents(1)[0];
    let blob_id = id(&pack::blob(content));
    // A frame that does not record its content size.
    let mut c = zstd::bulk::Compressor::new(3).unwrap();
    c.set_parameter(zstd::zstd_safe::CParameter::ContentSizeFlag(false))
        .unwrap();
    let no_size = c.compress(content).unwrap();
    let m = [(
        blob_id,
        Member::Zstd {
            frame: &no_size,
            dictionary: None,
        },
    )];
    assert!(pack::encode_members(&[blob_id], &m).is_err());
    // Not a frame at all.
    let m = [(
        blob_id,
        Member::Zstd {
            frame: b"not a frame",
            dictionary: None,
        },
    )];
    assert!(pack::encode_members(&[blob_id], &m).is_err());
    // A dictionary that is not in the pack, as a delta pack might wish.
    let frame = compress(content);
    let m = [(
        blob_id,
        Member::Zstd {
            frame: &frame,
            dictionary: Some([7; 32]),
        },
    )];
    assert!(pack::encode_members(&[blob_id], &m).is_err());
    // A raw member whose bytes are not its identity's.
    let m = [(f.root, Member::Raw(b"something else"))];
    assert!(pack::encode_members(&[f.root], &m).is_err());
}

#[cfg(any(feature = "zstd", feature = "ruzstd"))]
mod reading {
    use super::*;
    use merkle_champ::Sequence;
    use merkle_champ::pack::ReadOptions;

    #[test]
    fn decoding_gives_the_objects_and_their_raw_form() {
        let f = fixture(20);
        let bytes = pack::encode_members(&[f.root], &members(&f)).unwrap();
        let p = pack::decode(&bytes).unwrap();
        assert_eq!(p.roots, [f.root]);
        assert_eq!(p.objects, f.objects);
        assert_eq!(
            pack::encode(&p.roots, &p.objects).unwrap(),
            pack::encode(&[f.root], &f.objects).unwrap()
        );
    }

    #[test]
    fn members_read_one_at_a_time() {
        let f = fixture(10);
        let bytes = pack::encode_members(&[f.root], &members(&f)).unwrap();
        let index = pack::Index::parse(&bytes[..pack::Index::needed(&bytes).unwrap()]).unwrap();
        for (cid, _) in &f.chunks {
            let e = index.entry(cid).unwrap();
            let stored = &bytes[e.offset as usize..(e.offset + e.length) as usize];
            let object = pack::read_member(e, stored, None, &ReadOptions::default()).unwrap();
            assert_eq!(object, f.objects.get(cid).unwrap());
        }
        // A member larger than the reader allows is refused before decoding.
        let e = index.entry(&f.chunks[0].0).unwrap();
        let stored = &bytes[e.offset as usize..(e.offset + e.length) as usize];
        let small = ReadOptions {
            max_decoded: 1000,
            ..ReadOptions::default()
        };
        assert!(pack::read_member(e, stored, None, &small).is_err());
    }

    #[test]
    fn dictionaries_are_members_named_by_position() {
        let samples = contents(60);
        let dict = zstd::dict::from_samples(&samples, 4096).unwrap();
        let dict_blob = pack::blob(&dict);
        let dict_id = id(&dict_blob);
        let mut objects = Objects::new();
        let mut root_bytes = b"example/root/v1".to_vec();
        let mut frames = Vec::new();
        for (i, c) in samples.iter().take(10).enumerate() {
            let cid = objects.insert(pack::blob(c));
            root_bytes.extend_from_slice(&cid);
            let mut z = zstd::bulk::Compressor::with_dictionary(3, &dict).unwrap();
            // Half the frames leave the dictionary ID out; the entry names
            // the dictionary either way.
            z.set_parameter(zstd::zstd_safe::CParameter::DictIdFlag(i % 2 == 0))
                .unwrap();
            z.set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(true))
                .unwrap();
            frames.push((cid, z.compress(c).unwrap()));
        }
        let root = objects.insert(root_bytes.clone());
        objects.insert(dict_blob.clone());
        let mut m = vec![
            (root, Member::Raw(&root_bytes)),
            (dict_id, Member::Raw(&dict_blob)),
        ];
        for (cid, frame) in &frames {
            m.push((
                *cid,
                Member::Zstd {
                    frame,
                    dictionary: Some(dict_id),
                },
            ));
        }
        let bytes = pack::encode_members(&[root], &m).unwrap();
        let index = pack::Index::parse(&bytes).unwrap();
        let position = index
            .entries()
            .iter()
            .position(|e| e.id == dict_id)
            .unwrap() as u32;
        assert!(
            index
                .entries()
                .iter()
                .filter(|e| e.id != root && e.id != dict_id)
                .all(|e| e.encoding == Encoding::ZstdDictionary(position))
        );
        // The dictionary lies right after the first member that uses it.
        let first = index.entry(&frames[0].0).unwrap();
        assert_eq!(
            index.entry(&dict_id).unwrap().offset,
            first.offset + first.length
        );
        let p = pack::decode(&bytes).unwrap();
        assert_eq!(p.objects, objects);
        // Reading one member needs its dictionary's object.
        let e = index.entry(&frames[3].0).unwrap();
        let stored = &bytes[e.offset as usize..(e.offset + e.length) as usize];
        let options = ReadOptions::default();
        assert!(pack::read_member(e, stored, None, &options).is_err());
        let object = pack::read_member(e, stored, Some(&dict_blob), &options).unwrap();
        assert_eq!(object, objects.get(&frames[3].0).unwrap());
    }

    #[test]
    fn damage_and_false_identities_are_caught() {
        let f = fixture(5);
        let bytes = pack::encode_members(&[f.root], &members(&f)).unwrap();
        // A flipped byte inside a frame.
        let e = *pack::Index::parse(&bytes)
            .unwrap()
            .entry(&f.chunks[2].0)
            .unwrap();
        let mut damaged = bytes.clone();
        damaged[(e.offset + e.length / 2) as usize] ^= 1;
        assert!(pack::decode(&damaged).is_err());

        // A frame stored under an identity that is not its content's: caught
        // by identity, but not when trusting checksums, which only detect
        // corruption.
        let wrong = [9u8; 32];
        let mut root_bytes = b"example/root/v1".to_vec();
        root_bytes.extend_from_slice(&wrong);
        let root = id(&root_bytes);
        let m = [
            (root, Member::Raw(&root_bytes)),
            (
                wrong,
                Member::Zstd {
                    frame: &f.chunks[0].1,
                    dictionary: None,
                },
            ),
        ];
        let bytes = pack::encode_members(&[root], &m).unwrap();
        assert!(pack::decode(&bytes).is_err());
        let trusting = ReadOptions {
            trust_checksums: true,
            ..ReadOptions::default()
        };
        assert!(pack::decode_with(&bytes, &trusting).is_ok());
    }

    #[test]
    fn a_sequence_loads_from_a_base_pack_and_a_delta() {
        // One pack per version, holding only what the store lacks, as transfs
        // writes them; the version loads from the union.
        let v1: Sequence<u64> = (0..50_000).collect();
        let v2 = v1.insert(25_000, 7);
        let mut base = Objects::new();
        let id1 = v1.save(&mut base);
        let mut all = Objects::new();
        let id2 = v2.save(&mut all);
        let mut delta = Objects::new();
        for (i, b) in all.iter() {
            if !base.contains(i) {
                delta.insert(b.to_vec());
            }
        }
        assert!(delta.len() < 10);
        let base_pack = pack::encode(&[id1], &base).unwrap();
        let delta_pack = pack::encode(&[id2], &delta).unwrap();
        let mut objects = pack::decode(&base_pack).unwrap().objects;
        objects.extend(pack::decode(&delta_pack).unwrap().objects);
        assert_eq!(
            Sequence::<u64>::load(&id2, &objects).unwrap().identity(),
            v2.identity()
        );
        assert_eq!(
            Sequence::<u64>::load(&id1, &objects).unwrap().identity(),
            v1.identity()
        );
    }
}

#[cfg(not(any(feature = "zstd", feature = "ruzstd")))]
#[test]
fn without_a_decoder_compressed_members_are_refused_and_raw_ones_read() {
    let f = fixture(3);
    let bytes = pack::encode_members(&[f.root], &members(&f)).unwrap();
    assert!(pack::decode(&bytes).is_err());
    let index = pack::Index::parse(&bytes).unwrap();
    let e = index.entry(&f.root).unwrap();
    let stored = &bytes[e.offset as usize..(e.offset + e.length) as usize];
    let object = pack::read_member(e, stored, None, &pack::ReadOptions::default()).unwrap();
    assert_eq!(object, f.root_bytes);
}
