//! Golden vectors for identity format v1 (FORMAT.md). These values are fixed:
//! a change here is a format change and needs new domain strings.
use merkle_champ::{ChampMap, KeyHash, hash_bytes};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn map(entries: &[(&str, u64)]) -> ChampMap<String, u64> {
    entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

#[test]
fn placement_hash_vectors() {
    assert_eq!(hash_bytes(b""), GOLDEN_HASH_EMPTY);
    assert_eq!("a".key_hash(), GOLDEN_HASH_A);
    assert_eq!("namespace.word".to_string().key_hash(), GOLDEN_HASH_WORD);
    assert_eq!(42u64.key_hash(), GOLDEN_HASH_U64_42);
    assert_eq!((-1i64).key_hash(), GOLDEN_HASH_I64_MINUS1);
    // Strings and byte strings share the placement hash.
    assert_eq!("a".key_hash(), b"a".as_slice().key_hash());
}

/// Recomputes small identities directly from FORMAT.md, independently of the
/// trie code, to check that the specification and implementation agree.
#[test]
fn identities_follow_the_written_specification() {
    let enc_str = |h: &mut Sha256, s: &str| {
        h.update([b's']);
        h.update((s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    };
    let enc_u64 = |h: &mut Sha256, v: u64| {
        h.update([b'u']);
        h.update(8u64.to_le_bytes());
        h.update(v.to_le_bytes());
    };
    // Empty map: a root branch with zero bitmaps.
    let mut h = Sha256::new();
    h.update(b"merkle-champ/branch/v1");
    h.update(0u32.to_le_bytes());
    h.update(0u32.to_le_bytes());
    let empty: [u8; 32] = h.finalize().into();
    assert_eq!(ChampMap::<String, u64>::new().identity(), empty);

    // One entry: root datamap has the key's level-0 fragment set.
    let frag = ("a".key_hash() & 31) as u32;
    let mut h = Sha256::new();
    h.update(b"merkle-champ/branch/v1");
    h.update((1u32 << frag).to_le_bytes());
    h.update(0u32.to_le_bytes());
    enc_str(&mut h, "a");
    enc_u64(&mut h, 1);
    let one: [u8; 32] = h.finalize().into();
    assert_eq!(map(&[("a", 1)]).identity(), one);

    // Two entries with different level-0 fragments: both inline, in
    // ascending fragment order.
    let (fa, fb) = (("a".key_hash() & 31) as u32, ("b".key_hash() & 31) as u32);
    assert_ne!(fa, fb, "choose keys whose level-0 fragments differ");
    let ordered = if fa < fb {
        [("a", 1u64), ("b", 2)]
    } else {
        [("b", 2), ("a", 1)]
    };
    let mut h = Sha256::new();
    h.update(b"merkle-champ/branch/v1");
    h.update(((1u32 << fa) | (1u32 << fb)).to_le_bytes());
    h.update(0u32.to_le_bytes());
    for (k, v) in ordered {
        enc_str(&mut h, k);
        enc_u64(&mut h, v);
    }
    let two: [u8; 32] = h.finalize().into();
    assert_eq!(map(&[("b", 2), ("a", 1)]).identity(), two);
}

#[test]
fn fixed_identity_vectors() {
    let cases: Vec<(&str, [u8; 32])> = vec![
        ("empty", ChampMap::<String, u64>::new().identity()),
        ("a=1", map(&[("a", 1)]).identity()),
        ("a=1,b=2", map(&[("a", 1), ("b", 2)]).identity()),
        (
            "1000 words",
            (0..1000u64)
                .map(|i| (format!("ns{}.w{}", i % 7, i), i))
                .collect::<ChampMap<String, u64>>()
                .identity(),
        ),
        ("nested", {
            let inner = map(&[("print", 1), ("read", 2)]);
            let root: ChampMap<String, ChampMap<String, u64>> =
                [("io".to_string(), inner)].into_iter().collect();
            root.identity()
        }),
        ("bytes", {
            let m: ChampMap<Vec<u8>, i64> = [(b"k".to_vec(), -5i64)].into_iter().collect();
            m.identity()
        }),
    ];
    let mut report = String::new();
    for (name, id) in &cases {
        report.push_str(&format!("        (\"{name}\", \"{}\"),\n", hex(id)));
    }
    if std::env::var("GOLDEN_PRINT").is_ok() {
        println!("{report}");
    }
    for ((name, id), (gname, gold)) in cases.iter().zip(GOLDEN_IDENTITIES) {
        assert_eq!(name, gname);
        assert_eq!(
            hex(id),
            *gold,
            "identity vector {name} changed: format change?"
        );
    }
}

// Pinned on 2026-09-26 from the implementation, after the placement hash was
// checked against the written specification in `placement_hash_follows_spec`.
const GOLDEN_HASH_EMPTY: u64 = 0xefd01f60ba992926;
const GOLDEN_HASH_A: u64 = 0x25ad9d1b70de62d1;
const GOLDEN_HASH_WORD: u64 = 0x2349bf8732adaf25;
const GOLDEN_HASH_U64_42: u64 = 0x810879608e4259cc;
const GOLDEN_HASH_I64_MINUS1: u64 = 0x64b5720b4b825f21;
const GOLDEN_IDENTITIES: &[(&str, &str)] = &[
    (
        "empty",
        "c1a1bff2737c791971664a89f365aee690abcba400414f055658a188827ca8dc",
    ),
    (
        "a=1",
        "f5c38cd9a605af62e7382585cf6aba16cd8ae0614fab13bfc1c5212dbe611bd6",
    ),
    (
        "a=1,b=2",
        "31e363110681eaf39d1471c6cfff0776f505b09ee168072e292930c0594064ca",
    ),
    (
        "1000 words",
        "edb1bb51ca6df056222c109de16e50d9f6b674aedabe47a7cc4208b67f6b58ad",
    ),
    (
        "nested",
        "3c5c2fce42fe58d89d5418bcb0283d7aadf4c97b03c25e523a6cb1e630d9ef8e",
    ),
    (
        "bytes",
        "d4a149e4caac1a23eacfd5e2220cf0833ea641b485f2b5a4f528b0b6585a72f8",
    ),
];

/// The placement hash recomputed from FORMAT.md section 1.
#[test]
fn placement_hash_follows_spec() {
    fn fmix64(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^ (h >> 33)
    }
    fn spec_bytes(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100000001b3);
        }
        fmix64(h ^ bytes.len() as u64)
    }
    for s in ["", "a", "namespace.word", "\u{e9}\u{0}x"] {
        assert_eq!(s.key_hash(), spec_bytes(s.as_bytes()), "{s:?}");
    }
    assert_eq!(42u64.key_hash(), fmix64(42));
    assert_eq!((-1i64).key_hash(), fmix64(u64::MAX));
}
