//! Benchmark: merkle-champ vs imbl (HashMap with a fixed hasher, OrdMap) vs a
//! clone-on-write std HashMap floor, on workloads shaped like a namespaced
//! global store. Run with:
//!
//!   cargo run --release --example store_bench            (all sizes)
//!   cargo run --release --example store_bench -- 10000   (one size)
//!
//! Every timed loop checks a result so the work cannot be optimized away.
//! Reported numbers are nanoseconds per operation: min / median / max over
//! seven samples after one warm-up sample.

use merkle_champ::{ChampMap, Identity, hash_bytes};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap as StdMap;
use std::hash::{BuildHasher, Hasher};
use std::hint::black_box;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

// ------------------------------------------------------ allocation counter

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;
fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

// ---------------------------------------------------- fixed hasher for imbl

/// Deterministic hasher (same function as merkle-champ's key hash), so imbl
/// is compared with a hasher that could support a canonical store.
#[derive(Clone, Default)]
struct Fixed;
struct FixedHasher(Vec<u8>);
impl Hasher for FixedHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn finish(&self) -> u64 {
        hash_bytes(&self.0)
    }
}
impl BuildHasher for Fixed {
    type Hasher = FixedHasher;
    fn build_hasher(&self) -> FixedHasher {
        FixedHasher(Vec::with_capacity(32))
    }
}

type ImHash = imbl::GenericHashMap<String, u64, Fixed, imbl::shared_ptr::DefaultSharedPtr>;
type ImOrd = imbl::OrdMap<String, u64>;

// ------------------------------------------------------------------ inputs

const NAMESPACES: usize = 64;

fn key(i: usize) -> String {
    format!("ns{:02}.word{}", i % NAMESPACES, i)
}

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

// ----------------------------------------------------------------- timing

fn measure_setup<T>(
    label: &str,
    ops: usize,
    mut setup: impl FnMut() -> T,
    mut sample: impl FnMut(&T) -> u64,
) {
    let x = setup();
    black_box(sample(&x));
    let mut times: Vec<f64> = (0..7)
        .map(|_| {
            let x = setup();
            let t = Instant::now();
            black_box(sample(&x));
            t.elapsed().as_nanos() as f64 / ops as f64
        })
        .collect();
    times.sort_by(f64::total_cmp);
    println!(
        "  {label:<48} {:>11.1} {:>11.1} {:>11.1}",
        times[0], times[3], times[6]
    );
}

fn measure(label: &str, ops: usize, mut sample: impl FnMut() -> u64) {
    black_box(sample());
    let mut times: Vec<f64> = (0..7)
        .map(|_| {
            let t = Instant::now();
            black_box(sample());
            t.elapsed().as_nanos() as f64 / ops as f64
        })
        .collect();
    times.sort_by(f64::total_cmp);
    println!(
        "  {label:<48} {:>11.1} {:>11.1} {:>11.1}",
        times[0], times[3], times[6]
    );
}

/// Identity layered on a map without structural hashing: sort all entries
/// and hash them. This is what a store would have to do per identity request.
fn layered_identity<'a>(entries: impl Iterator<Item = (&'a String, &'a u64)>) -> Identity {
    let mut all: Vec<_> = entries.collect();
    all.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    for (k, v) in all {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}

fn run(n: usize) {
    println!("\n== {n} entries ==   (ns per op: min / median / max)");
    let keys: Vec<String> = (0..n).map(key).collect();
    let misses: Vec<String> = (0..1024).map(|i| format!("absent.{i}")).collect();
    let mut rng = Rng(n as u64);
    let probes: Vec<usize> = (0..1024).map(|_| rng.next() as usize % n).collect();

    // Build all structures, measuring retained bytes.
    let before = live();
    let champ: ChampMap<String, u64> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let champ_bytes = live() - before;
    let before = live();
    let imh: ImHash = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let imh_bytes = live() - before;
    let before = live();
    let imo: ImOrd = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let imo_bytes = live() - before;
    let before = live();
    let std: StdMap<String, u64> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let std_bytes = live() - before;
    let key_bytes: isize = keys.iter().map(|k| k.capacity() as isize).sum();
    println!(
        "  memory, bytes per entry including key strings ({} key bytes/entry):",
        key_bytes / n as isize
    );
    for (name, bytes) in [
        ("merkle-champ", champ_bytes),
        ("imbl HashMap", imh_bytes),
        ("imbl OrdMap", imo_bytes),
        ("std HashMap", std_bytes),
    ] {
        println!("    {name:<14} {:>8.1}", bytes as f64 / n as f64);
    }

    println!("  lookup (hit)");
    measure("merkle-champ", probes.len(), || {
        probes.iter().map(|&i| *champ.get(&keys[i]).unwrap()).sum()
    });
    measure("imbl HashMap (fixed hasher)", probes.len(), || {
        probes.iter().map(|&i| *imh.get(&keys[i]).unwrap()).sum()
    });
    measure("imbl OrdMap", probes.len(), || {
        probes.iter().map(|&i| *imo.get(&keys[i]).unwrap()).sum()
    });
    measure("std HashMap", probes.len(), || {
        probes.iter().map(|&i| *std.get(&keys[i]).unwrap()).sum()
    });

    println!("  lookup (miss)");
    measure("merkle-champ", misses.len(), || {
        misses.iter().filter(|k| champ.get(k).is_none()).count() as u64
    });
    measure("imbl HashMap (fixed hasher)", misses.len(), || {
        misses.iter().filter(|k| imh.get(*k).is_none()).count() as u64
    });
    measure("imbl OrdMap", misses.len(), || {
        misses.iter().filter(|k| imo.get(*k).is_none()).count() as u64
    });

    println!("  persistent write (previous version kept alive)");
    measure("merkle-champ", probes.len(), || {
        probes
            .iter()
            .map(|&i| champ.update(keys[i].clone(), 7).len() as u64)
            .sum()
    });
    measure("imbl HashMap (fixed hasher)", probes.len(), || {
        probes
            .iter()
            .map(|&i| imh.update(keys[i].clone(), 7).len() as u64)
            .sum()
    });
    measure("imbl OrdMap", probes.len(), || {
        probes
            .iter()
            .map(|&i| imo.update(keys[i].clone(), 7).len() as u64)
            .sum()
    });
    if n <= 10_000 {
        let few = &probes[..64];
        measure("std HashMap, clone per write (floor)", few.len(), || {
            few.iter()
                .map(|&i| {
                    let mut c = std.clone();
                    c.insert(keys[i].clone(), 7);
                    c.len() as u64
                })
                .sum()
        });
    }

    println!("  in-place write (sole owner)");
    let mut c = champ.clone();
    c.insert("warm".into(), 0);
    measure("merkle-champ", probes.len(), || {
        probes
            .iter()
            .map(|&i| c.insert(keys[i].clone(), 9).unwrap_or(0))
            .sum()
    });
    let mut h = imh.clone();
    h.insert("warm".into(), 0);
    measure("imbl HashMap (fixed hasher)", probes.len(), || {
        probes
            .iter()
            .map(|&i| h.insert(keys[i].clone(), 9).unwrap_or(0))
            .sum()
    });
    let mut o = imo.clone();
    o.insert("warm".into(), 0);
    measure("imbl OrdMap", probes.len(), || {
        probes
            .iter()
            .map(|&i| o.insert(keys[i].clone(), 9).unwrap_or(0))
            .sum()
    });
    drop((c, h, o));

    println!("  persistent delete");
    measure("merkle-champ", probes.len(), || {
        probes
            .iter()
            .map(|&i| champ.without(&keys[i]).len() as u64)
            .sum()
    });
    measure("imbl HashMap (fixed hasher)", probes.len(), || {
        probes
            .iter()
            .map(|&i| imh.without(&keys[i]).len() as u64)
            .sum()
    });
    measure("imbl OrdMap", probes.len(), || {
        probes
            .iter()
            .map(|&i| imo.without(&keys[i]).len() as u64)
            .sum()
    });

    println!("  list one namespace ({} entries)", n / NAMESPACES);
    let prefix = "ns07.";
    measure("merkle-champ flat (filter all)", 1, || {
        champ.iter().filter(|(k, _)| k.starts_with(prefix)).count() as u64
    });
    let mut nested: ChampMap<String, ChampMap<String, u64>> = ChampMap::new();
    for (i, k) in keys.iter().enumerate() {
        let (ns, name) = k.split_at(4);
        let inner = nested.get(&ns.to_string()).cloned().unwrap_or_default();
        nested.insert(
            ns.to_string(),
            inner.update(name[1..].to_string(), i as u64),
        );
    }
    measure("merkle-champ nested (one map per namespace)", 1, || {
        nested
            .get(&"ns07".to_string())
            .map(|m| m.iter().count() as u64)
            .unwrap_or(0)
    });
    measure("imbl OrdMap range scan", 1, || {
        imo.range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .count() as u64
    });
    measure("imbl HashMap (filter all)", 1, || {
        imh.iter().filter(|(k, _)| k.starts_with(prefix)).count() as u64
    });

    println!("  identity of the whole map");
    measure_setup(
        "merkle-champ first identity (cold)",
        1,
        || {
            keys.iter()
                .enumerate()
                .map(|(i, k)| (k.clone(), i as u64))
                .collect::<ChampMap<String, u64>>()
        },
        |m| m.identity()[0] as u64,
    );
    let warm = champ.clone();
    let base_id = warm.identity();
    measure(
        "merkle-champ identity after one write",
        probes.len(),
        || {
            probes
                .iter()
                .map(|&i| warm.update(keys[i].clone(), 11).identity()[0] as u64)
                .sum()
        },
    );
    let few = &probes[..4.min(probes.len())];
    measure(
        "imbl HashMap layered identity (sort+hash all)",
        few.len(),
        || {
            few.iter()
                .map(|&i| layered_identity(imh.update(keys[i].clone(), 11).iter())[0] as u64)
                .sum()
        },
    );
    measure(
        "imbl OrdMap layered identity (hash all, sorted)",
        few.len(),
        || {
            few.iter()
                .map(|&i| layered_identity(imo.update(keys[i].clone(), 11).iter())[0] as u64)
                .sum()
        },
    );
    assert_eq!(warm.identity(), base_id);

    for changes in [1usize, 100, 10_000] {
        if changes > n {
            continue;
        }
        println!("  diff, {changes} changed entries");
        let mut c2 = champ.clone();
        let mut h2 = imh.clone();
        let mut o2 = imo.clone();
        let mut r = Rng(changes as u64);
        for _ in 0..changes {
            let i = r.next() as usize % n;
            c2.insert(keys[i].clone(), u64::MAX);
            h2.insert(keys[i].clone(), u64::MAX);
            o2.insert(keys[i].clone(), u64::MAX);
        }
        measure("merkle-champ structural diff", 1, || {
            champ.diff(&c2).len() as u64
        });
        measure("imbl OrdMap diff", 1, || imo.diff(&o2).count() as u64);
        measure("imbl HashMap layered diff (scan both)", 1, || {
            let mut d = h2.iter().filter(|(k, v)| imh.get(*k) != Some(v)).count();
            d += imh.iter().filter(|(k, _)| !h2.contains_key(*k)).count();
            d as u64
        });
    }

    // Independently constructed maps: equal contents except `changes`
    // entries, built separately (reverse insertion order), so no nodes are
    // shared and pointer equality cannot help either structure.
    for changes in [1usize, 100] {
        if changes > n {
            continue;
        }
        println!("  diff, {changes} changed entries, independently constructed (no shared nodes)");
        let mut r = Rng(changes as u64 + 99);
        let changed: Vec<usize> = (0..changes).map(|_| r.next() as usize % n).collect();
        let build_champ = || {
            let mut m: ChampMap<String, u64> = keys
                .iter()
                .enumerate()
                .rev()
                .map(|(i, k)| (k.clone(), i as u64))
                .collect();
            for &i in &changed {
                m.insert(keys[i].clone(), u64::MAX);
            }
            m
        };
        let build_ord = || {
            let mut m: ImOrd = keys
                .iter()
                .enumerate()
                .rev()
                .map(|(i, k)| (k.clone(), i as u64))
                .collect();
            for &i in &changed {
                m.insert(keys[i].clone(), u64::MAX);
            }
            m
        };
        measure_setup(
            "merkle-champ diff, no identities cached",
            1,
            build_champ,
            |other| champ.diff(other).len() as u64,
        );
        let base_with_id = champ.clone();
        base_with_id.identity();
        measure_setup(
            "merkle-champ diff, both identities cached",
            1,
            || {
                let m = build_champ();
                m.identity();
                m
            },
            |other| base_with_id.diff(other).len() as u64,
        );
        measure_setup("imbl OrdMap diff", 1, build_ord, |other| {
            imo.diff(other).count() as u64
        });
    }
}

fn main() {
    let sizes: Vec<usize> = match std::env::args().nth(1) {
        Some(n) => vec![n.parse().expect("size")],
        None => vec![100, 10_000, 1_000_000],
    };
    for n in sizes {
        run(n);
    }
}
