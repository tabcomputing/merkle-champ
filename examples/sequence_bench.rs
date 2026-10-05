//! `Sequence` against imbl's RRB `Vector`, which also inserts and joins in
//! logarithmic time but has no canonical shape and no identities, and
//! against `std::Vec`, which is mutable and keeps no old versions, on a
//! million `u64` and a million bytes. Each figure is the median of seven
//! samples after a warm-up, in nanoseconds per operation unless marked. Run
//! with `cargo run --release --example sequence_bench`.
use merkle_champ::{Identify, Identity, Sequence};
use std::collections::HashSet;
use std::hint::black_box;
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn time(ops: usize, mut f: impl FnMut()) -> f64 {
    f();
    let mut samples: Vec<f64> = (0..7)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos() as f64 / ops as f64
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[3]
}

fn show(ns: f64) -> String {
    if ns >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.1} µs", ns / 1e3)
    } else {
        format!("{ns:.1}")
    }
}

fn row(name: &str, seq: f64, rrb: f64, vec: Option<f64>) {
    let v = vec.map_or("—".to_string(), show);
    println!("| {name} | {} | {} | {v} |", show(seq), show(rrb));
}

trait Elem: Copy + Clone + Identify + Default {
    fn from(x: u64) -> Self;
    fn widen(self) -> u64;
}
impl Elem for u64 {
    fn from(x: u64) -> Self {
        x
    }
    fn widen(self) -> u64 {
        self
    }
}
impl Elem for u8 {
    fn from(x: u64) -> Self {
        x as u8
    }
    fn widen(self) -> u64 {
        self as u64
    }
}

/// All three are built from an iterator, to compare like with like.
#[allow(clippy::iter_cloned_collect)]
fn bench<T: Elem>(name: &str) {
    let n = 1_000_000usize;
    println!("\n## {n} {name}\n");
    println!("| Workload | Sequence | imbl RRB Vector | std Vec |");
    println!("|---|---:|---:|---:|");
    let mut source = Rng(0x9E37_79B9_7F4A_7C15);
    let data: Vec<T> = (0..n).map(|_| T::from(source.next() >> 7)).collect();
    let s: Sequence<T> = data.iter().copied().collect();
    let r: imbl::Vector<T> = data.iter().copied().collect();
    let mut rng = Rng(7);
    let idx: Vec<usize> = (0..1_000).map(|_| rng.next() as usize % n).collect();
    let few = &idx[..100];
    let fewer = &idx[..10];

    row(
        "build from an iterator, per element",
        time(n, || {
            black_box(data.iter().copied().collect::<Sequence<T>>());
        }),
        time(n, || {
            black_box(data.iter().copied().collect::<imbl::Vector<T>>());
        }),
        Some(time(n, || {
            black_box(data.iter().copied().collect::<Vec<T>>());
        })),
    );
    row(
        "get, random index",
        time(idx.len(), || {
            for &i in &idx {
                black_box(s.get(i));
            }
        }),
        time(idx.len(), || {
            for &i in &idx {
                black_box(r.get(i));
            }
        }),
        Some(time(idx.len(), || {
            for &i in &idx {
                black_box(data.get(i));
            }
        })),
    );
    row(
        "iterate, per element",
        time(n, || {
            black_box(s.iter().map(|x| x.widen()).sum::<u64>());
        }),
        time(n, || {
            black_box(r.iter().map(|x| x.widen()).sum::<u64>());
        }),
        Some(time(n, || {
            black_box(data.iter().map(|x| x.widen()).sum::<u64>());
        })),
    );
    row(
        "update one element, old version kept",
        time(few.len(), || {
            for &i in few {
                black_box(s.update(i, T::default()));
            }
        }),
        time(few.len(), || {
            for &i in few {
                black_box(r.update(i, T::default()));
            }
        }),
        None,
    );
    let mut copy = data.clone();
    row(
        "insert one element in the middle",
        time(fewer.len(), || {
            for &i in fewer {
                black_box(s.insert(i, T::default()));
            }
        }),
        time(fewer.len(), || {
            for &i in fewer {
                let mut w = r.clone();
                w.insert(i, T::default());
                black_box(w);
            }
        }),
        Some(time(fewer.len(), || {
            for &i in fewer {
                copy.insert(i, T::default());
                copy.remove(i);
            }
        }) / 2.0),
    );
    row(
        "remove one element in the middle",
        time(fewer.len(), || {
            for &i in fewer {
                black_box(s.remove(i));
            }
        }),
        time(fewer.len(), || {
            for &i in fewer {
                let mut w = r.clone();
                w.remove(i);
                black_box(w);
            }
        }),
        None,
    );
    let half = n / 2;
    let (sa, sb) = (s.slice(0..half), s.slice(half..n));
    let (ra, rb) = (r.clone().slice(0..half), r.clone().slice(half..n));
    row(
        "concat two halves",
        time(1, || {
            black_box(sa.concat(&sb));
        }),
        time(1, || {
            let mut w = ra.clone();
            w.append(rb.clone());
            black_box(w);
        }),
        None,
    );
    row(
        "slice the middle half",
        time(1, || {
            black_box(s.slice(n / 4..3 * n / 4));
        }),
        time(1, || {
            black_box(r.clone().slice(n / 4..3 * n / 4));
        }),
        None,
    );
    // Identities: imbl has none, so its column is hashing every element in
    // order, which a store would have to do per request.
    let layered = time(1, || {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for x in r.iter() {
            x.identify(&mut h);
        }
        black_box(h.finalize());
    });
    let fresh: Sequence<T> = data.iter().copied().collect();
    let cold = {
        let t = Instant::now();
        black_box(fresh.identity());
        t.elapsed().as_nanos() as f64
    };
    row("first identity, cold", cold, layered, None);
    black_box(s.identity());
    row(
        "identity after one insert in the middle",
        time(1, || {
            black_box(s.insert(n / 2, T::default()).identity());
        }),
        layered,
        None,
    );
    let old: HashSet<Identity> = s.node_ids().into_iter().collect();
    let new_nodes = s
        .insert(n / 2, T::default())
        .node_ids()
        .iter()
        .filter(|id| !old.contains(*id))
        .count();
    println!(
        "| new nodes after an insert in the middle | {new_nodes} of {} | — | — |",
        old.len()
    );
}

fn main() {
    bench::<u64>("u64");
    bench::<u8>("bytes");
}
