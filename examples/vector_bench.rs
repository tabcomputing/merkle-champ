//! Timings against imbl's Vector (an RRB tree, no content identities) and
//! std's Vec. Each figure is the median of seven samples after a warm-up, in
//! nanoseconds per operation unless marked. Run with
//! `cargo run --release --example vector_bench`.
use merkle_champ::Vector;
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

/// Median nanoseconds per operation of `ops` operations done by `f`.
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

fn row(name: &str, mv: f64, imbl: f64, vec: Option<f64>) {
    let v = vec.map_or("—".to_string(), |v| format!("{v:.1}"));
    println!("| {name} | {mv:.1} | {imbl:.1} | {v} |");
}

fn main() {
    for n in [10_000usize, 1_000_000] {
        println!("\n## {n} elements\n");
        println!("| Workload | Vector | imbl Vector | std Vec |");
        println!("|---|---:|---:|---:|");
        let mv: Vector<u64> = (0..n as u64).collect();
        let im: imbl::Vector<u64> = (0..n as u64).collect();
        let sv: Vec<u64> = (0..n as u64).collect();
        let mut rng = Rng(7);
        let idx: Vec<usize> = (0..10_000).map(|_| rng.next() as usize % n).collect();

        row(
            "build from an iterator (per element)",
            time(n, || {
                black_box((0..n as u64).collect::<Vector<u64>>());
            }),
            time(n, || {
                black_box((0..n as u64).collect::<imbl::Vector<u64>>());
            }),
            Some(time(n, || {
                black_box((0..n as u64).collect::<Vec<u64>>());
            })),
        );
        row(
            "get, random index",
            time(idx.len(), || {
                for &i in &idx {
                    black_box(mv.get(i));
                }
            }),
            time(idx.len(), || {
                for &i in &idx {
                    black_box(im.get(i));
                }
            }),
            Some(time(idx.len(), || {
                for &i in &idx {
                    black_box(sv.get(i));
                }
            })),
        );
        row(
            "iterate (per element)",
            time(n, || {
                black_box(mv.iter().sum::<u64>());
            }),
            time(n, || {
                black_box(im.iter().sum::<u64>());
            }),
            Some(time(n, || {
                black_box(sv.iter().sum::<u64>());
            })),
        );
        row(
            "set, old version kept",
            time(idx.len(), || {
                for &i in &idx {
                    black_box(mv.update(i, 1));
                }
            }),
            time(idx.len(), || {
                for &i in &idx {
                    black_box(im.update(i, 1));
                }
            }),
            None,
        );
        let mut mv2 = mv.clone();
        let mut im2 = im.clone();
        mv2.set(0, 0).unwrap();
        im2.set(0, 0);
        row(
            "set, sole owner",
            time(idx.len(), || {
                for &i in &idx {
                    mv2.set(i, 2).unwrap();
                }
            }),
            time(idx.len(), || {
                for &i in &idx {
                    im2.set(i, 2);
                }
            }),
            None,
        );
        row(
            "push then pop, sole owner",
            time(10_000, || {
                for i in 0..10_000u64 {
                    mv2.push(i);
                }
                for _ in 0..10_000 {
                    mv2.pop();
                }
            }) / 2.0,
            time(10_000, || {
                for i in 0..10_000u64 {
                    im2.push_back(i);
                }
                for _ in 0..10_000 {
                    im2.pop_back();
                }
            }) / 2.0,
            None,
        );
        // Identity: the first is cold (every node hashed); after one write
        // only the changed path is. imbl has no structural identity, so the
        // comparison is hashing every element in order.
        let cold = {
            let t = Instant::now();
            black_box(mv.identity());
            t.elapsed().as_nanos() as f64
        };
        let after_write = time(1, || {
            let v = mv.update(n / 2, 9);
            black_box(v.identity());
        });
        let layered = time(1, || {
            use merkle_champ::Identify;
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for x in im.iter() {
                x.identify(&mut h);
            }
            black_box(h.finalize());
        });
        println!("| first identity, cold | {:.2} ms | — | — |", cold / 1e6);
        println!(
            "| identity after one write | {:.2} µs | {:.2} ms, layered | — |",
            after_write / 1e3,
            layered / 1e6
        );
    }
    bytes();
}

/// Bytes, packed 1,024 to a leaf, against a `Vec<u8>`, whose content
/// identity is a SHA-256 of the whole buffer, recomputed after any write.
/// Both are built from an iterator, to compare like with like.
#[allow(clippy::iter_cloned_collect)]
fn bytes() {
    let n = 1_000_000usize;
    println!("\n## {n} bytes\n");
    println!("| Workload | Vector<u8> | std Vec<u8> |");
    println!("|---|---:|---:|");
    let data: Vec<u8> = (0..n).map(|i| (i * 31 % 251) as u8).collect();
    let mv: Vector<u8> = data.iter().copied().collect();
    let mut rng = Rng(9);
    let idx: Vec<usize> = (0..10_000).map(|_| rng.next() as usize % n).collect();
    let pair = |name: &str, a: f64, b: f64| println!("| {name} | {a:.2} | {b:.2} |");
    pair(
        "build from an iterator (per byte)",
        time(n, || {
            black_box(data.iter().copied().collect::<Vector<u8>>());
        }),
        time(n, || {
            black_box(data.iter().copied().collect::<Vec<u8>>());
        }),
    );
    pair(
        "get, random index",
        time(idx.len(), || {
            for &i in &idx {
                black_box(mv.get(i));
            }
        }),
        time(idx.len(), || {
            for &i in &idx {
                black_box(data.get(i));
            }
        }),
    );
    pair(
        "iterate (per byte)",
        time(n, || {
            black_box(mv.iter().map(|&b| b as u64).sum::<u64>());
        }),
        time(n, || {
            black_box(data.iter().map(|&b| b as u64).sum::<u64>());
        }),
    );
    let flat = |d: &[u8]| {
        use sha2::{Digest, Sha256};
        let out: [u8; 32] = Sha256::digest(d).into();
        out
    };
    let cold = {
        let t = Instant::now();
        black_box(mv.identity());
        t.elapsed().as_nanos() as f64
    };
    println!(
        "| first identity, cold | {:.2} ms | {:.2} ms, flat SHA-256 |",
        cold / 1e6,
        time(1, || {
            black_box(flat(&data));
        }) / 1e6
    );
    let mut copy = data.clone();
    println!(
        "| identity after one write | {:.2} µs | {:.2} µs, flat SHA-256 |",
        time(1, || {
            let v = mv.update(n / 2, 9);
            black_box(v.identity());
        }) / 1e3,
        time(1, || {
            copy[n / 2] = 9;
            black_box(flat(&copy));
        }) / 1e3
    );
}
