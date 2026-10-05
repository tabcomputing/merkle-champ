//! The content-defined `Sequence` prototype against the dense `Vector`, on
//! a million `u64` and a million bytes. Each figure is the median of seven
//! samples after a warm-up, in nanoseconds per operation unless marked. Run
//! with `cargo run --release --example sequence_bench`.
//!
//! `Vector` has no insert or remove; they are done as slice, push and concat,
//! which copy, as a user would have to.
use merkle_champ::{Identify, Identity, Sequence, Vector};
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

fn row(name: &str, seq: f64, vec: f64) {
    println!("| {name} | {} | {} |", show(seq), show(vec));
}

trait Elem: Copy + Identify + Default + std::ops::Add<Output = Self> {
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

fn bench<T: Elem>(name: &str) {
    let n = 1_000_000usize;
    println!("\n## {n} {name}\n");
    println!("| Workload | Sequence | Vector |");
    println!("|---|---:|---:|");
    let mut source = Rng(0x9E37_79B9_7F4A_7C15);
    let data: Vec<T> = (0..n).map(|_| T::from(source.next() >> 7)).collect();
    let s: Sequence<T> = data.iter().copied().collect();
    let v: Vector<T> = data.iter().copied().collect();
    let mut rng = Rng(7);
    let idx: Vec<usize> = (0..1_000).map(|_| rng.next() as usize % n).collect();

    row(
        "build from an iterator, per element",
        time(n, || {
            black_box(data.iter().copied().collect::<Sequence<T>>());
        }),
        time(n, || {
            black_box(data.iter().copied().collect::<Vector<T>>());
        }),
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
                black_box(v.get(i));
            }
        }),
    );
    row(
        "iterate, per element",
        time(n, || {
            black_box(s.iter().map(|x| x.widen()).sum::<u64>());
        }),
        time(n, || {
            black_box(v.iter().map(|x| x.widen()).sum::<u64>());
        }),
    );
    let few = &idx[..100];
    row(
        "update one element, old version kept",
        time(few.len(), || {
            for &i in few {
                black_box(s.update(i, T::default()));
            }
        }),
        time(few.len(), || {
            for &i in few {
                black_box(v.update(i, T::default()));
            }
        }),
    );
    let fewer = &idx[..10];
    row(
        "insert one element in the middle",
        time(fewer.len(), || {
            for &i in fewer {
                black_box(s.insert(i, T::default()));
            }
        }),
        time(fewer.len(), || {
            for &i in fewer {
                let mut w = v.slice(0..i);
                w.push(T::default());
                black_box(w.concat(&v.slice(i..n)));
            }
        }),
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
                black_box(v.slice(0..i).concat(&v.slice(i + 1..n)));
            }
        }),
    );
    let half = n / 2;
    let (sa, sb) = (s.slice(0..half), s.slice(half..n));
    let (va, vb) = (v.slice(0..half), v.slice(half..n));
    row(
        "concat two halves",
        time(1, || {
            black_box(sa.concat(&sb));
        }),
        time(1, || {
            black_box(va.concat(&vb));
        }),
    );
    row(
        "slice the middle half",
        time(1, || {
            black_box(s.slice(n / 4..3 * n / 4));
        }),
        time(1, || {
            black_box(v.slice(n / 4..3 * n / 4));
        }),
    );
    let cold = |f: &dyn Fn() -> Identity| {
        let t = Instant::now();
        black_box(f());
        t.elapsed().as_nanos() as f64
    };
    let fresh_s: Sequence<T> = data.iter().copied().collect();
    let fresh_v: Vector<T> = data.iter().copied().collect();
    row(
        "first identity, cold",
        cold(&|| fresh_s.identity()),
        cold(&|| fresh_v.identity()),
    );
    black_box(s.identity());
    black_box(v.identity());
    row(
        "identity after one update",
        time(1, || {
            black_box(s.update(n / 2, T::default()).identity());
        }),
        time(1, || {
            black_box(v.update(n / 2, T::default()).identity());
        }),
    );
    row(
        "identity after one insert in the middle",
        time(1, || {
            black_box(s.insert(n / 2, T::default()).identity());
        }),
        time(1, || {
            let mut w = v.slice(0..n / 2);
            w.push(T::default());
            black_box(w.concat(&v.slice(n / 2..n)).identity());
        }),
    );
    let old: HashSet<Identity> = s.node_ids().into_iter().collect();
    let new_nodes = s
        .insert(n / 2, T::default())
        .node_ids()
        .iter()
        .filter(|id| !old.contains(*id))
        .count();
    println!(
        "| new nodes after an insert in the middle | {new_nodes} of {} | every leaf after it |",
        old.len()
    );
}

fn main() {
    bench::<u64>("u64");
    bench::<u8>("bytes");
}
