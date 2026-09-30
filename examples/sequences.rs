//! Integrated-cost benchmark for a namespaced store: realistic edit and
//! checkpoint sequences (part A) and transitive code-update propagation
//! (part B), comparing identity schemes under different identity-request
//! frequencies. A MODEL of March's store, not March execution.
//!
//!   RUSTFLAGS="-C target-feature=+popcnt" cargo run --release --example sequences [a|b] [10000|1000000]
//!
//! Candidates (all nested: namespace -> name -> value, all persistent):
//!   champ         ChampMap of ChampMaps; identity = cached Merkle root.
//!   imbl-full     imbl HashMap of HashMaps; identity = sort + hash everything
//!                 on every request (deterministic serialization).
//!   imbl-nscache  imbl as above plus a per-namespace digest cache with dirty
//!                 tracking; identity = rehash dirty namespaces (sort + hash
//!                 that namespace), then hash the sorted (namespace, digest)
//!                 list. The strongest cheap scheme layered on imbl.
//! Entry encoding for identity is the same `Identify` encoding in all three;
//! the digests differ between schemes by design (different framing).

use merkle_champ::{ChampMap, Identify, Identity};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

// ---------------------------------------------------- peak memory tracking

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
fn note(delta: isize) {
    let now = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    PEAK.fetch_max(now, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size() as isize);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        note(-(l.size() as isize));
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        note(n as isize - l.size() as isize);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;
fn reset_peak() -> isize {
    let now = LIVE.load(Ordering::Relaxed);
    PEAK.store(now, Ordering::Relaxed);
    now
}
fn peak_since(base: isize) -> f64 {
    (PEAK.load(Ordering::Relaxed) - base) as f64 / 1_048_576.0
}

// ------------------------------------------------------------------- misc

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const NAMESPACES: usize = 256;
fn ns(i: usize) -> String {
    format!("ns{:03}", i % NAMESPACES)
}

fn median(mut v: Vec<f64>) -> (f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    (v[0], v[v.len() / 2], v[v.len() - 1])
}

type Model<V> = BTreeMap<(String, String), V>;

// ------------------------------------------------------------- candidates

trait Store<V: Clone>: Clone {
    const NAME: &'static str;
    fn build(model: &Model<V>) -> Self;
    fn put(&mut self, ns: &str, name: &str, v: V);
    fn del(&mut self, ns: &str, name: &str);
    fn get(&self, ns: &str, name: &str) -> Option<V>;
    fn identity(&mut self) -> Identity;
    fn contents(&self) -> Model<V>;
    /// Same-lineage diff size between two checkpoints (optional workload).
    fn diff_len(&self, other: &Self) -> usize;
}

fn entry_digest<V: Identify>(pairs: &mut [(&String, &V)]) -> Identity {
    pairs.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    h.update(b"ns/v1");
    for (k, v) in pairs.iter() {
        k.identify(&mut h);
        v.identify(&mut h);
    }
    h.finalize().into()
}

fn root_digest<'a>(list: impl Iterator<Item = (&'a String, Identity)>) -> Identity {
    let mut all: Vec<_> = list.collect();
    all.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    h.update(b"root/v1");
    for (k, d) in all {
        k.identify(&mut h);
        h.update(d);
    }
    h.finalize().into()
}

// champ ---------------------------------------------------------------------

#[derive(Clone)]
struct Champ<V>(ChampMap<String, ChampMap<String, V>>);

impl<V: Clone + Identify + PartialEq> Store<V> for Champ<V> {
    const NAME: &'static str = "champ";
    fn build(model: &Model<V>) -> Self {
        let mut root: ChampMap<String, ChampMap<String, V>> = ChampMap::new();
        for ((n, k), v) in model {
            match root.get_mut(n) {
                Some(inner) => {
                    inner.insert(k.clone(), v.clone());
                }
                None => {
                    root.insert(n.clone(), ChampMap::new().update(k.clone(), v.clone()));
                }
            }
        }
        Champ(root)
    }
    fn put(&mut self, n: &str, k: &str, v: V) {
        let n = n.to_string();
        match self.0.get_mut(&n) {
            Some(inner) => {
                inner.insert(k.to_string(), v);
            }
            None => {
                self.0.insert(n, ChampMap::new().update(k.to_string(), v));
            }
        }
    }
    fn del(&mut self, n: &str, k: &str) {
        let n = n.to_string();
        let empty = match self.0.get_mut(&n) {
            Some(inner) => {
                inner.remove(&k.to_string());
                inner.is_empty()
            }
            None => false,
        };
        if empty {
            self.0.remove(&n);
        }
    }
    fn get(&self, n: &str, k: &str) -> Option<V> {
        self.0.get(&n.to_string())?.get(&k.to_string()).cloned()
    }
    fn identity(&mut self) -> Identity {
        self.0.identity()
    }
    fn contents(&self) -> Model<V> {
        let mut m = Model::new();
        for (n, inner) in self.0.iter() {
            for (k, v) in inner.iter() {
                m.insert((n.clone(), k.clone()), v.clone());
            }
        }
        m
    }
    fn diff_len(&self, other: &Self) -> usize {
        self.0.diff(&other.0).len()
    }
}

// imbl, full serialization ----------------------------------------------------

type Inner<V> = imbl::HashMap<String, V>;

#[derive(Clone)]
struct ImblFull<V: Clone>(imbl::HashMap<String, Inner<V>>);

fn imbl_build<V: Clone>(model: &Model<V>) -> imbl::HashMap<String, Inner<V>> {
    let mut root: imbl::HashMap<String, Inner<V>> = imbl::HashMap::new();
    for ((n, k), v) in model {
        root.entry(n.clone())
            .or_default()
            .insert(k.clone(), v.clone());
    }
    root
}
fn imbl_put<V: Clone>(root: &mut imbl::HashMap<String, Inner<V>>, n: &str, k: &str, v: V) {
    root.entry(n.to_string())
        .or_default()
        .insert(k.to_string(), v);
}
fn imbl_del<V: Clone>(root: &mut imbl::HashMap<String, Inner<V>>, n: &str, k: &str) {
    let empty = match root.get_mut(n) {
        Some(inner) => {
            inner.remove(k);
            inner.is_empty()
        }
        None => false,
    };
    if empty {
        root.remove(n);
    }
}
fn imbl_contents<V: Clone>(root: &imbl::HashMap<String, Inner<V>>) -> Model<V> {
    let mut m = Model::new();
    for (n, inner) in root.iter() {
        for (k, v) in inner.iter() {
            m.insert((n.clone(), k.clone()), v.clone());
        }
    }
    m
}
/// Same-lineage diff layered on imbl: skip namespaces whose inner map is the
/// same shared node (ptr_eq), scan the rest.
fn imbl_diff<V: Clone + PartialEq>(
    a: &imbl::HashMap<String, Inner<V>>,
    b: &imbl::HashMap<String, Inner<V>>,
) -> usize {
    let mut d = 0;
    let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for n in names {
        match (a.get(n), b.get(n)) {
            (Some(x), Some(y)) if x.ptr_eq(y) => {}
            (Some(x), Some(y)) => {
                d += y.iter().filter(|(k, v)| x.get(*k) != Some(v)).count();
                d += x.keys().filter(|k| !y.contains_key(*k)).count();
            }
            (Some(x), None) => d += x.len(),
            (None, Some(y)) => d += y.len(),
            (None, None) => {}
        }
    }
    d
}

impl<V: Clone + Identify + PartialEq> Store<V> for ImblFull<V> {
    const NAME: &'static str = "imbl-full";
    fn build(model: &Model<V>) -> Self {
        ImblFull(imbl_build(model))
    }
    fn put(&mut self, n: &str, k: &str, v: V) {
        imbl_put(&mut self.0, n, k, v)
    }
    fn del(&mut self, n: &str, k: &str) {
        imbl_del(&mut self.0, n, k)
    }
    fn get(&self, n: &str, k: &str) -> Option<V> {
        self.0.get(n)?.get(k).cloned()
    }
    fn identity(&mut self) -> Identity {
        root_digest(self.0.iter().map(|(n, inner)| {
            let mut pairs: Vec<_> = inner.iter().collect();
            (n, entry_digest(&mut pairs))
        }))
    }
    fn contents(&self) -> Model<V> {
        imbl_contents(&self.0)
    }
    fn diff_len(&self, other: &Self) -> usize {
        imbl_diff(&self.0, &other.0)
    }
}

// imbl, per-namespace digest cache ---------------------------------------------

#[derive(Clone)]
struct ImblNsCache<V: Clone> {
    root: imbl::HashMap<String, Inner<V>>,
    /// Digest per namespace; a write removes its namespace's entry.
    digests: imbl::HashMap<String, Identity>,
}

impl<V: Clone + Identify + PartialEq> Store<V> for ImblNsCache<V> {
    const NAME: &'static str = "imbl-nscache";
    fn build(model: &Model<V>) -> Self {
        ImblNsCache {
            root: imbl_build(model),
            digests: imbl::HashMap::new(),
        }
    }
    fn put(&mut self, n: &str, k: &str, v: V) {
        imbl_put(&mut self.root, n, k, v);
        self.digests.remove(n);
    }
    fn del(&mut self, n: &str, k: &str) {
        imbl_del(&mut self.root, n, k);
        self.digests.remove(n);
    }
    fn get(&self, n: &str, k: &str) -> Option<V> {
        self.root.get(n)?.get(k).cloned()
    }
    fn identity(&mut self) -> Identity {
        for (n, inner) in self.root.iter() {
            if !self.digests.contains_key(n) {
                let mut pairs: Vec<_> = inner.iter().collect();
                self.digests.insert(n.clone(), entry_digest(&mut pairs));
            }
        }
        let digests = &self.digests;
        root_digest(self.root.keys().map(|n| (n, digests[n])))
    }
    fn contents(&self) -> Model<V> {
        imbl_contents(&self.root)
    }
    fn diff_len(&self, other: &Self) -> usize {
        imbl_diff(&self.root, &other.root)
    }
}

// ------------------------------------------------------ part A: sequences

#[derive(Clone)]
enum Edit {
    Put(String, String, u64),
    Del(String, String),
}

/// Deterministic trace over a model: 60% replace an existing key, 20% insert
/// a new key, 20% delete an existing key. `clustered` sends 95% of edits to
/// namespaces 0 and 1; otherwise namespaces are uniform.
fn trace(model: &Model<u64>, edits: usize, clustered: bool, seed: u64) -> (Vec<Edit>, Model<u64>) {
    let mut rng = Rng(seed);
    let mut m = model.clone();
    let mut by_ns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, k) in m.keys() {
        by_ns.entry(n.clone()).or_default().push(k.clone());
    }
    let mut out = Vec::with_capacity(edits);
    for e in 0..edits {
        let target = if clustered && rng.below(100) < 95 {
            rng.below(2)
        } else {
            rng.below(NAMESPACES)
        };
        let n = ns(target);
        let names = by_ns.entry(n.clone()).or_default();
        let roll = rng.below(100);
        if roll < 20 || names.is_empty() {
            let k = format!("new{seed}.{e}");
            names.push(k.clone());
            let v = rng.next();
            m.insert((n.clone(), k.clone()), v);
            out.push(Edit::Put(n, k, v));
        } else if roll < 40 {
            let i = rng.below(names.len());
            let k = names.swap_remove(i);
            m.remove(&(n.clone(), k.clone()));
            out.push(Edit::Del(n, k));
        } else {
            let k = names[rng.below(names.len())].clone();
            let v = rng.next();
            m.insert((n.clone(), k.clone()), v);
            out.push(Edit::Put(n, k, v));
        }
    }
    (out, m)
}

struct Outcome {
    /// Whole-sequence elapsed time, including checkpoint handling.
    wall_ms: f64,
    /// Sum of timed updates and identity requests only.
    total_ms: f64,
    update_ms: f64,
    identity_ms: f64,
    checkpoints: usize,
    max_checkpoint_ms: f64,
    peak_mb: f64,
    diff_ms: f64,
    extrapolated: bool,
}

/// Runs one trace. `every` = identity request period (0 = end only).
/// Retains the previous checkpoint (or a window of them).
fn run_trace<S: Store<u64>>(
    start: &S,
    edits: &[Edit],
    every: usize,
    window: usize,
    limit: Option<usize>,
) -> (Outcome, S) {
    let mut s = start.clone();
    let mut retained: std::collections::VecDeque<S> = std::collections::VecDeque::new();
    retained.push_back(s.clone());
    let base = reset_peak();
    let wall = Instant::now();
    let (mut update, mut ident, mut max_cp, mut cps) = (0.0f64, 0.0f64, 0.0f64, 0usize);
    let run_edits = limit.map_or(edits.len(), |l| l.min(edits.len()));
    for (i, e) in edits[..run_edits].iter().enumerate() {
        let t = Instant::now();
        match e {
            Edit::Put(n, k, v) => s.put(n, k, *v),
            Edit::Del(n, k) => s.del(n, k),
        }
        update += t.elapsed().as_secs_f64();
        if every > 0 && (i + 1) % every == 0 {
            let t = Instant::now();
            black_box(s.identity());
            let dt = t.elapsed().as_secs_f64();
            ident += dt;
            max_cp = max_cp.max(dt);
            cps += 1;
            retained.push_back(s.clone());
            while retained.len() > window {
                retained.pop_front();
            }
        }
    }
    let t = Instant::now();
    black_box(s.identity());
    let dt = t.elapsed().as_secs_f64();
    ident += dt;
    max_cp = max_cp.max(dt);
    cps += 1;
    // Whole sequence, including checkpoint cloning, replacement and dropping.
    let wall_ms = wall.elapsed().as_secs_f64() * 1e3;
    let peak = peak_since(base);
    // Optional same-lineage diff between the last two checkpoints.
    let t = Instant::now();
    let prev = retained.front().cloned().unwrap_or_else(|| start.clone());
    black_box(prev.diff_len(&s));
    let diff_ms = t.elapsed().as_secs_f64() * 1e3;
    let scale = edits.len() as f64 / run_edits as f64;
    let extrapolated = run_edits < edits.len();
    (
        Outcome {
            wall_ms: wall_ms * scale,
            total_ms: (update + ident) * 1e3 * scale,
            update_ms: update * 1e3 * scale,
            identity_ms: ident * 1e3 * scale,
            checkpoints: (cps as f64 * scale) as usize,
            max_checkpoint_ms: max_cp * 1e3,
            peak_mb: peak,
            diff_ms,
            extrapolated,
        },
        s,
    )
}

fn part_a_candidate<S: Store<u64>>(
    model: &Model<u64>,
    traces: &[(&str, Vec<Edit>, Model<u64>)],
    size: usize,
    edits: usize,
) {
    for cached in [false, true] {
        let mut start = S::build(model);
        let t = Instant::now();
        let initial = if cached {
            black_box(start.identity());
            t.elapsed().as_secs_f64() * 1e3
        } else {
            0.0
        };
        // History independence of this scheme: the start built from a model
        // must have the same identity as the same contents built differently.
        for (dist, tr, expected) in traces {
            let quick = std::env::var("SEQ_QUICK").is_ok();
            if quick && !cached {
                continue;
            }
            let everies: &[usize] = if quick {
                &[1, 100, 0]
            } else {
                &[1, 100, 10_000, 0]
            };
            for &every in everies {
                if every > edits {
                    continue;
                }
                // Full serialization at 1M on every edit is extrapolated from
                // the first 25 edits to keep total runtime bounded.
                let limit =
                    (S::NAME == "imbl-full" && size >= 1_000_000 && every == 1).then_some(25);
                let mut totals = Vec::new();
                let mut results = Vec::new();
                for _rep in 0..3 {
                    // A cold start must be rebuilt every time: CHAMP caches
                    // identities inside nodes shared with `start`, so reusing
                    // it would make every later "cold" run warm.
                    let fresh;
                    let from = if cached {
                        &start
                    } else {
                        fresh = S::build(model);
                        &fresh
                    };
                    let (o, end) = run_trace(from, tr, every, 2, limit);
                    if limit.is_none() {
                        assert_eq!(&end.contents(), expected, "{} contents", S::NAME);
                    }
                    totals.push(o.wall_ms);
                    results.push(o);
                }
                let (lo, mid, hi) = median(totals);
                let r = &results[1];
                println!(
                    "  {:<13} {:<6} {:<9} every {:>6} | elapsed {:>10.2} ms [{:.2}-{:.2}] | updates+identity {:>10.2} | updates {:>9.2} | identity {:>10.2} ({:>5} req, max {:>8.3} ms) | peak {:>7.1} MB | diff {:>8.3} ms{}",
                    S::NAME,
                    if cached { "cached" } else { "cold" },
                    dist,
                    if every == 0 {
                        "end".to_string()
                    } else {
                        every.to_string()
                    },
                    mid,
                    lo,
                    hi,
                    r.total_ms,
                    r.update_ms,
                    r.identity_ms,
                    r.checkpoints,
                    r.max_checkpoint_ms,
                    r.peak_mb,
                    r.diff_ms,
                    if r.extrapolated {
                        "  (extrapolated from 25 edits)"
                    } else {
                        ""
                    }
                );
            }
        }
        if cached {
            println!(
                "  {:<13} initial identity (cold, reported separately): {:.2} ms",
                S::NAME,
                initial
            );
        }
    }
    // Retention cost of a window of 8 checkpoints, spread edits, every 100.
    let start = S::build(model);
    if let Some((_, tr, _)) = traces.iter().find(|t| t.0 == "spread") {
        let (o, _) = run_trace(&start, tr, 100, 8, None);
        println!(
            "  {:<13} window of 8 checkpoints, spread, every 100: peak {:.1} MB, total {:.2} ms",
            S::NAME,
            o.peak_mb,
            o.total_ms
        );
    }
    // History independence: final contents rebuilt directly give the same identity.
    let (_, tr, expected) = &traces[0];
    let (_, mut end) = run_trace(&start, tr, 0, 1, None);
    let mut direct = S::build(expected);
    assert_eq!(
        end.identity(),
        direct.identity(),
        "{} history independence",
        S::NAME
    );
    println!("  {:<13} history-independent identity: verified", S::NAME);
}

fn part_a(size: usize) {
    let edits = if size >= 1_000_000 { 2_000 } else { 10_000 };
    println!("\n== Part A: {size} entries, {edits} edits per trace, 3 reps (median [min-max]) ==");
    let model: Model<u64> = (0..size)
        .map(|i| ((ns(i), format!("w{i}")), i as u64))
        .collect();
    let (spread, spread_end) = trace(&model, edits, false, 1);
    let (clustered, clustered_end) = trace(&model, edits, true, 2);
    let traces = vec![
        ("spread", spread, spread_end),
        ("clustered", clustered, clustered_end),
    ];
    part_a_candidate::<Champ<u64>>(&model, &traces, size, edits);
    part_a_candidate::<ImblNsCache<u64>>(&model, &traces, size, edits);
    part_a_candidate::<ImblFull<u64>>(&model, &traces, size, edits);
}

// ------------------------------------------------ part B: code propagation

struct Graph {
    name: &'static str,
    /// refs[i]: indices of definitions i calls; always lower indices.
    refs: Vec<Vec<usize>>,
    changed: usize,
}

fn def_cid(lit: u64, children: &[Identity]) -> Identity {
    let mut h = Sha256::new();
    h.update(b"model-definition/v1");
    h.update(lit.to_le_bytes());
    for c in children {
        h.update(c);
    }
    h.finalize().into()
}

fn graphs() -> Vec<Graph> {
    let mut out = Vec::new();
    // A chain: each definition calls the previous one; change the bottom.
    let n = 2_000;
    out.push(Graph {
        name: "chain 2000",
        refs: (0..n)
            .map(|i| if i == 0 { vec![] } else { vec![i - 1] })
            .collect(),
        changed: 0,
    });
    // A DAG of 20,000 definitions, each calling 3 earlier ones chosen from a
    // recent window (overlapping caller paths).
    let n = 20_000;
    let mut rng = Rng(7);
    let dag: Vec<Vec<usize>> = (0..n)
        .map(|i| {
            if i < 50 {
                return vec![];
            }
            let mut r: Vec<usize> = (0..3).map(|_| i - 1 - rng.below(i.min(400))).collect();
            r.sort_unstable();
            r.dedup();
            r
        })
        .collect();
    // Local change: a definition near the top with few callers.
    out.push(Graph {
        name: "DAG 20000, local change",
        refs: dag.clone(),
        changed: n - 30,
    });
    // Widely shared leaf: definition 0, called by every 10th definition too.
    let mut wide = dag;
    for (i, r) in wide.iter_mut().enumerate() {
        if i > 0 && i % 10 == 0 && !r.contains(&0) {
            r.insert(0, 0);
        }
    }
    out.push(Graph {
        name: "DAG 20000, shared leaf",
        refs: wide,
        changed: 0,
    });
    out
}

fn part_b_candidate<S: Store<Identity>>(
    base: &Model<Identity>,
    graph: &Graph,
    new_cids: &[(usize, Identity)],
    expected: &Model<Identity>,
) {
    for cached in [true, false] {
        let mut times = Vec::new();
        let mut idts = Vec::new();
        let mut last = None;
        for _ in 0..3 {
            let mut s = S::build(base);
            if cached {
                s.identity();
            }
            let checkpoint = s.clone();
            let t = Instant::now();
            for (i, cid) in new_cids {
                s.put(&ns(*i), &format!("def{i}"), *cid);
            }
            let upd = t.elapsed().as_secs_f64() * 1e3;
            let t = Instant::now();
            black_box(s.identity());
            let idt = t.elapsed().as_secs_f64() * 1e3;
            times.push(upd);
            idts.push(idt);
            black_box(&checkpoint);
            last = Some(s);
        }
        let s = last.unwrap();
        assert_eq!(
            &s.contents(),
            expected,
            "{} bindings for {}",
            S::NAME,
            graph.name
        );
        let (_, u, _) = median(times);
        let (lo, i, hi) = median(idts);
        println!(
            "    {:<13} {:<6} binding updates {:>9.3} ms | final identity {:>10.3} ms [{:.3}-{:.3}] | layer 2 total {:>10.3} ms",
            S::NAME,
            if cached { "cached" } else { "cold" },
            u,
            i,
            lo,
            hi,
            u + i
        );
    }
}

fn part_b(size: usize) {
    println!(
        "\n== Part B: transitive code updates, store of ~{size} bindings (model, not March execution) =="
    );
    for graph in graphs() {
        let n = graph.refs.len();
        let lits: Vec<u64> = (0..n as u64).collect();
        // Original CIDs in dependency (index) order.
        let mut cids = Vec::with_capacity(n);
        for (i, lit) in lits.iter().enumerate() {
            let children: Vec<Identity> = graph.refs[i].iter().map(|&j| cids[j]).collect();
            cids.push(def_cid(*lit, &children));
        }
        // Layer 1: change one definition, propagate to reverse dependencies.
        let t = Instant::now();
        let mut callers = vec![Vec::new(); n];
        for (i, r) in graph.refs.iter().enumerate() {
            for &j in r {
                callers[j].push(i);
            }
        }
        let mut affected = BTreeSet::new();
        let mut stack = vec![graph.changed];
        while let Some(d) = stack.pop() {
            if affected.insert(d) {
                stack.extend(callers[d].iter().copied());
            }
        }
        let mut new = cids.clone();
        let mut recomputed = 0;
        for &d in &affected {
            // Ascending index order is dependency order: callees first.
            let lit = if d == graph.changed {
                lits[d] + 1_000_000
            } else {
                lits[d]
            };
            let children: Vec<Identity> = graph.refs[d].iter().map(|&j| new[j]).collect();
            new[d] = def_cid(lit, &children);
            recomputed += 1;
        }
        let layer1 = t.elapsed().as_secs_f64() * 1e3;
        assert_eq!(
            recomputed,
            affected.len(),
            "each affected definition recomputed once"
        );
        for i in 0..n {
            if !affected.contains(&i) {
                assert_eq!(new[i], cids[i], "unaffected CID changed");
            } else {
                assert_ne!(new[i], cids[i], "affected CID unchanged");
            }
        }
        println!(
            "  {}: {} definitions, {} affected (each recomputed once), layer 1 CID propagation {:.3} ms",
            graph.name,
            n,
            affected.len(),
            layer1
        );
        // Store: all definition bindings plus filler up to `size`.
        let mut base: Model<Identity> = (0..n)
            .map(|i| ((ns(i), format!("def{i}")), cids[i]))
            .collect();
        for i in 0..size.saturating_sub(n) {
            let mut h = Sha256::new();
            h.update((i as u64).to_le_bytes());
            base.insert((ns(i), format!("filler{i}")), h.finalize().into());
        }
        let changed_bindings: Vec<(usize, Identity)> =
            affected.iter().map(|&d| (d, new[d])).collect();
        let mut expected = base.clone();
        for (i, c) in &changed_bindings {
            expected.insert((ns(*i), format!("def{i}")), *c);
        }
        println!("    changed bindings: {}", changed_bindings.len());
        part_b_candidate::<Champ<Identity>>(&base, &graph, &changed_bindings, &expected);
        part_b_candidate::<ImblNsCache<Identity>>(&base, &graph, &changed_bindings, &expected);
        part_b_candidate::<ImblFull<Identity>>(&base, &graph, &changed_bindings, &expected);
    }
}

// --------------------------------------------- part C: development loop
//
// The inner loop of an interactive session: edit one definition, rebuild it
// and every transitive caller (so the next run uses the new code), update
// their bindings, then run, which requests the store identity (for example
// because caches are keyed by the store as context).
//
// Everything lives in ONE store, as in March: code by identity, name
// bindings, and a reverse-dependency index keyed by name. Old code entries
// are deleted when replaced (standing in for collection of unreferenced
// code), so the store does not grow without bound.

#[derive(Clone, PartialEq)]
struct Body {
    lit: u64,
    /// Callees by definition number (their names), for rebuilding.
    callee_names: Arc<[u32]>,
    /// Callees by identity; the definition identity covers lit + these.
    callees: Arc<[Identity]>,
}

#[derive(Clone, PartialEq)]
enum Val {
    Cid(Identity),
    Def(Arc<Body>),
    Names(Arc<[u32]>),
    Data(u64),
}

impl Identify for Val {
    fn identify<S: merkle_champ::Sink + ?Sized>(&self, h: &mut S) {
        match self {
            Val::Cid(c) => {
                h.update(&[0]);
                h.update(c);
            }
            Val::Def(b) => {
                h.update(&[1]);
                h.update(&b.lit.to_le_bytes());
                h.update(&(b.callees.len() as u64).to_le_bytes());
                for c in b.callees.iter() {
                    h.update(c);
                }
                for n in b.callee_names.iter() {
                    h.update(&n.to_le_bytes());
                }
            }
            Val::Names(n) => {
                h.update(&[2]);
                h.update(&(n.len() as u64).to_le_bytes());
                for x in n.iter() {
                    h.update(&x.to_le_bytes());
                }
            }
            Val::Data(x) => {
                h.update(&[3]);
                h.update(&x.to_le_bytes());
            }
        }
    }
}

/// Code is sharded into 256 namespaces by identity prefix, so a scheme that
/// caches per-namespace digests only rehashes the shards an edit touches.
fn code_ns(key: &str) -> String {
    format!("march.code.{}", &key[..2])
}

fn hex(c: &Identity) -> String {
    c.iter().map(|b| format!("{b:02x}")).collect()
}
fn user_ns(d: u32) -> String {
    format!("user.m{:03}", d / 100)
}
fn def_name(d: u32) -> String {
    format!("def{d}")
}

/// A modular program: `modules` modules of `per` definitions. A definition
/// calls up to 3 earlier definitions in its own module, and with 30%
/// probability also one of the 10 "exported" definitions of an earlier
/// module. Callees always have lower numbers than callers.
fn program(modules: u32, per: u32, seed: u64) -> Vec<Vec<u32>> {
    let mut rng = Rng(seed);
    let mut refs = Vec::new();
    for m in 0..modules {
        for i in 0..per {
            let d = m * per + i;
            let mut r = Vec::new();
            for _ in 0..3 {
                if i > 0 {
                    r.push(m * per + rng.below(i as usize) as u32);
                }
            }
            if m > 0 && rng.below(100) < 30 {
                let other = rng.below(m as usize) as u32;
                r.push(other * per + rng.below(10) as u32);
            }
            r.sort_unstable();
            r.dedup();
            let _ = d;
            refs.push(r);
        }
    }
    refs
}

fn dev_model(refs: &[Vec<u32>], filler: usize) -> Model<Val> {
    let n = refs.len() as u32;
    let mut model = Model::new();
    let mut cids: Vec<Identity> = Vec::with_capacity(n as usize);
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n as usize];
    for d in 0..n {
        let callees: Vec<Identity> = refs[d as usize].iter().map(|&c| cids[c as usize]).collect();
        let cid = def_cid(u64::from(d), &callees);
        cids.push(cid);
        model.insert(
            (code_ns(&hex(&cid)), hex(&cid)),
            Val::Def(Arc::new(Body {
                lit: u64::from(d),
                callee_names: refs[d as usize].clone().into(),
                callees: callees.into(),
            })),
        );
        model.insert((user_ns(d), def_name(d)), Val::Cid(cid));
        for &c in &refs[d as usize] {
            callers[c as usize].push(d);
        }
    }
    for d in 0..n {
        model.insert(
            ("march.callers".into(), def_name(d)),
            Val::Names(callers[d as usize].clone().into()),
        );
    }
    for i in 0..filler {
        model.insert((ns(i), format!("data{i}")), Val::Data(i as u64));
    }
    model
}

/// One edit-and-run cycle. Returns (affected definitions, propagation time,
/// identity time).
fn dev_cycle<S: Store<Val>>(s: &mut S, edited: u32, bump: u64, run: bool) -> (usize, f64, f64) {
    let t = Instant::now();
    // Transitive callers through the reverse index (store reads).
    let mut affected = BTreeSet::new();
    let mut stack = vec![edited];
    while let Some(d) = stack.pop() {
        if affected.insert(d)
            && let Some(Val::Names(cs)) = s.get("march.callers", &def_name(d))
        {
            stack.extend(cs.iter().copied());
        }
    }
    // Rebuild in dependency order (ascending numbers): read binding, read
    // body, read callees' current bindings, hash, write new code, rebind,
    // delete the replaced code entry.
    for &d in &affected {
        let Some(Val::Cid(old)) = s.get(&user_ns(d), &def_name(d)) else {
            unreachable!()
        };
        let old_key = hex(&old);
        let Some(Val::Def(body)) = s.get(&code_ns(&old_key), &old_key) else {
            unreachable!()
        };
        let callees: Vec<Identity> = body
            .callee_names
            .iter()
            .map(|&c| match s.get(&user_ns(c), &def_name(c)) {
                Some(Val::Cid(x)) => x,
                _ => unreachable!(),
            })
            .collect();
        let lit = if d == edited {
            body.lit.wrapping_add(bump)
        } else {
            body.lit
        };
        let cid = def_cid(lit, &callees);
        let new_key = hex(&cid);
        s.put(
            &code_ns(&new_key),
            &new_key,
            Val::Def(Arc::new(Body {
                lit,
                callee_names: body.callee_names.clone(),
                callees: callees.into(),
            })),
        );
        s.put(&user_ns(d), &def_name(d), Val::Cid(cid));
        if old != cid {
            s.del(&code_ns(&old_key), &old_key);
        }
    }
    let propagate = t.elapsed().as_secs_f64();
    let t = Instant::now();
    if run {
        black_box(s.identity());
    }
    (affected.len(), propagate, t.elapsed().as_secs_f64())
}

fn part_c_candidate<S: Store<Val>>(
    model: &Model<Val>,
    edits: &[u32],
    limit: Option<usize>,
) -> Model<Val> {
    let mut results = Vec::new();
    let mut last = None;
    for _ in 0..3 {
        let mut s = S::build(model);
        s.identity(); // a session starts from a store whose identity is known
        let mut previous = s.clone(); // the previous checkpoint stays alive
        let base = reset_peak();
        let wall = Instant::now();
        let n = limit.map_or(edits.len(), |l| l.min(edits.len()));
        let (mut aff, mut prop, mut idt) = (0usize, 0.0, 0.0);
        let mut max_cycle = 0.0f64;
        for (i, &d) in edits[..n].iter().enumerate() {
            let (a, p, t) = dev_cycle(&mut s, d, i as u64 + 1, true);
            aff += a;
            prop += p;
            idt += t;
            max_cycle = max_cycle.max(p + t);
            previous = s.clone();
        }
        black_box(&previous);
        drop(previous);
        let wall_ms = wall.elapsed().as_secs_f64() * 1e3;
        let scale = edits.len() as f64 / n as f64;
        results.push((
            wall_ms * scale,
            (prop + idt) * 1e3 * scale,
            prop * 1e3 * scale,
            idt * 1e3 * scale,
            aff as f64 / n as f64,
            max_cycle * 1e3,
            peak_since(base),
            n < edits.len(),
        ));
        last = Some(s);
    }
    results.sort_by(|a, b| a.0.total_cmp(&b.0));
    let r = results[1];
    println!(
        "  {:<13} {} cycles | elapsed {:>10.1} ms [{:.1}-{:.1}] | propagation+identity {:>10.1} | propagation {:>9.1} | run identity {:>10.1} | mean affected {:>7.1} | slowest cycle {:>8.2} ms | peak {:>6.1} MB{}",
        S::NAME,
        edits.len(),
        r.0,
        results[0].0,
        results[2].0,
        r.1,
        r.2,
        r.3,
        r.4,
        r.5,
        r.6,
        if r.7 { "  (extrapolated)" } else { "" }
    );
    let s = last.unwrap();
    if limit.is_none() {
        s.contents()
    } else {
        Model::new()
    }
}

fn part_c(filler: usize) {
    let refs = program(200, 100, 11);
    let n = refs.len() as u32;
    let model = dev_model(&refs, filler);
    // Edits: 80% within a working set of 30 definitions, 20% anywhere.
    let mut rng = Rng(12);
    let working: Vec<u32> = (0..30).map(|_| rng.below(n as usize) as u32).collect();
    let edits: Vec<u32> = (0..500)
        .map(|_| {
            if rng.below(100) < 80 {
                working[rng.below(30)]
            } else {
                rng.below(n as usize) as u32
            }
        })
        .collect();
    println!(
        "\n== Part C: development loop, {} definitions in 200 modules, store {} entries, 500 edit-run cycles (model) ==",
        n,
        model.len()
    );
    let a = part_c_candidate::<Champ<Val>>(&model, &edits, None);
    let b = part_c_candidate::<ImblNsCache<Val>>(&model, &edits, None);
    let full_limit = (model.len() > 200_000).then_some(20);
    let c = part_c_candidate::<ImblFull<Val>>(&model, &edits, full_limit);
    assert!(a == b, "champ and imbl-nscache end states differ");
    if !c.is_empty() {
        assert!(a == c, "champ and imbl-full end states differ");
    }
    println!("  end states verified equal across candidates");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let part = args.first().map(String::as_str).unwrap_or("ab");
    let sizes: Vec<usize> = match args.get(1) {
        Some(n) => vec![n.parse().expect("size")],
        None => vec![10_000, 1_000_000],
    };
    for size in sizes {
        if part.contains('a') {
            part_a(size);
        }
        if part.contains('b') {
            part_b(size);
        }
        if part.contains('c') {
            part_c(size.saturating_sub(60_000));
        }
    }
}
