# Benchmark summary, 2026-09-26

Machine: Intel Core Ultra 7 155H, Linux, Rust 1.90, release build with
`-C target-feature=+popcnt`, pinned to one CPU (`taskset -c 2`). Three
process runs (`run1.txt` .. `run3.txt`); each figure is the median of seven
samples after a warm-up. Numbers below are the range of those three medians,
in nanoseconds per operation unless marked. Keys are namespace-shaped strings
(`ns07.word1234`), 64 namespaces. imbl's HashMap uses the same fixed
deterministic hasher as merkle-champ.

| Workload | Size | merkle-champ | imbl HashMap | imbl OrdMap |
|---|---:|---:|---:|---:|
| lookup hit | 10k | 31–32 | 29 | 133–145 |
| lookup hit | 1M | 63–79 | 51–54 | 1,260–1,380 |
| lookup miss | 1M | 30–31 | 28–30 | 64–67 |
| write, old version kept | 10k | 1,091–1,141 | 972–1,008 | 1,380–1,470 |
| write, old version kept | 1M | 2,092–2,937 | 2,994–3,510 | 3,836–4,062 |
| write, sole owner | 1M | 77–84 | 77–83 | 430–459 |
| delete, old version kept | 1M | 3,230–3,332 | 3,184–3,420 | 3,670–4,020 |
| list one namespace (15,625 entries) | 1M | 83–87 µs nested | 49 ms (scan all) | 647–683 µs range |
| identity after one write | 1M | 6.9–7.6 µs | 372–390 ms, layered | 93–99 ms, layered |
| first identity, cold | 1M | 174–183 ms | (same as layered) | (same as layered) |
| diff, 1 change | 1M | 0.7–1.2 µs | 319–341 ms, layered | 0.9–1.3 µs |
| diff, 100 changes | 1M | 59–86 µs | 320–353 ms, layered | 54–66 µs |
| diff, 10,000 changes | 1M | 9.5 ms | 319–331 ms, layered | 9.3–9.5 ms |
| memory, bytes/entry incl. 26-byte keys | 1M | 97 | 181 | 87 |

"Layered" means built on top of the map from outside: identity by sorting and
hashing every entry, diff by scanning both versions. imbl exposes no
structural hashing, so this is what a store would have to do per request.

## Reading

- Hot path: within 1.5x of imbl's HashMap on every lookup and write, equal
  or faster on writes at 1M. Cold (cache-missing) lookups at 1M measured
  417 ns vs 400 ns in `examples/layout.rs`. Warm lookups remain slower,
  mostly per-level CPU overhead; `popcnt` matters (without it, ~30% slower).
- Identity after a write: about 50,000x faster than recomputing it on imbl,
  because only the changed path is rehashed. This is the property the store
  needs and the one imbl cannot provide.
- Diff: equal to OrdMap's structural diff for small change sets; slower
  (2.6x) at 10,000 changes on a 10,000-entry map, where most entries change
  and the prototype's diff allocates per entry. An optimization target.
- Cold first identity: about 1.9x slower than hashing a sorted OrdMap in one
  stream, because it finalizes one SHA-256 per node. Paid once per map.
- Namespace listing with one map per namespace level: faster than an ordered
  range scan.

## Addendum: independently constructed maps (after Codex's review)

Codex pointed out that pointer sharing helps diff between snapshots of one
lineage even without canonical shape, and asked for maps built independently.
Both maps below are built separately (reverse insertion order), so no node is
shared. One process run, pinned; medians of seven.

| Workload | Size | CHAMP, no identities | CHAMP, both identities cached | imbl OrdMap |
|---|---:|---:|---:|---:|
| diff, 1 change | 10k | 230 µs | 1.2 µs | 116 µs |
| diff, 100 changes | 10k | 237 µs | 36 µs | 114 µs |
| diff, 1 change | 1M | 111 ms | 16 µs | 75 ms |
| diff, 100 changes | 1M | 110 ms | 536 µs | 74 ms |

Without cached identities the CHAMP diff is a full walk and about 1.5x slower
than OrdMap's ordered merge. With identities already cached on both sides it
skips every equal subtree and is thousands of times faster, but computing a
cold identity costs 174–183 ms at 1M, so this only pays when identities
already exist, for example when they are persisted with a store image.

The test `both_identity_schemes_are_history_independent` confirms that the
layered identity used for imbl (sort + hash all entries) is history-independent
too, as Codex noted: canonical internal shape is not required for canonical
identity. What canonical shape buys is the incremental cost, not correctness.

## Addendum 2: integrated sequences (`examples/sequences.rs`), after Codex's and Thomas's requests

Three candidates, all nested per namespace: `champ` (cached Merkle root),
`imbl-nscache` (imbl plus a per-namespace digest cache with dirty tracking,
the strongest cheap scheme layered on imbl), `imbl-full` (sort and hash
everything per request). Same `Identify` entry encoding; digests differ by
scheme. 256 namespaces. Final contents checked against a model; each scheme's
identity checked history-independent. Pinned CPU, 3 repetitions, medians.

Files: `sequences-A-10k.txt`, `sequences-A-1M.txt` (part A, CORRECTED);
`sequences-10k.txt`, `sequences-1M.txt` (parts B and C are valid; their
part A sections are superseded, see the correction below).

**Correction.** The first part-A run reused one starting map for every
repetition. CHAMP caches identities in nodes shared with that map, so every
"cold" CHAMP run after the first was actually warm. Cold starts are now
rebuilt per repetition; the `-A-` files are the corrected runs.

### A. Edit and checkpoint sequences, total ms (updates + requested identities)

60% replace, 20% insert, 20% delete; previous checkpoint retained.
10k entries: 10,000 edits. 1M entries: 2,000 edits (imbl-full at 1M with
identity after every edit is extrapolated from 25 edits).

| Store, start | Edits | Identity requested | champ | imbl-nscache | imbl-full |
|---|---|---|---:|---:|---:|
| 10k, cached | spread | every edit | 28.7 | 293 | 5,679 |
| 10k, cached | spread | every 100 | 14.4 | 30.1 | 65.4 |
| 10k, cached | spread | end only | 4.2 | 2.4 | 2.2 |
| 10k, cached | clustered | every 100 | 4.4 | 6.6 | 57.7 |
| 1M, cached | spread | every edit | 14.8 | 790 | ~192,600 |
| 1M, cached | spread | every 100 | 14.1 | 614 | 1,969 |
| 1M, cached | spread | end only | 9.3 | 97.9 | 98.0 |
| 1M, cached | clustered | every 100 | 3.5 | 48.5 | 1,955 |
| 1M, cold | spread | end only | 77.0 | 99.1 | 101.7 |

Cold starts at 1M cost CHAMP about 72 ms once for the first identity, after
which requests are incremental. Where identity is requested rarely on a small
store, imbl is 1.5-2x cheaper (plain updates are faster); everywhere else CHAMP
is cheaper, by 10-50x against the namespace cache at 1M.

### B. Transitive code updates, store of 1M bindings, starting from a known identity

Layer 1 (propagating definition identities through dependents, same for all
candidates in this model): 0.3 ms chain, 0.8 ms local, 6.1 ms shared leaf.
Layer 2 (batch binding updates + one final identity), ms:

| Change | Affected | champ | imbl-nscache | imbl-full |
|---|---:|---:|---:|---:|
| chain of 2,000 | 2,000 | 10.1 | 122 | 122 |
| local, DAG of 20,000 | 1 | 0.02 | 0.52 | 116 |
| shared leaf, DAG of 20,000 | 19,925 | 55 | 159 | 159 |

### C. Development loop (Thomas's scenario), 500 edit-run cycles

One store holds code by identity (256 shards), name bindings, and a
reverse-dependency index. Each cycle: edit one definition (80% in a working
set of 30), find transitive callers through the index, rebuild each in
dependency order with store reads, write new code, rebind, delete the replaced
code, then run, which requests the store identity. 20,000 definitions in 200
modules; mean 51.7 definitions rebuilt per edit.

| Store | champ | imbl-nscache | imbl-full |
|---|---:|---:|---:|
| 60k entries | 235 ms (0.47 ms/cycle) | 638 ms | 6,339 ms |
| 1M entries | 249 ms (0.50 ms/cycle) | 712 ms | ~53,800 ms (extrapolated) |

Propagation (reads, hashing, writes) costs about the same for all three
(162-200 ms per 500 cycles); the per-run store identity is the difference.
With code unsharded in one namespace, imbl-nscache took 2.9 s at 60k.

### Limitations

A model, not March execution: synthetic definitions, a synthetic program
graph, and an assumed identity request per run. The reverse index is keyed by
name and read-only (edits change bodies, not call structure). Old code is
deleted on replacement to stand in for collection. No image I/O. imbl-full's
largest cases are extrapolated. Single machine, one CPU.

## Addendum 3: whole-sequence elapsed time (2026-09-26 hardening pass)

Codex noted that the earlier "total" figures were sums of timed updates and
identity requests, not end-to-end time. The harness now also reports elapsed
time for the whole sequence, including cloning, replacing and dropping
checkpoints. Earlier outputs are kept unchanged and remain labeled as
sums. Representative cases were rerun (cached starts; spread and clustered
edits; identity after every edit, every 100 edits, and at the end; the
development loop), in `2026-09-26-elapsed/`. One process run per size,
3 repetitions, medians. Absolute times in this run are 5-20% higher than the
earlier runs for the same code paths (run-to-run host variation plus the added
timer).

| Case | champ elapsed | imbl-nscache elapsed | imbl-full elapsed |
|---|---:|---:|---:|
| 10k, spread, identity every 100 | 18.0 ms | 36.2 ms | 74.4 ms |
| 10k, spread, end only | 4.8 ms | 3.0 ms | 2.8 ms |
| 1M, spread, identity every 100 | 17.7 ms | 680 ms | 2,141 ms |
| 1M, spread, end only | 10.6 ms | 108 ms | 107 ms |
| Dev loop, 500 cycles, 60k store | 315 ms | 962 ms | 7,127 ms |
| Dev loop, 500 cycles, 1M store | 304 ms | 865 ms | ~58,900 ms (extrapolated) |

Elapsed time exceeds the summed subtimings by about 1-20% (checkpoint
handling, loop overhead); the ranking and ratios are unchanged. For imbl-full
cases extrapolated from 25 edits, elapsed and summed figures are each scaled
and can cross slightly.
