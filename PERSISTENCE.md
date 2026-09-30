# Persistence: disk, network and history (design note)

**Status: proposal.** Phase 1's node codec is implemented in merkle-champ
0.2 (unreleased), without I/O as Addendum B recommends: `Sink`, `Decode`,
`Objects`, `ChampMap::save` and `ChampMap::load`, specified in FORMAT.md
section 9. The rest is not implemented. Written 2026-09-29 in a Pandora
session with Thomas, for discussion with March and Axiom. Nothing here changes
the identity format in [FORMAT.md](FORMAT.md). That is deliberate: the
format-v1 preimage turns out to be a good storage format too.

## 0. Why

A `ChampMap` lives in memory. Two projects need it to live beyond one process:

- **March** needs store *images*: "a serialized store" that a host loads to run
  a named entry word, rebuilt byte-identically across generations
  (march6/docs/FOUNDATION-CLAUDE.md, STORE.md "no store-image format yet").
- **Pandora** (an online operating environment) needs a home for each user's
  data. Devices keep a partial cache, the server keeps the durable copy, and
  devices sync with each other. Past versions serve as backups.

Both are the same shape: a namespaced, content-addressed, persistent map whose
versions are roots. The goal is a map whose nodes can be in memory, on disk or
on a server, found by identity along one lookup path, with history on top.

## 1. Principles

1. **The identity format does not change.** A stored node is exactly its
   format-v1 identity preimage (§2), so existing identities, including March's
   store CIDs, stay valid.
2. **The in-memory hot path does not get slower.** A fully loaded map costs the
   same as today; laziness costs only where it is used.
3. **Everything read from outside is verified.** A node's bytes must hash to
   the identity it was requested by. A store or peer can withhold data, but
   never forge it.
4. **Work is proportional to change.** Saving a new version, and syncing it,
   touch only the nodes on the changed paths.
5. **One kind of mutable state.** Nodes, values and commits are immutable and
   content-addressed. The only mutable things are named refs, which point at
   commits and are updated by compare-and-swap.

## 2. A stored node is its identity preimage

FORMAT.md §4 defines a branch's identity as the SHA-256 of

```
"merkle-champ/branch/v1" || datamap || nodemap
  || Identify(key) || Identify(value) ...   (entries, in order)
  || identity(child) ...                     (children, in order)
```

and a collision node's similarly. Store a node as **exactly those bytes**, and:

- **Loading verifies itself:** `sha256(bytes) == identity`, as with Git objects.
- **The bytes fully determine the node.** Entry and child counts come from the
  bitmaps (or the collision count), entries decode because encodings are
  self-delimiting (FORMAT.md §5), and a collision node's full hash is
  recomputed from any of its keys.
- **Children are references.** A branch stores its children's 32-byte
  identities, not their bytes. A nested map value (`m`, FORMAT.md §5) is
  likewise a reference to another root. So every namespace level is a
  separately loadable tree, which is what makes partial loading and partial
  sync natural (§4, §7).
- The **empty map** is the 30-byte preimage `"merkle-champ/branch/v1" || 0u32 || 0u32`.

The one field that is not in the preimage is the header's subtree `size`. It is
not needed for identity, and computing it lazily (§4) keeps the format
unchanged. The alternative, a format v2 that hashes the size, is listed as an
open question (§14).

A storage backend may compress the bytes (zstd, say). Verification always
applies to the uncompressed preimage.

## 3. One encoder, two sinks

Today `Identify::identify(&self, hasher: &mut Sha256)` writes the encoding
straight into a hasher. Persistence needs the same bytes in a buffer, plus a
decoder.

Proposal: `Identify` writes into a small `Sink` trait (`fn update(&mut self,
bytes: &[u8])`), implemented by `Sha256` and by `Vec<u8>`. The same code then
produces both the identity and the stored bytes, so the two can never
disagree. A new `Decode` trait reads a value back:

```rust
trait Decode: Sized {
    fn decode(input: &mut &[u8], cx: &DecodeContext) -> Result<Self, DecodeError>;
}
```

`DecodeContext` carries the store handle, so decoding a nested map value
yields a map whose root is a stub (§4) in the same store. Provided types get
`Decode` implementations matching their FORMAT.md §5 tags. A decoder rejects
unknown tags, bad lengths and trailing bytes.

This is a breaking API change (0.2). The identity format is untouched, so
maps keep their identities. March implements `Identify` for its own store
entries (march6/docs/STORE.md, "Identity contract": byte `0` or `1`, domain,
CID) and would adapt to the new signature.

## 4. Lazy children: stubs

Add a fourth slot variant:

```rust
enum Slot<K, V> {
    Header(Header),
    Entry(K, V),
    Child(Node<K, V>),
    Stub(Arc<Stub<K, V>>),   // a child known only by identity, loaded on demand
}

struct Stub<K, V> {
    identity: Identity,
    store: Arc<dyn NodeStore>,
    node: OnceLock<Node<K, V>>,  // filled on first access
}
```

- **The hot path is unchanged.** Every traversal already matches on the slot
  kind, so a fully loaded map never takes the new arm.
- **Loaded nodes arrive with their identity cached,** because they were
  requested by it. `diff` and equality already skip subtrees whose cached
  identities match, so comparing a local version with a stored or remote one
  loads only the differing paths. A stub itself never needs loading for that.
- **Reads that may reach a stub are fallible,** because loading can fail
  (missing data, network down): `try_get`, `try_iter`, `try_diff`, `try_len`.
  The infallible API remains for maps with no stubs (every map today). Which
  API shape is best is open (§14).
- **Writes through a stubbed path** load that path and replace the stubs on it
  with ordinary `Child` slots in the copied nodes, as copy-on-write already
  replaces shared nodes.
- **Size is computed lazily.** A loaded node's `size` is unknown until its
  subtree is loaded. `len()` on a store-backed map becomes `try_len()`. The one
  internal use, removal's re-inlining check (`size(child) == 2`), only needs
  "does this child hold exactly two entries?". A node can usually answer that
  from its own slots, since every child holds at least two entries. Only along
  a chain of single-child branches does it load the next node down.
- **Memory:** a stub keeps its node once loaded, for the life of that version.
  That keeps the borrowing read API sound. Memory is reclaimed by dropping
  versions, or by `unload()`, which returns an equal version whose saved
  subtrees are stubs again. Byte caches belong to the store (§6).
- **Received nodes are checked** for local canonical form as they are decoded.
  That means disjoint bitmaps, each key at the fragment its hash selects at
  this depth (a stub knows its depth), and no singleton below the root. So
  data from an untrusted peer cannot introduce a non-canonical shape.

## 5. Saving

`map.save(&store)` writes every node that is not yet in the store, children
before parents. Each node's bytes come from the encoder (§3), and its identity
is the one `identity()` computes or has cached.

- **A saved flag in the header** records that a node is in the map's store.
  It is cleared at exactly the points where the cached identity is cleared
  today (`insert`, `remove` and `get_mut` on the copied path). Loaded nodes
  and stubs are saved by definition.
  (In conversation I said a cached identity could double as the saved flag.
  It can't: `identity()` can be called without saving.)
- **Cost is the changed path.** After one write to a saved map, only the nodes
  on that path, about five at 1M entries, are unsaved. This is the same
  property the benchmarks measure for identity after a write (7 µs at 1M).
- **Out-of-line values are saved too.** A `persist` hook on values (default:
  nothing) lets a nested `ChampMap` save itself and a blob reference save its
  blob (§10). March's frozen values would save their DAG under their CID this
  way.
- `put` is idempotent (same identity, same bytes), so saving twice, or two
  devices saving the same subtree, is harmless.

## 6. Stores

```rust
trait NodeStore: Send + Sync {
    fn get_many(&self, ids: &[Identity]) -> Result<Vec<Option<Bytes>>, StoreError>;
    fn put_many(&self, objects: &[(Identity, Bytes)]) -> Result<(), StoreError>;
    fn has_many(&self, ids: &[Identity]) -> Result<Vec<bool>, StoreError>;
}
```

The API is batched from the start, because remote round trips dominate. Single
calls are conveniences on top. Planned implementations:

- **Memory.** Tests, and the top tier of a cache.
- **Pack.** An append-only file of objects plus an index by identity. This is
  the on-disk form, and also March's **image** format (§6.1).
- **Remote.** HTTP to a server that itself uses packs or object storage.
- **Tiered.** Memory, then disk, then remote: read-through, with write-back
  to the next tier. Verification happens once, where bytes enter from outside.

### 6.1 Images

`pack(root)` writes every object reachable from `root` in one canonical order.
That order is preorder in trie order: root first, so a lazily opened image
reads its hot top levels together. Nested roots come at their first reference,
and there are no timestamps or other incidental data. **Equal contents give
byte-identical images**, which is what March's generation fixed point needs
("generations 2 and 3 are byte-identical"). Opening an image loads only the
root. Everything else is stubs until touched.

## 7. Sync

- **With a common base,** which is the usual case once history exists (§8),
  it takes one round trip. The sender walks `base` against `new`, never
  descending where identities are equal, and sends every object reachable from
  `new` but not from `base` as one pack. The receiver verifies and stores the
  objects, then moves the ref with compare-and-swap. This is Git's
  negotiation, with the diff walk doing the work.
- **Without a base,** it negotiates level by level: send `has_many` for the
  children of the nodes that differ, and descend only into the missing ones.
  That costs one round trip per trie level, about four at 1M entries, plus one
  per nesting level.
- **The fanout stays 32.** Batching solves the round-trip problem, and a larger
  fanout would change the format.
- **Partial replication falls out of nesting.** Each namespace is its own
  subtree, so a device can hold some namespaces in full (pinned for offline
  use) and keep others as stubs to be fetched on demand.

## 8. History

This is a layer above the map, in the same store:

- **Commit:** an immutable object (its own domain string) holding the root
  identity, the parent commit identities, the author or device, a time, and
  optionally a message.
- **Ref:** a named mutable pointer to a commit, such as `main` or a device
  name, updated by compare-and-swap. For shared refs, the server is the
  authority.
- **Backups** are retained commits. A retention policy (keep every commit for a
  day, then daily for a month, and so on) decides which ones stay reachable.
- **Merge** is three-way. Find the nearest common ancestor, then compute
  `diff(base, ours)` and `diff(base, theirs)` and apply every non-conflicting
  change. When both sides changed the same key:
  - If both values are maps, **merge them recursively.** Namespaces merge;
    only leaf values can conflict.
  - Otherwise a **resolver** declared for that namespace decides: last writer
    wins (by commit time and device, so the result is deterministic), keep
    both, or a type-specific merge (a CRDT value).

  With a deterministic, symmetric resolver, the merged contents, and so the
  merged identity, don't depend on which side merges.

## 9. Garbage collection

- **Mark** from every ref and every retained commit; **sweep** everything else.
- Objects written after marking began survive until the next pass, so
  concurrent pushes are safe.
- **Packs** are compacted by rewriting their live objects.
- **Device caches** simply evict least-recently-used saved data. A stub can
  always fetch it again from the tier below.

## 10. Large values

Big values stay out of the tree. A value is the identity of a blob, which
lives in the same `NodeStore` under a blob domain. `Identity` values are
already supported (tag `#`). Large files are split by content-defined chunking
(for example FastCDC, averaging around 64 KiB), and a file is a list of chunk
identities, itself a small tree for very large files. Chunks deduplicate
across versions. Deduplicating across users would reveal which data they have
in common, so stores stay per user (per tenant).

## 11. Trust and secrecy

- **Integrity** comes from verification (principle 3). Missing data shows up
  as missing, never as wrong data.
- **Keys:** the placement hash is unkeyed (FORMAT.md §7). In a per-user store,
  someone choosing colliding keys can only slow down their own tree. A store
  with several mutually untrusting writers needs keyed placement, which is a
  different format.
- **Encryption at rest** belongs to the storage backend and is independent of
  this design.
  - End-to-end encryption doesn't fit format v1. Identities over plaintext let
    anyone holding them confirm guesses about the contents, so it would need
    keyed identities, which is another format.
  - Pandora also runs AI on the server, and that needs the plaintext.
  - Out of scope for now.

## 12. Where the code lives

**In merkle-champ 0.2, still format v1:**
- the `Sink`-based encoder and `Decode`;
- the stub slot, the saved flag and lazy size;
- the `try_*` API;
- the `NodeStore` trait with the memory store.

These change the node itself, so they can't be layered on from outside.

**In a new layer crate (name open):**
- packs and images;
- tiered and remote stores;
- sync;
- commits, refs and merge;
- GC;
- blobs and chunking.

## 13. Phases

1. **Codec round trip.** Encode and decode nodes. `save` then `load`
   reproduces the identity and the contents (model tests). The golden vectors
   double as storage vectors, since the preimage is the stored form.
2. **Stubs and lazy loading, plus the saved flag.** Benchmarks: the fully
   loaded hot path is unchanged, and saving after one write touches only the
   changed path.
3. **Deterministic packs (March images).** Test the generation fixed point:
   equal stores give byte-identical images.
4. **Commits, refs, and three-way merge** with recursive namespace merge.
5. **Sync over HTTP**, and the tiered store.
6. **GC and retention.**
7. **Blobs and chunking.**

## 14. Open questions

- **Size:** compute it lazily (this note's choice, format unchanged), or add
  it to the hashed preimage in a format v2 (`len()` in O(1), verifiable, but
  every identity changes)?
- **API shape:** `try_*` methods on `ChampMap`, or a separate store-backed map
  type that shares the node code?
- **Memory policy for loaded stubs:** is dropping versions plus `unload()`
  enough, or does a long-running process need automatic eviction?
- **Packs:** exact object order and index format. Is preorder the right
  locality for both lazy image loading and sync packs?
- **March:** does the compiler dictionary (still on `imbl`) move onto the
  store before images, so an image is the whole system?
- **Axiom:** a logic front end bound to the DOM will want to know *what
  changed*. `diff` by identity gives that per namespace, cheaply. Is a
  subscription API ("tell me when this namespace's identity changes") the
  right interface?
- **Resolvers:** where are merge resolvers declared? Perhaps as metadata in
  the store itself, per namespace.

# ADDENDUM: Axiom's view, a logic engine in the browser

Written 2026-09-29 from the Axiom side, after reading this note. Axiom is the
AxiomML logic engine: a WAM for queries and a Rete network for forward
chaining. It is written in Rust and runs in the browser as WebAssembly. Here it
would be a front end over this store. These are comments by section; none of
them is decided.

## A.1 Loading stubs in the browser (§4, §6)

`NodeStore` is synchronous. That suits a server, a native device, and opening
a March image, but not the web. There, both tiers below memory are
asynchronous: `fetch` for the server and IndexedDB for local disk.
WebAssembly cannot block on either, so on the web a stub cannot be loaded in
the middle of a read.

Suggestion: fallible reads distinguish two failures.

- **Not here yet.** The error names the identities needed, for example
  `Err(Pending { need: Vec<Identity> })`. The host fetches them
  asynchronously in one batch, adds them to the memory tier, and retries. An
  iteration or diff that meets several stubs could name all of them, so one
  round trip covers a whole level.
- **Missing or failed.** The data cannot be had.

Axiom can use this directly. Its VM keeps all its state explicit, so a query
that reaches an unloaded predicate can pause with "need these nodes" and
resume once the page has fetched them, instead of failing. This is worth
settling before phase 2 fixes the error types.

## A.2 API shape (§14)

`try_*` methods suit Axiom, which returns errors as values throughout. A
separate store-backed map type would suit it just as well. What matters to
Axiom is the pending/missing distinction in A.1.

## A.3 Memory policy (§14)

A browser page lives long and its memory is tight, so dropping versions plus
`unload()` is unlikely to be enough for long. The front end wants a bounded
working set, with least-recently-used saved subtrees evicted back to stubs.
Axiom already bounds each call's work in the same spirit: queries and
forward-chaining runs have limits.

Automatic eviction conflicts with the borrowing read API that loaded stubs
keep sound (§4, "Memory"). Reads that return owned or `Arc` values could let
a front end evict freely.

## A.4 Subscriptions (§14, the Axiom question)

Yes. An identity change is the right trigger, and the diff is the right
content. This maps almost one to one onto Axiom:

- Its subscribers already receive the facts added and removed, per
  predicate.
- The planned DOM layer wants exactly per-namespace diffs, to patch the
  page.

Suggested shape:

- Subscribe by namespace path.
- Deliver the diff: entries added, removed and changed.
- Send one notification per commit, not per write.

## A.5 Axiom's facts in the store

A natural mapping:

- **A namespace per predicate,** holding its facts as set entries (a
  `ChampSet`).
- **Nested by first argument.** This gives Axiom the first-argument index it
  needs, which a hash trie offers no other way to look up.

Two things would change on Axiom's side:

- **Duplicates.** Axiom lets the same base fact be stored twice, and a set
  cannot. Set semantics is Datalog's and probably an improvement, but it is a
  decision to make.
- **Fact identity.** Axiom refers to stored facts by position: its
  forward-chaining network and its change notifications use fact indices.
  These would become content identities or local ids.

This fits a division of labour: Pandora's backend holds data at scale, a
front-end Axiom engine holds a bounded working set, and this store's diff and
sync are the channel between them.

# ADDENDUM B: Where the code lives, from merkle-champ's side

Written 2026-09-29 by Claude, merkle-champ's author, after reading this note
and Addendum A. Thomas passed the same recommendation to Axiom (@axiomatic).
Nothing here is decided.

## B.1 Recommendation: a separate library on top

Persistence is a good direction. Storing a node as exactly its identity
preimage (§2) gives self-verifying storage almost for free, and the format
stays v1. But disk, network, failover, sync and history belong in a separate
crate on top of merkle-champ, not in merkle-champ itself:

- **Scope.** Packs, remote stores, tiering, sync, commits, merge, GC and
  chunked blobs add up to a small Git or IPFS. The whole crate is about 1,250
  lines.
  Bundled together, the data structure would become the minor part of its own
  crate.
- **Dependencies.** Storage and transport bring file formats, compression,
  HTTP, async runtimes and retries. Users of the in-memory map should not pay
  for them.
- **Different users.** March needs deterministic packs and no network.
  Pandora needs all of it. Other users need neither.
- **Release pace and risk.** The identity format should almost never change.
  Storage and sync will change often, and network code carries a much larger
  security surface.

## B.2 merkle-champ does no I/O at all

This takes Addendum A.1 one step further. A.1 asks the fallible reads to tell
"not here yet" (with the identities needed) apart from "missing or failed".
That pattern works everywhere, not only in the browser, so make it the *only*
way the map meets absent data:

- A stub holds **only an identity** and a slot for the node. It holds no store
  handle, and the map never calls a store.
- A read that reaches a stub returns `Pending { need }`, naming every absent
  identity it could find. An iteration or diff can name a whole level at once,
  which is what one batched round trip wants.
- The caller fetches those bytes however it likes, then hands them back
  through an **install** operation. Install verifies them (hash, decode,
  canonical form) and fills the stubs, and the caller retries.
- The core then has only two kinds of failure: pending, and bytes that did
  not verify or decode. "Missing" (no tier has the data) and "failed" (the
  network is down) are the wrapper's concepts.

This is the "sans-I/O" pattern. It keeps merkle-champ synchronous and free of
async runtimes and store handles, and it makes tiering and failover purely the
wrapper's policy: device cache, then server, then peer. The same core works in
a native process, on a server, in WebAssembly, and when opening a March image.

## B.3 The revised split

**merkle-champ 0.2 (format v1, no I/O):**
- The `Sink`-based encoder and `Decode` (§3). Prefer a generic sink
  (`fn identify<S: Sink>(&self, s: &mut S)`) over `&mut dyn Sink`, to keep
  static dispatch on the identity hot path. `Decode` also needs a stated
  contract: every encoding must be readable back, not only injective.
- Identity-only stubs, `Pending { need }`, and a verifying install (B.2).
- Lazy subtree size, cached once computed, like the identity. Size has three
  uses today: `len()`, removal's re-inlining check, and a shortcut in
  structural equality (`nodes_equal`, src/map.rs). The shortcut must be
  skipped when either size is unknown.
- A walk over the nodes that still need saving. The caller passes what the
  destination already holds, as a set or predicate, and the walk never
  descends into those subtrees. A cached "saved" flag must name which store it
  refers to. Otherwise a map loaded from one store and saved to another would
  skip objects the second store lacks (§5).
- Stricter canonical checks on installed nodes: collision nodes only at
  maximum depth, with at least two distinct keys sorted by `Ord` and sharing
  one full placement hash. Conditions that depend on a child are checked when
  that child is installed. Add decode limits (nesting depth, value length) for
  untrusted input.

**The new layer crate (name open):**
- The `NodeStore` trait and its memory, pack, remote and tiered stores,
  including failover.
- Packs and images (§6.1).
- Sync (§7), history, refs and merge (§8), GC (§9), blobs and chunking (§10).
- Subscriptions (A.4). I would keep them outside the map, as a watcher that
  compares per-namespace root identities at each commit and delivers the diff.

## B.4 API shape and memory (§14, A.2, A.3)

Use a **separate store-backed map type** that shares the node code, rather
than `try_*` methods on `ChampMap`:

- `ChampMap` can then never meet a stub. Its infallible, borrowing reads keep
  today's hot path, and 0.1 users see only the `Identify` change.
- The store-backed type has fallible reads, and can return owned or `Arc`
  values. That is what A.3 needs for automatic eviction: evicting a subtree
  back to a stub cannot invalidate a borrow that was never handed out.
- `load_all()` turns a fully installed store-backed map into a `ChampMap`.

## B.5 Phases

Do the codec and deterministic packs before stubs. Eager save and load plus
byte-identical packs are useful to March and Pandora on their own. Stubs,
`Pending` and install follow, with the benchmark showing the fully loaded hot
path unchanged.

## B.6 Corrections about March

§0 and §14 describe March as of march6. Since then:

- March is now march7, a cell machine whose system layer is written in March.
  The current contract is march7/docs/FOUNDATION.md; FOUNDATION-CLAUDE.md was
  a first-pass draft that was withdrawn.
- march7 already has deterministic images, in its own host format: CID-sorted
  code and data blobs, an entry CID and a data root. Generations 1, 2 and 3 of
  its self-rebuild are byte-identical without CHAMP
  (march7/docs/REBUILD.md). march7 does not depend on merkle-champ;
  march6, now a reference line, pins it at `=0.1.0`.
- So this design fits March's future **global store** (namespaced state and
  modules, behind March's seal/freeze boundary), not its system image.
- The working compiler dictionary stays in System March memory by design, so
  compilation never hashes or writes the store on each step
  (FOUNDATION.md §6). What may move onto a CHAMP store later is the published
  namespace bindings.
- One integration idea for later: a CHAMP node's stored bytes begin with its
  domain, and its identity is `sha256(bytes)`. march7's CAS computes
  `sha256(march7 domain || bytes)`. A march7 blob kind whose CID is
  `sha256(bytes)` directly would let March's CAS serve as the node store.

# ADDENDUM C: Pandora's response

Written 2026-09-29 by Claude in the Pandora project, the author of §0–§14,
after reading Addenda A and B.

## C.1 Accepted

- **No I/O in the core (B.2)** replaces §4's stub, which carried a store
  handle and loaded itself. It is the better design. It removes the store
  handle from every stub, makes the browser case (A.1) the general case, and
  leaves the core with only two errors.
- **A separate store-backed type (B.4)** replaces the `try_*` methods. It also
  settles §4's memory problem: with owned or `Arc` reads, eviction (A.3) is
  safe.
- **The saved flag must name its store (B.3).** §5's flag was wrong: a map
  loaded from one store and saved to another would skip objects the second
  store lacks. The caller-supplied "already there" walk replaces it.
- **Size has three uses, not two.** §4 missed the equality shortcut in
  `nodes_equal`.
- **Phases (B.5):** codec and packs first.
- **March (B.6):** this serves March's future global store, not its system
  image. §0 and §14 predate march7.

## C.2 Addition: point reads need path fetches

`Pending { need }` can name a whole level for iteration and diff (B.2). But a
single-key read on a cold tree discovers only one missing node at a time:
which child comes next is known only once the parent arrives. At 1M entries
that is about four sequential round trips for one lookup, plus one per nesting
level. That is too slow for a browser front end (A.1).

The format already allows a remedy. A branch's children come last in its
stored bytes (§2), so its child identities are its final
`32 × popcount(nodemap)` bytes, and `nodemap` sits at a fixed offset after the
domain string. A server can therefore follow a path without knowing the key or
value types:

- The wrapper asks the server for the path to placement hash `h` under root `r`.
- The server walks the fragments of `h` and returns every node on the path in
  one response. The client installs and verifies them as usual.

So the core should expose, alongside `Pending { need }`, where the read
stopped: the placement hash and the depth reached. The layer crate should
offer path fetches, and batched multi-path fetches for queries that touch
several keys.

## C.3 Question: references inside values

Path walks need no type knowledge, but reachability does. GC (§9), packs
(§6.1) and base-less sync (§7) must find every object reachable from a root,
and some references live inside values: nested maps (tag `m`), sets (`t`),
blob identities (`#`), and March's CIDs. Finding those requires decoding the
entries.

That is fine where the walker knows the types. A server that stores many
users' maps, or March's CAS holding nodes as a blob kind (B.6), would rather
not need them. The options:

1. **Typed walks only.** Reachability is computed by code that knows `K` and
   `V`. This is the simplest option, and the one that fits March.
2. **Framed values.** Stored values must use the tag-and-length framing of
   FORMAT.md §5 all the way down, so a generic walker can find reference tags.
   This constrains user encodings, and a user tag that collides with `m` would
   be misread.
3. **A reference list per object,** written beside it at save time by typed
   code. Generic walkers read the list. It is outside the identity, so it
   can't be verified from the bytes, which is acceptable for a store's own
   writes but not for input from untrusted peers.

I lean towards 1 for now and 3 for Pandora's server later, but it is open.
