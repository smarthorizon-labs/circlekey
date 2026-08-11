# How CircleKey is built

This is an orientation guide for developers reading or extending the
code. It is **not** a specification — the protocol is specified in
[The GroupVault Protocol](https://github.com/groupvault/protocol/blob/main/README.md), and where the two ever disagree,
the specification wins. What follows is how this particular TypeScript
implementation is arranged, and which parts of it will bite you.

If you are integrating CircleKey rather than working on it, start with
the [README](../README.md) and
[docs/backend-checklist.md](./backend-checklist.md) instead.

---

## The shape of it

```
┌────────────────────────────────────────────────────────────────┐
│  Public API                                                    │
│    GroupVault — the only class an application constructs       │
├────────────────────────────────────────────────────────────────┤
│  Orchestration                                                 │
│    GroupManager · DeviceManager · BackupManager · SyncManager  │
├────────────────────────────────────────────────────────────────┤
│  Protocol core (pure, platform-free, dependency-free)          │
│    EpochChain · GroupState · RecordCrypto · Envelopes          │
│    KeyManager · KDF · Codec · Padding · Profiles · RelayAuth   │
├────────────────────────────────────────────────────────────────┤
│  Ports (interfaces)                                            │
│    CryptoProvider · StorageAdapter · Transport                 │
│    LockProvider · HintChannel                                  │
├────────────────────────────────────────────────────────────────┤
│  Adapters                                                      │
│    WebCryptoProvider · IndexedDbStore · MemoryStore            │
│    WebLocks · BroadcastChannel hints · MockTransport           │
└────────────────────────────────────────────────────────────────┘
```

**Dependencies point downward only.** `src/core/` imports no platform
API, no manager, and no adapter — it is pure functions over plain data,
which is what makes it testable in Node and auditable in isolation.
Adapters never import protocol logic. Applications import only
`GroupVault`.

Two runtime dependencies exist, `@noble/curves` and `hash-wasm`, and
both are confined to the default `CryptoProvider` adapter. Everything
else, including all of `src/core/`, is dependency-free. Adding to that
list is a design decision, not a convenience call — and CircleKey never
implements a cryptographic primitive itself.

### Where things live

```
src/
  index.ts          public entry point
  api/              GroupVault facade + typed event hub
  core/             protocol logic — pure, no platform APIs
  managers/         orchestration: governance, devices, backup, sync
  ports/            the five interfaces the platform enters through
  adapters/         browser and in-memory implementations
test/
  vectors/          frozen interoperability vectors
  browser/          the real-browser suite (run by hand — see below)
```

### What each layer owns

**`core/epoch-chain.ts` is the product.** The protocol's entire security
argument is that clients independently verify every epoch transition.
Everything else in the library exists to feed that function inputs and
act on its outputs. `core/group-state.ts` folds verified transitions
into the current state and enforces the group invariants; the fold is
deterministic, so any client replaying the same verified chain reaches
the same state.

**`managers/` sequences, it does not decide.** `GroupManager` runs
governance operations (create, add, remove, promote, demote, set
policy), each one: sync to the head → build the transition → submit →
apply locally *only after* the backend accepts. `SyncManager` is the
only module that touches `Transport`, and it contains no cryptography
and no trust decisions. `DeviceManager` splits device linking across
the two devices involved. `BackupManager` owns enrollment and restore.

**`GroupVault` is a facade with preconditions.** It contains no
protocol logic. Its job is to make misuse hard: it refuses to construct
outside a secure context, blocks every group operation until backup
enrollment completes, and generates identifiers that the application is
not permitted to choose.

---

## Non-negotiable invariants

These implement the spec's MUSTs. No refactor, feature, or test
shortcut may weaken them:

- Every incoming `EpochTransition` passes the **full §9.1 checklist**
  (epoch exactly `current + 1`, prev-hash match, signer authorized
  *before* the transition, valid Ed25519 signature, `min_managers`
  policy holds after, history link present) before any state or
  storage is touched. Backend data is never trusted —
  `GroupStateSnapshot` is a routing hint only.
- **Signer authorization splits by action** (spec §9.1 check 3):
  governance actions require a manager; the device actions
  `add_device` / `remove_device` instead require **self-scoping** —
  the signer may modify only their own `device_pubkeys` and nothing
  else, so a manager may not touch another member's devices and a
  regular member may manage their own. Never collapse these two rules
  into one.
- Plaintext, private keys, and group secrets never reach the
  `Transport` port. The only secrets that leave the device are inside
  sealed envelopes or the encrypted backup blob.
- `min_managers` is enforced locally after **every individual
  transition** (a composed transfer may not transiently violate it).
- AES-GCM nonces: CSPRNG only, 96-bit, fresh per operation; per-key
  usage counters are persisted and encryption refuses past the bound
  (spec §6.1).
- Never assume a single instance per origin: multiple tabs share one
  IndexedDB. Chain mutations run under the per-group Web Lock, usage
  counters increment via atomic read-modify-write, and cross-tab
  broadcasts are hints only — the receiving tab re-reads verified
  state, never applies message payloads.
- HKDF `info` labels come from the closed enum in `core/kdf.ts` — never
  free-form strings.
- Every envelope/ciphertext/backup blob carries the versioned suite
  identifier (spec §6.3).
- Backup enrollment is structurally mandatory: `GroupManager` makes
  every group operation unreachable until enrollment completes, and
  the facade surfaces it (spec §9.6). Not a UI convention.
- **Wire formats are normative (spec §6.5)**, not local choices:
  canonical JSON for signing/hashing, base64url without padding, the
  `"gv1"` identifier, and the envelope / history-link / record /
  backup-blob layouts. They are frozen by `test/vectors/`, which the
  spec designates as the interoperability check. Changing any of them
  is a suite-version bump, never an edit.

---

## Pitfalls

These are the things that have actually caused bugs here, or that
reviewers reliably get wrong on first reading.

### The backend is a hostile courier

No module treats backend-supplied data as authoritative — not even the
group state the backend returns, which is a routing hint and nothing
more. The only authoritative state is the one derived locally by
replaying the verified chain. If you find yourself writing code that
believes a server response, you have found a bug.

### Decryption is authentication, never authorization

Transition bodies are sealed. Opening one proves a member wrote it and
proves nothing else. The full verification checklist still decides
whether it is accepted. **Any code path that accepts a transition
because it decrypted successfully is a critical defect.** Verification
runs backward (can we place this in the chain at all?) before forward
(is the signer authorized, does the policy hold after?), and both
halves are mandatory.

### Multiple tabs share one database

Every open tab is an independent CircleKey instance against the same
IndexedDB, so a single-instance mental model is wrong in a way that
unit tests will not reveal. Chain mutations run under a per-group Web
Lock, not an in-process mutex. Usage counters increment by atomic
read-modify-write. Cross-tab broadcasts are **hints only** — a
receiving tab re-reads verified state and never applies the message
payload, because a hint arrives from another tab that could be running
older code.

A stale in-memory view re-appending stored history got through every
single-instance test suite here before a two-instance test caught it.

### `fake-indexeddb` cannot settle concurrency questions

It is a JavaScript reimplementation, and its transaction scheduling
need not match a browser's. Whether IndexedDB actually serializes the
usage-counter read-modify-write across two connections — which is what
stops two tabs from double-spending the nonce budget — can only be
answered by the real thing. That is what `test/browser/` is for.

**The browser suite runs only when someone opens it.** Nothing in CI
executes it, so it can rot silently while the Node suite stays green.
Re-run it by hand whenever you touch the IndexedDB, locks, or hints
adapters: `npm run build`, then open `test/browser/` from a local
static server.

### The IndexedDB upgrade to version 3 is destructive

The database is at **version 3**, and the upgrade **drops**
`transitions`, `groups`, `secrets`, `key_usage` and `records_meta`,
preserving only `identity`. That is deliberate: anything written by an
earlier version is in a wire format this code cannot verify, so it is
discarded rather than left to fail replay forever. Preserving the
identity key is what turns this from an involuntary "lost device" —
which would need the backup credential — into an ordinary resync, since
the device is still in the member set and its envelopes are re-fetched.

**A host application must be told before it adopts a release carrying
this upgrade.**

### Wire formats are frozen, not chosen

Canonical JSON for signing and hashing, base64url without padding, the
`gv1` suite identifier, and the envelope, history-link, record and
backup-blob layouts are all normative. They are frozen by
`test/vectors/`, which the specification designates as the
interoperability check. Changing any of them is a suite-version bump,
never an edit — **a vector diff in a pull request is a red flag**, and
should be called out as one.

Canonicalization is also a security boundary: it is where `__proto__`
and friends get to be interesting. A property test found a real defect
there that hand-written cases missed.

### Nonce budgets are real and enforced

AES-GCM nonces are 96-bit, CSPRNG-generated, fresh per operation, and
per-key usage counters are persisted. Encryption **refuses** past the
bound rather than degrading. This is why the counter's atomicity across
tabs matters.

### Backup enrollment is structural, not advisory

Every group operation is unreachable until enrollment completes. This
is enforced inside `GroupManager`, so it cannot be bypassed by calling
a lower layer, and it is not a UI convention you can decide to skip.
Losing the local database without the recovery credential is
unrecoverable, by design.

### A removed member does not see its own removal

The transition removing a member is sealed to a secret that member
never receives. They stop at their last accessible epoch and observe
loss of access — which is stricter than telling them, since they learn
nothing about the remaining membership, but it means they cannot
distinguish removal from a backend that is withholding data. A removed
device attempting a governance operation gets a conflict error, not a
diagnostic one.

### Records are padded, and there is a practical size ceiling

Record sizes are bucketed and padded so that length leaks little. A
record is padded, encrypted and base64url-encoded as one in-memory
operation, so practical size stays in the low single-digit megabytes.
That is an implementation ceiling, not a protocol one. Large binaries
belong in general-purpose blob storage, referenced from a record by a
small pointer.

### Failures are typed, and silence is a bug

Every rejected transition, stale epoch, and fork signal raises a typed
error descending from `CircleKeyError`; library code never throws a
bare `Error`. Fork detection surfaces through a dedicated event so an
application can alert the user. A backend conflict surfaces as a typed
`ConflictError` — never silently.

### You implement `Transport`

CircleKey ships no production transport adapter. The host application
implements the interface against its own backend. `MockTransport` is a
full-fidelity in-memory reference — including the `(group_id, epoch)`
uniqueness constraint and stale-epoch rejection — and doubles as an
executable description of what a conforming backend must do. Read it
alongside [docs/backend-checklist.md](./backend-checklist.md).

---

## Testing conventions

Proving that bad input is refused matters more than proving good input
is accepted. Concretely, for every change:

- Every verification check and governance invariant has an explicit
  **rejection-path** test.
- New protocol behavior comes with adversarial `MockTransport` cases —
  replay, fork, gap, signature swap — each producing a typed error and
  an event, never silence.
- **Reach for property tests where the input space is wide**:
  encodings, canonicalization, invariants over operation sequences.
  They have found real defects here that example-based tests missed.
- **Anything touching shared storage needs a two-instance test.**
- **Check that a new test can actually fail.** More than one test here
  has passed for the wrong reason, asserting on a path that never ran.
  Break the thing under test, watch it go red, then fix it.

The Node suite runs offline against `MemoryStore` and `MockTransport`,
with no real network and no sleeps. Before declaring anything done:

```bash
npm run typecheck && npm run lint && npm test
```

---

## Where to look next

- [The GroupVault Protocol](https://github.com/groupvault/protocol/blob/main/README.md) — what any conforming
  implementation must guarantee.
- [docs/conformance.md](./conformance.md) — every client-observable
  MUST, mapped to the test that proves it.
- [docs/backend-checklist.md](./backend-checklist.md) — what the
  backend you write has to do.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — the working rules.
