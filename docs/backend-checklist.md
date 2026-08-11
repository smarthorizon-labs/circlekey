# Backend checklist — GroupVault Protocol spec §10

What your backend must implement for CircleKey and other clients of
the GroupVault Protocol (the "*spec*" throughout this document) to work
against it.

Keep the trust model in mind while reading (spec §10.1): the backend is
a **relay and storage layer**. It is not part of the protocol's trust
root. Clients verify every membership change cryptographically (spec
§9.1); a misbehaving relay can cause denial of service, never forged
state or disclosed content.

> **Read [Why the contract looks like this](#why-the-contract-looks-like-this)
> if the rules below seem unusual.** The short version: the relay never
> sees the membership list, so authorization cannot be something it
> derives by reading — several rules exist because the obvious
> alternative is not merely worse but *impossible to satisfy*.

**Executable reference:** `MockTransport` (import from
`circlekey/testing`) implements everything below in memory, and
[`test/mock-transport.test.ts`](../test/mock-transport.test.ts) is the
written contract. When in doubt, do what the mock does.

## What you can and cannot see

This is the part worth internalizing before writing any code, because
it invalidates the obvious design.

A transition arrives as a `WireTransition`. Everything that describes
*what it did* — the action, the member list, device keys, user ids, the
policy, the signature, the previous-transition hash — is inside
`sealed_body`, encrypted to a key you never receive (spec §6.5). You
cannot tell an add from a removal from a policy change. You cannot
learn how many members a group has, or whether a given person is one.

What you legitimately see, and need:

| Field | Why you get it |
|---|---|
| `group_id` | routing. Random, no semantics (spec §5.8 rule 2) |
| `epoch` | ordering and the uniqueness constraint |
| `auth_pubkey` | the per-epoch key that authenticates later requests |
| `sealed_body` | opaque; fixed size per capacity profile |
| `secret_envelopes[]` | opaque; **fixed count**, mostly decoys |
| `prev_secret_ciphertext` | opaque history link |
| `removal_notice` | opaque; present on **every** transition ≥ epoch 1 |

Two consequences people get wrong:

- **The envelope count is constant and tells you nothing.** It is the
  profile's slot count (45 for `lite`), not the member count. Most
  slots hold decoys. Never size, index, or optimize storage on it.
- **`removal_notice` is always present and always the same size**,
  whether or not anyone was removed and whether or not the group even
  uses notices. Do not treat its presence as a signal, and never omit
  it when relaying.

## Operations to expose (spec §10.3)

Any wire format works (REST, GraphQL, WebSocket, …) — your client-side
`Transport` adapter maps it onto this interface:

| Operation | Notes |
|---|---|
| `createGroup(genesis)` | Genesis `create` transitions only; group id must be new |
| `getGroupState(groupId)` | Returns only `{group_id, current_epoch}`; a routing hint clients never trust |
| `submitTransition(groupId, transition)` | See the uniqueness rule below |
| `getTransitions(groupId, sinceEpoch?)` | Ascending by epoch; `sinceEpoch` is exclusive; all when omitted |
| `subscribeToTransitions(...)` | Optional; clients fall back to polling |
| `putRecord(groupId, record)` | See the freshness gate below |
| `getRecord(groupId, recordId)` / `listRecords(groupId, cursor?)` | Error on missing record |
| `putBackupBlob(handle, blob)` / `getBackupBlob(handle)` | One blob per handle, last write wins |

**There are no device endpoints** (spec §10.3). A user's devices live in
the epoch chain's member set and reach clients through
`getTransitions`, verified like everything else — a backend device
registry would be a second, untrusted source of truth for the same
fact. If your application keeps its own device directory for product
reasons, it has no protocol role.

## MUST

- [ ] **`(group_id, epoch)` uniqueness, atomically** (spec §10.4): a
      database uniqueness constraint or equivalent. First submission
      for an epoch wins; every later one gets
      `{ accepted: false, reason: "conflict" }`. This is the only
      concurrency control the protocol needs from you.

- [ ] **Request authentication, with the read/write split** (spec
      §10.1). Every group-scoped call carries a signature under a key
      derived from that epoch's group secret. Verify it against an
      `auth_pubkey` you have seen published for the group, and then:

      - **Reads** (`getTransitions`, `getGroupState`, `getRecord`,
        `listRecords`) accept **any** published `auth_pubkey`, current
        or historical.
      - **Writes** (`submitTransition`, `putRecord`) require the
        **current** epoch's key.

      > Do not "simplify" this into one rule. Requiring the current key
      > for reads makes catching up impossible for any client that was
      > briefly offline — it would need the key that the very fetch it
      > cannot make would deliver. That deadlock is easy to introduce
      > and invisible until a client falls behind, which is why spec
      > §10.5 enumerates who can satisfy each rule.

- [ ] **Retain every `auth_pubkey` you have ever accepted for a group.**
      They are the read ACL. Pruning old ones locks out lagging
      clients, which fails silently and looks like data loss.

- [ ] **Honour the bootstrap exemption** (spec §10.1, §10.5). Three
      legitimate callers hold no group key yet and cannot sign:
      creating a group, a newly-added member's first fetch, and a
      restored device's first fetch. Anchor these in your own account
      layer — an authenticated session, an invite token — exactly as
      you would any other product authorization. **Reads may bootstrap
      this way; writes never do.** A caller that cannot sign a write is
      not a member.

- [ ] **Record freshness gate** (spec §9.3 step 4): track the plaintext
      `current_epoch` integer per group (the last accepted transition's
      epoch). Reject record writes tagged with a lower epoch:
      `{ accepted: false, reason: "stale_epoch" }`. A plain integer
      comparison — no cryptography.
      > Defense in depth only. Conforming clients sync before
      > encrypting (§9.3 step 3) and do not depend on this check; it
      > exists to catch buggy or malicious clients. Getting it wrong
      > degrades nothing a correct client guarantees for itself — so
      > implement it, but never treat it as the thing that makes
      > removal safe.

- [ ] **Opaque fields stay opaque** (spec §10.2): store and serve
      byte-for-byte, never parse, transform, re-encode, or
      **re-compress** — `sealed_body`, `secret_envelopes[]`,
      `prev_secret_ciphertext`, `removal_notice`, record
      `ciphertext`/`nonce`, backup blob
      `ciphertext`/`salt`/`kdf`/`kdf_params`.

- [ ] **Never strip or normalize padding.** Sealed bodies, envelopes,
      notices and records are padded to fixed sizes precisely so their
      length says nothing (spec §5.8 rule 3). A storage layer that
      trims trailing zeros, or a transfer encoding that compresses them
      away, reintroduces the exact leak the padding removes. Store
      bytes.

- [ ] **Backup blobs are keyed by a blinded handle, not a user id**
      (spec §6.5). The handle derives from the user's recovery
      credential. Store it as an opaque key: do not index it against
      accounts, do not log it beside a user id, and do not report
      "no such user" — a missing blob and a wrong credential must be
      indistinguishable, or you become a credential-guessing oracle.

- [ ] **Transitions are append-only**: never mutate, replace, or
      reorder stored transitions. Serve them ascending by epoch.

## SHOULD

- [ ] **Revoke a removed member's sessions** (spec §9.3 step 5). When
      someone is removed from a group, invalidate any session or token
      they hold for it. This is an authorization-layer action, not a
      cryptographic one: it stops their client from continuing to pull
      sync traffic it cannot decrypt, and it is ordinary zero-trust
      hygiene.

      **Note where this has to happen.** The relay cannot detect a
      removal — every transition is the same opaque shape, and that is
      deliberate (spec §5.8) — so it cannot trigger this by inspecting
      the chain. It has to be driven by the account layer that
      performed the removal: your application knows, the storage layer
      does not.

      Confidentiality does not rest on it either way. A removed member
      is excluded from the next epoch's envelopes, so everything
      written after the removal is unreadable to them whether or not
      their session was cut (spec §9.3).

## MUST NOT

- [ ] **Do not pre-validate transitions.** It is tempting to re-check
      signatures server-side as a hygiene measure. You cannot: the
      signature, the signer, the member list and the hash link are all
      inside `sealed_body`. There is nothing left for you to check beyond the
      structural rules above, and code that tries will either reject
      valid traffic or grow a dependency on fields that must stay
      opaque.

- [ ] **Do not infer anything from shape or timing.** Equal-size
      bodies, constant envelope counts and always-present notices are
      deliberate. Building on them — caching by envelope count,
      alerting on notice presence — will break, and quietly recreates
      the metadata channel the design removes.

## Acceptance test

Point the integration scenario at your adapter; it exercises the whole
client-observable contract (gate, governance, records across epochs,
onboarding with history, removal, restore) and throws with a labeled
failure otherwise:

```typescript
import { runHostIntegrationScenario } from "circlekey/testing";
import { MyBackendTransport } from "./my-transport";

const report = await runHostIntegrationScenario({
  makeTransport: () => new MyBackendTransport({ baseUrl, session }),
});
console.log(report.checks); // every passed assertion, in order
```

A `Transport` adapter is typically a thin HTTP mapping. Note that
`auth` must be forwarded — it is what the relay verifies:

```typescript
import type { Transport } from "circlekey";

export class MyBackendTransport implements Transport {
  async submitTransition(groupId, transition, auth) {
    const response = await fetch(`${base}/groups/${groupId}/transitions`, {
      method: "POST",
      body: JSON.stringify(transition),
      headers: { ...headers, ...authHeaders(auth) },
    });
    if (response.status === 409) return { accepted: false, reason: "conflict" };
    if (!response.ok) throw new Error(await response.text());
    return { accepted: true };
  }
  // …the remaining spec §10.3 operations
}
```

## Why the contract looks like this

It is
tempting to expose membership to the backend, on the reasoning that it
needs it for access control — but that reasoning holds only while the
backend is the application's own server. It fails the moment the
backend is a third-party relay, and this protocol is designed to support that
case as well. The column on the left is the design you might reasonably expect;
the right is what you actually implement.

| What you might expect | What this contract requires |
|---|---|
| Membership, action and policy were plaintext | All inside `sealed_body` |
| Authorize by reading the membership list | Authorize by **request signature**, read/write split |
| Envelopes addressed by `device_pubkey` | Unaddressed, fixed count, decoy-padded |
| Backup blobs keyed by `userId` | Keyed by a blinded handle from the recovery credential |
| Pre-validation permitted | Nothing left to pre-validate; do not attempt |
| `getGroupState` returned a membership snapshot | Returns `{group_id, current_epoch}` only |
| Records carried `created_at` | Removed; records are padded to size buckets |
| Record ids chosen by the application | Derived, opaque to you |

There is no **coarse authorization from a plaintext membership list**,
in any softened form. There is no membership list to read. Request
signatures do that work instead, and the bootstrap exemption above is
how callers who hold no key yet still get in.
