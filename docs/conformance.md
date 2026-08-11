# GroupVault Protocol v1 — conformance map

The protocol [§14](https://github.com/groupvault/protocol/blob/main/README.md#14-conformance) (hereon, the *spec*)
defines conformance as satisfying
**every MUST and MUST NOT requirement in §5 through §13**, and validating
against the published test vectors. This document is the
requirement-by-requirement audit that claim rests on: every normative
statement in that range, with the named test that holds it.

**Scope note.** CircleKey is a *client* library. A number of §5–§13
requirements are obligations on the **backend**, which CircleKey does not
ship — the host application implements the `Transport` port against its
own server. Those requirements are listed here too, marked `BACKEND`,
with the `MockTransport` case that models the obligation as an executable
reference. They are the host team's to satisfy; see
[backend-checklist.md](./backend-checklist.md).

## Legend

| Mark | Meaning |
|---|---|
| `TEST` | Client-observable; held by the named test(s) |
| `BACKEND` | Backend obligation; `MockTransport` models it, host must implement |
| `DESIGN` | Satisfied by construction (type system, layering, closed enum); named test guards regression |
| `PROCESS` | Process, deployment, or forward-looking guidance — not executable |
| `N/A` | Does not apply to CircleKey's design; reason given |

Requirement strength is shown as **MUST** (required for conformance) or
*SHOULD* (recommended; tracked, not required). Test names are exact, so one can
`grep` for them.

---

## §5 Core Principles

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 5.2-1 | All encryption and decryption MUST happen inside the client | MUST | `TEST` | `no-secret-leaks`: *survives a full lifecycle with every secret withheld*; *proves the search would actually catch a leak* |
| 5.4-1 | Clients MUST refuse to apply a transition that does not chain to the accepted history | MUST | `TEST` | `epoch-chain`: *rejects an epoch gap*; *rejects a rollback to an older epoch*; *rejects a transition referencing a different previous transition* |
| 5.5-1 | Implementations SHOULD NOT be used for groups larger than a few dozen members | *SHOULD* | `TEST` | Satisfied by construction rather than by advice: a group is bounded by its capacity profile's envelope slots (spec §6.5), and a transition that would exceed them fails instead of dropping a device. `profiles`: *refuses to place more envelopes than the profile has slots*; *bounds devices, not members — `maxMembers` is documentary*. The profiles cap devices at 45 (`lite`) and 90 (`x`), well inside the spec's "few dozen" |
| 5.6-1 | Clients MUST enforce `min_managers` independently of the backend | MUST | `TEST` | `group-state`: *is exactly `managerCount >= min_managers`, never off by one*; *holds exactly at the boundary, and fails one below it*; `epoch-chain`: *rejects removing the sole manager (self-removal)* |
| 5.6-2 | A policy-violating transition MUST be rejected locally, even when relayed by the backend and signed by a legitimate manager | MUST | `TEST` | `epoch-chain`: *rejects a set_policy raising min_managers above the manager count*; *rejects a demote that transiently violates min_managers (transfer rule, spec §8)* |
| 5.7-1 | Clients MUST NOT trust the backend's account of group state | MUST | `TEST` | `live-sync`: *never applies the pushed payload — a forged push cannot move state*; *a sibling tab re-reads verified state instead of trusting the hint*; `epoch-chain`: *rejects a transition signed by a non-member (fabricated by a backend)* |
| 5.7-2 | Every epoch transition MUST be independently verified against the signature chain | MUST | `TEST` | `chain-vectors`: *rejects the chain when two committed bodies are swapped (adversarial)*; *rejects the chain when a transition is dropped (adversarial)*; the whole `epoch-chain` suite |

### §5.8 Metadata minimization


| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 5.8-1 | Nothing is sent in plaintext unless the relay demonstrably needs it to route or store | MUST | `TEST` | `no-secret-leaks`: *hands the relay no identity, device key, action, or policy*; *leaks none of the above in a raw-byte spelling either*; *proves the metadata search would actually catch a leak* |
| 5.8-2 | Plaintext identifiers carry no application semantics | MUST | `TEST` | `group-vault`: *generates an opaque group id rather than accepting one (spec §6.5, §12)*; *derives record identifiers, stably across rotations (spec §5.8 rule 2)*; `record-crypto`: *derives an opaque record_id that hides the application key (spec §6.5)* |
| 5.8-3 | Structure is padded to fixed shapes so size and count reveal nothing | MUST | `TEST` | `no-secret-leaks`: *makes every transition the same shape, whatever it did*; `sealed-body`: *seals to a fixed size regardless of payload, and opens back*; `removal-notice`: *is present and identically sized when nothing was removed*; the `padding` suite in full |

## §6 Cryptographic Model

### §6.1 Nonce policy

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.1-1 | Nonces MUST be CSPRNG-generated, 96-bit, fresh per operation | MUST | `TEST` | `record-crypto`: *uses a fresh CSPRNG nonce per operation (spec §6.1)*; `web-crypto-provider`: *returns the requested length and non-constant output* |
| 6.1-2 | A single key SHOULD NOT exceed the NIST SP 800-38D random-nonce bound | *SHOULD* | `TEST` | Enforced strictly (below), which is stronger than the SHOULD |
| 6.1-3 | Implementations MUST track per-key usage and refuse encryption past the bound | MUST | `TEST` | `record-crypto`: *refuses encryption past the bound, per (group, epoch)*; *does not count decryption*; *persists via the injected store — a fresh RecordCrypto sees prior usage*; `storage-adapters`: *increments usage counters atomically per (group, epoch)*; `multi-instance`: *counts every concurrent encryption exactly once*; **browser suite**: *usage counter: concurrent increments across two connections are gap-free*; *usage bound holds across two RecordCrypto instances on one database* |

> NOTE: The browser-suite rows are the load-bearing ones for 6.1-3 under
> multi-tab conditions. `fake-indexeddb` cannot settle whether real
> IndexedDB serializes the read-modify-write across connections; only
> `test/browser/` can, and it is **run by hand**.

### §6.2 Backup KDF parameters

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.2-1 | SHOULD prefer Argon2id 46 MiB / t=1 / p=1 | *SHOULD* | `TEST` | `backup`: *uses the spec §6.2 baseline parameters by default*; *defaults to Argon2id when the provider implements it*; *keeps PBKDF2's default at the spec §6.2 minimum* |
| 6.2-2 | Parameters MUST be revisited periodically as hardware improves | MUST | `PROCESS` | Annual review; not executable. Parameters are a constant in `src/managers/backup-manager.ts`, and travel with each blob so raising them needs no migration |
| 6.2-3 | Implementations MUST store the parameters with the blob | MUST | `TEST` | `backup`: *uploads a suite-tagged blob with its KDF parameters (spec §6.2)*; *honors the KDF parameters stored in the blob, not local config* |

### §6.3 Cryptographic agility

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.3-1 | Every envelope, ciphertext, and backup blob MUST carry an explicit suite identifier | MUST | `TEST` | `envelopes`: *rejects unknown suite versions (spec §6.3)*; *rejects malformed or foreign-suite blobs*; `record-crypto`: *rejects unknown suites instead of guessing (spec §6.3)*; `backup`: *rejects wrong credentials, tampering, and foreign formats* |

### §6.4 Device key binding

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.4-1 | A device's two keypairs MUST NOT be independent | MUST | `TEST` | `key-manager`: *derives the X25519 device key as the birational image of the identity key* |
| 6.4-2 | The X25519 keypair MUST be the deterministic birational image of the Ed25519 identity keypair | MUST | `TEST` | `key-manager`: *produces converted keypairs that actually agree on X25519 shared secrets*; *rebuilds the same device keys from the identity private key (restore path)*; `chain-vectors`: *rebuilds the committed device keys from the committed seeds*; `web-crypto-provider`: *matches RFC 7748 §5.2 vector 1* |
| 6.4-3 | A future suite replacing either algorithm MUST define its own binding | MUST | `PROCESS` | Forward-looking; applies to a v2 suite that does not exist |

### §6.5 Wire encoding and formats

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.5-1 | Decoders MUST reject characters outside the base64url alphabet | MUST | `TEST` | `bytes`: *rejects characters outside the alphabet*; *uses the URL-safe alphabet, never + / or padding* |
| 6.5-2 | Decoders MUST reject non-zero trailing bits | MUST | `TEST` | `bytes`: *rejects non-zero trailing bits*; *rejects an impossible length (one leftover character)*; *matches RFC 4648 §5 test vectors, unpadded* |
| 6.5-3 | An implementation MUST reject any suite identifier it does not implement | MUST | `TEST` | Same as 6.3-1 |
| 6.5-4 | The canonical-JSON restrictions MUST be enforced | MUST | `TEST` | `codec`: *sorts object keys by UTF-16 code units*; *sorts numeric-looking keys as strings*; *recurses into nested structures without whitespace*; *escapes strings per ES JSON.stringify rules*; *is independent of object key insertion order*; *canonicalizes a literal "__proto__" key rather than dropping it*; *is stable: canonicalize(parse(canonicalize(v))) === canonicalize(v)* |
| 6.5-5 | Values outside the safe range or outside JSON MUST be rejected rather than serialized | MUST | `TEST` | `codec`: *rejects non-integer and unsafe numbers*; *rejects non-JSON values*; *rejects class instances instead of silently serializing them*; *serializes -0 as 0 and accepts the safe-integer bounds* |
| 6.5-6 | A key whose value is absent MUST be omitted from the object entirely | MUST | `TEST` | `codec`: *rejects undefined property values instead of skipping them*; `wire`: *omits absent optional fields instead of setting them undefined* |
| 6.5-7 | Field order MUST be produced by applying JCS, not hardcoded | MUST | `TEST` | `vectors`: *`${entry.name}`: signing bytes* / *chain hash* (vector-driven, so a hardcoded order would have to match JCS everywhere); `codec`: *omits `signature` but keeps `signed_by` in the signing bytes* |
| 6.5-8 | A restoring client MUST tolerate a blob written with older KDF parameters | MUST | `TEST` | `backup`: *opens a legacy PBKDF2 blob on an Argon2id-default client — no migration*; *re-seals a legacy PBKDF2 blob under Argon2id on refresh* |
| 6.5-9 | An implementation SHOULD validate itself against the published test vectors | *SHOULD* | `TEST` | `vectors` and `chain-vectors` suites in full; `chain-vectors`: *replays the full committed chain to the committed final state* |

#### §6.5 wire formats

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 6.5-10 | The transition body MUST be sealed under `group_secret[epoch]`, padded to the profile size | MUST | `TEST` | `sealed-body`: *seals to a fixed size regardless of payload, and opens back*; *refuses a body that outgrows its capacity profile*; *cannot be opened with another epoch's secret* |
| 6.5-11 | `secret_envelopes` MUST be padded to the profile's slot count with indistinguishable decoys at CSPRNG-chosen positions | MUST | `TEST` | `envelopes`: decoy and placement cases; `no-secret-leaks`: *makes every transition the same shape, whatever it did*; `chain-vectors`: *opens alice's envelope at every epoch to the committed group_secret* |
| 6.5-12 | `envelope_slots` MUST map each member device to its slot, so no device is skipped, served twice, or served when it is not a member | MUST | `TEST` | `sealed-body`: *rejects a body that decrypts but is not authorized to do what it says*; `devices`: removed-device cases; `chain-vectors`: *stops enveloping to bob once removed (spec §9.3)* |
| 6.5-13 | Every transition at epoch ≥ 1 MUST carry a fixed-size `removal_notice`, sealed under the *previous* epoch's secret, identically sized under every policy and outcome | MUST | `TEST` | `removal-notice`: *is present and identically sized when nothing was removed*; *cannot be opened with the current epoch's secret*; *genesis carries no notice*; *refuses a notice too large for the profile*; *rejects a notice padded to a different profile's size*; `chain-vectors`: *is the same size whether or not it says anything (spec §5.8)* |
| 6.5-14 | A removal notice MUST be signed by the same actor that signed the transition; clients MUST reject one that is not | MUST | `TEST` | `removal-notice`: *rejects a notice sealed and signed by a non-manager peer*; *rejects a notice whose signature does not verify*; *rejects a notice replayed onto another epoch*; `chain-vectors`: *names exactly the removed device, signed by the acting manager* |
| 6.5-15 | Capacity profiles MUST be frozen values; a group's `capacity` is immutable after genesis | MUST | `TEST` | `profiles`: *freezes the wire-format sizes — changing one is a protocol break*; *rejects an unknown capacity rather than falling back*; `sealed-body`: *an x-profile group verifies against x sizes, not the default* |
| 6.5-16 | Record plaintexts MUST be padded into size buckets before encryption | MUST | `TEST` | `padding`: *always returns a bucket that fits the payload and its prefix*; *is non-decreasing in payload length*; *collapses a wide range of sizes onto few distinct values*; *pads a real payload into its bucket and back* |
| 6.5-17 | Decoders MUST verify padding rather than assume it | MUST | `TEST` | `padding`: *rejects a declared length beyond the buffer — no out-of-bounds read*; *rejects a declared length one byte past capacity*; *rejects a non-zero padding byte anywhere in the region*; *rejects a buffer that is not exactly the expected size* |
| 6.5-18b | `group_id` MUST be a value the client generates at random, never one the application supplies | MUST | `TEST` | `group-vault`: *generates an opaque group id rather than accepting one (spec §6.5, §12)* — 128 bits, base64url, fresh per group; the facade's arity is the enforcement |
| 6.5-18 | `record_id` MUST be PRF-derived, never an application-supplied name | MUST | `TEST` | `group-vault`: *derives record identifiers, stably across rotations (spec §5.8 rule 2)*; `no-secret-leaks`: *hands the relay no identity, device key, action, or policy* (asserts the application's key is absent) |
| 6.5-19 | Backup blobs MUST be addressed by a handle blinded from the recovery credential, never a `user_id` | MUST | `TEST` | `handles`: *is stable for one credential at one relay*; *is unlinkable across relays — the point of blinding*; *does not embed the credential it derives from*; `capability-reachability`: *wrong credential — cannot locate a backup, and cannot tell why* |
| 6.5-20 | Each epoch MUST have its own relay auth key derived from `group_secret[epoch]` | MUST | `TEST` | `relay-auth`: *is deterministic — every member of an epoch derives the same key*; *diverges across epochs, so each epoch has its own credential*; *is not the group secret itself, nor any trivial function of it* |
| 6.5-21 | `created_at` MUST NOT appear on a record | MUST | `TEST` | `no-secret-leaks`: *hands the relay no identity, device key, action, or policy* (asserts no `created_at` and no RFC 3339-shaped value) |

## §7 Key Hierarchy

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 7-1 | Domain separation via distinct `info` strings is REQUIRED | MUST | `TEST` | `kdf`: *separates domains: different labels yield different keys from one secret*; *builds info as label \|\| context*; *calls HKDF with empty salt, the labeled info, and 32-byte length* |
| 7-2 | The `group_secret` MUST NOT be used directly for encryption | MUST | `DESIGN` | Every key reaches AES-GCM through `deriveKey` (`core/kdf.ts`); `record-crypto`: *round-trips and stays domain-separated from record keys* |
| 7-3 | Different derived-key contexts MUST NOT share an `info` label | MUST | `DESIGN` | Closed enum in `core/kdf.ts`; `kdf`: *freezes the closed label set — changing a label is a protocol break* |

## §8 Group Governance Model

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 8-1 | The `min_managers` invariant MUST hold after *every* transition, not just at the end of a composed operation | MUST | `TEST` | `epoch-chain`: *rejects a demote that transiently violates min_managers (transfer rule, spec §8)*; `chain-properties`: *every reachable state satisfies the §9.1 and §8.1 rules* |
| 8.1-1 | A business workspace SHOULD default to a higher `min_managers` | *SHOULD* | `PROCESS` | Host policy choice; the library takes `min_managers` from the caller and enforces whatever it is |
| 8.1-2 | Clients SHOULD prompt the creator to add a second manager | *SHOULD* | `N/A` | Host-UI concern. CircleKey is a library with no UI; `lostDeviceOptions` surfaces the recovery consequences (`devices`: *escalates to a manager when the member has no route of their own*) |

## §9 Protocol Flows

### §9.1 Transition verification — outer checks

A relay-visible `WireTransition` wraps the sealed `EpochTransition`.
The outer checks run first, but **opening the body is authentication,
never authorization** — the full checklist below still decides.

| # | Check | Strength | Status | Held by |
|---|---|---|---|---|
| 9.1-O1 | A device MUST find its own envelope by trial decryption; failure at every slot means no access | MUST | `TEST` | `chain-vectors`: *stops enveloping to bob once removed (spec §9.3)*; `sealed-body`: *refuses to replay past the epoch whose secret it lacks* |
| 9.1-O2 | The sealed body MUST open under `group_secret[epoch]`, with AAD binding it to its group and epoch | MUST | `TEST` | `sealed-body`: *O2: rejects a tampered sealed body*; *O2: rejects a body relabelled onto another epoch — AAD binding*; *O2: rejects a body relabelled onto another group* |
| 9.1-O3 | Inner `group_id`/`epoch` MUST match the outer envelope | MUST | `TEST` | `sealed-body`: *O3: rejects inner/outer group_id and epoch mismatches* |
| 9.1-O4 | The body MUST be padded to exactly the profile's size | MUST | `TEST` | `sealed-body`: *O4: rejects a body padded to the wrong profile size* |
| 9.1-O5 | A body that decrypts MUST still face the full §9.1 checklist | MUST | `TEST` | `sealed-body`: *rejects a body that decrypts but is not authorized to do what it says* — mutation-verified |

### §9.1 Transition verification — genesis checklist

| # | Check | Strength | Status | Held by |
|---|---|---|---|---|
| 9.1-G1 | `epoch === 0` | MUST | `TEST` | `epoch-chain`: *rejects genesis with epoch != 0 (check 1)* |
| 9.1-G2 | `prev_transition_hash` equals the genesis marker `hash(group_id)` | MUST | `TEST` | `epoch-chain`: *rejects genesis whose prev hash is not the genesis marker (check 2)*; `codec`: *computes the genesis marker as base64url(SHA-256(utf8(group_id)))*; `vectors`: *anchors genesis: t0.prev_transition_hash === genesis marker* |
| 9.1-G3 | `members` contains exactly one entry, `is_manager: true` | MUST | `TEST` | `epoch-chain`: *rejects genesis with more than one member (check 3)*; *rejects genesis whose creator is not a manager (check 3)* |
| 9.1-G4 | `signed_by` converts (§6.4) to a device key listed for the creator | MUST | `TEST` | `epoch-chain`: *rejects genesis signed by a key that is not the creator's device* |
| 9.1-G5 | The Ed25519 signature is valid | MUST | `TEST` | `epoch-chain`: *rejects genesis with an invalid signature* |
| 9.1-G6 | `prev_secret_ciphertext` is absent | MUST | `TEST` | `sealed-body`: *rejects a genesis carrying a history link* |

> **Note — `min_managers` is not a genesis check.** The list above has no
> `min_managers` check, while every successor has one (9.1-S5). That is
> deliberate: a genesis names exactly one member (9.1-G3), so a policy
> demanding more managers than that would make the group's own founding
> transition invalid.
>
> The consequence is the following: A genesis policy of
> `min_managers: 3` verifies at epoch 0 and then refuses every governance
> operation, because no single transition can climb from one manager to
> three. It is recoverable only by a `set_policy` that lowers the
> bar first.
>
> **A group that needs several managers adds the managers first, then
> raises `min_managers` to match.** The policy ratchets up behind the
> managers that exist and may never exceed them (5.6-2), so the sequence
> alternates: promote, raise, promote, raise.
>
> CircleKey therefore refuses to *create* such a group —
> `min-managers-bootstrap`: *refuses to create a group demanding more
> managers than it can have*; *climbs by alternating promotion and policy
> raise*. This is a guarantee of the client API, not of the protocol.

### §9.1 Transition verification — successor checklist

| # | Check | Strength | Status | Held by |
|---|---|---|---|---|
| 9.1-S1 | `epoch === last_known_epoch + 1` (rejects gaps and rollback) | MUST | `TEST` | `epoch-chain`: *accepts the exact successor epoch*; *rejects a replayed transition (same epoch)*; *rejects an epoch gap*; *rejects a rollback to an older epoch*; `group-sync`: *replayed transitions are rejected and never applied*; *epoch gaps are rejected* |
| 9.1-S2 | `prev_transition_hash` matches the last accepted transition (rejects forks) | MUST | `TEST` | `epoch-chain`: *rejects a transition referencing a different previous transition*; `group-sync`: *a forked history is detected, surfaced, and refused*; `chain-properties`: *rejects any transition replayed out of its position* |
| 9.1-S3a | Governance actions: signer MUST belong to a member with `is_manager: true`, evaluated against the member set *before* the transition | MUST | `TEST` | `epoch-chain`: *rejects a transition signed by a regular member*; *rejects a transition signed by a non-member (fabricated by a backend)*; *rejects a demoted manager acting on stale authority* |
| 9.1-S3b | Device actions: signer MUST be the *same member* whose `device_pubkeys` change, and that member MUST be the only member changed. A manager MUST NOT alter another member's device list | MUST | `TEST` | `devices`: *accepts a member linking a device to their own entry*; *rejects editing another member's devices — even by a manager*; *rejects removing another member's device — even by a manager*; *rejects a device action signed by a non-member*; *rejects smuggling a privilege change alongside a device change*; *rejects smuggling a membership change alongside a device change*; *rejects changing two members' device lists at once*; *rejects a swap disguised as add_device*; *still rejects device changes hidden in a governance action* |
| 9.1-S4 | The Ed25519 signature is valid | MUST | `TEST` | `epoch-chain`: *rejects a flipped signature*; *rejects content tampered after signing*; *rejects malformed signature encodings*; `codec`: *includes the signature in the chain hash — a signature swap is a fork*; `group-sync`: *swapped sealed bodies are rejected* |
| 9.1-S5 | The resulting member set satisfies the current `min_managers` policy | MUST | `TEST` | Same as 5.6-1 / 5.6-2 / 8-1 |
| 9.1-S6 | `prev_secret_ciphertext` is present and carries a supported suite identifier | MUST | `TEST` | `sealed-body`: *rejects a successor transition without a history link*; *rejects a malformed history link blob* |
| 9.1-S6b | Clients holding `group_secret[epoch-1]` SHOULD verify the link decrypts to it | *SHOULD* | `TEST` | `group-sync`: *detects a manager that sealed the wrong secret into a history link* — implemented, raising `HistoryIntegrityError` |
| 9.1-S7 | `auth_pubkey` MUST be the key derivable from this epoch's `group_secret` | MUST | `TEST` | `sealed-body`: *rejects an auth_pubkey nobody can derive (spec §9.1 check 7)* |
| 9.1-S8 | `capacity` MUST NOT change after genesis | MUST | `TEST` | `sealed-body`: *an x-profile group verifies against x sizes, not the default*; `profiles`: *reads the capacity off a policy that declares one* |
| 9.1-S9 | The genesis MUST declare both `capacity` and `removal_notice` explicitly | MUST | `TEST` | `sealed-body`: *carries the removal_notice policy into verified state*; `profiles`: *defaults to lite when a policy predates the field* |
| 9.1-S10 | A client holding `group_secret[e-1]` MUST verify the notice against the body and the policy, **in both directions** | MUST | `TEST` | `removal-notice`: *required: rejects a removal whose notice was stripped*; *suppressed: emits no notice, and rejects one that appears*; *accepts a conforming removal under either policy*; *rejects a notice listing devices the transition did not remove*; `chain-vectors`: *rejects the chain when the removal is stripped of its notice* |
| 9.1-S11 | A client that cannot obtain `group_secret[e-1]` MUST record the check as **skipped**, never as passed | MUST | `TEST` | `removal-notice`: *reports when check 11 could not run, rather than implying it passed* |
| 9.1-R1 | On any failed check the client MUST reject the transition and MUST NOT apply it | MUST | `TEST` | `group-sync`: *replayed transitions are rejected and never applied*; `startup`: *fails loudly on tampered local history instead of trusting it*; `epoch-chain`: *rejects a non-create transition when no state exists* |
| 9.1-R2 | A detected fork SHOULD be surfaced to the user rather than silently ignored | *SHOULD* | `TEST` | `group-vault`: *surfaces forks through the forkDetected event*; `group-sync`: *a forked history is detected, surfaced, and refused* |

### §9.3 Remove member (immediate)

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 9.3-1 | Clients MUST sync before encrypting and MUST NOT encrypt under an epoch they can verify is superseded; MUST NOT rely on the backend gate (§9.3 step 3) | MUST | `TEST` | `group-vault`: *syncs before encrypting, so a rotated epoch never yields a stale write* — asserts the write lands on the **first** attempt, which is the spec's stated observable |
| 9.3-2 | The backend MUST track a plaintext `current_epoch` per group and reject writes tagged below it (§9.3 step 4) | MUST | `BACKEND` | `mock-transport`: *rejects writes tagged with a superseded epoch*; client-observed in `group-sync`: *a stale record write → StaleEpochError (spec §9.3)*. Defense in depth — no client guarantee depends on it |
| 9.3-3 | The backend SHOULD immediately invalidate sessions/tokens of the removed member (§9.3 step 5) | *SHOULD* | `BACKEND` | Authorization-layer concern, outside the protocol. [backend-checklist.md](./backend-checklist.md) |
| 9.3-5 | A removed member MUST be able to read the notice for its own removal, and MUST NOT learn the membership that remains | MUST | `TEST` | `removal-notice`: *is readable by the removed member, using the secret they still hold*; *carries only the removed devices — never the membership that remains*; `chain-vectors`: *is readable by the member it removes, using the secret they still hold* |
| 9.3-6 | Implementations MUST NOT present `"suppressed"` as a guarantee of silence, nor `removed_at` as verified time | MUST | `PROCESS` | Stated in spec §6.5/§8.1 and in the API docs; not executable — it is a claim an implementation must refrain from making. `removal-notice` proves the mechanism; the restraint is editorial |
| 9.3-4 | Removal cuts off new data immediately | MUST | `TEST` | `chain-vectors`: *stops enveloping to bob once removed (spec §9.3)*; `group-sync`: *a removed member stops advancing and receives no new secrets*; `json-roundtrip`: *keeps outsiders and removed members out* |


### §9.5 Multi-device

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 9.5-1 | A backend-side device list MUST NOT be relied on as the cut-off mechanism | MUST | `DESIGN` | The `Transport` port has no device endpoints at all (`src/ports/transport.ts`); cut-off is the epoch chain. `devices`: *cuts a removed device off from post-removal data* |

### §9.6 Recovery / backup (mandatory)

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 9.6-1 | A device MUST NOT finish onboarding into any group until a recovery backup is enrolled | MUST | `TEST` | `backup`: *blocks every group operation until enrollment completes*; *blocks operations when no identity exists at all*; `group-vault`: *onboards, enforces the backup gate, and round-trips records* |
| 9.6-2 | The recovery credential MUST be displayed once, and the client MUST confirm it was stored | MUST | `TEST` | Two-phase enrollment: `backup`: *refuses to confirm with a credential that cannot open the backup*; *cannot enroll twice or without an identity*; *verifies the credential before overwriting — a typo cannot destroy the backup*. The *display* half is the host's UI; the library returns the credential exactly once from `enrollBackup()` and gates on `confirmBackupStored()` |
| 9.6-3 | If a user-chosen passphrase is allowed, the client MUST enforce a minimum strength policy | MUST | `N/A` | CircleKey does not offer user-chosen passphrases. `BackupManager` generates a high-entropy system credential; the conditional never fires. A host that adds passphrase entry inherits this requirement |

### §9.7 New member access to group history

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 9.7-1 | Every transition advancing a group to epoch `e ≥ 1` MUST include `prev_secret_ciphertext` | MUST | `TEST` | `sealed-body`: *rejects a successor transition without a history link*; `chain-vectors`: *gives the added member the full secret history via the chain (spec §9.7)*; *recovers the entire history from the newest secret alone (spec §9.7)* |
| 9.7-2 | The genesis transition MUST NOT carry the field | MUST | `TEST` | `sealed-body`: *rejects a genesis carrying a history link* |
| 9.7-3 | Members holding `group_secret[e-1]` SHOULD verify the link | *SHOULD* | `TEST` | Same as 9.1-S6b |
| 9.7-4 | A mismatch SHOULD be surfaced as an integrity issue | *SHOULD* | `TEST` | `group-sync`: *detects a manager that sealed the wrong secret into a history link* (typed `HistoryIntegrityError`, never silent) |

## §10 Backend Interface

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 10.2-1 | `secret_envelopes[].ciphertext` MUST remain opaque to the backend | MUST | `TEST` | `no-secret-leaks`: *survives a full lifecycle with every secret withheld* |
| 10.2-2 | Sensitive application content MUST live inside the record ciphertext, not in a separate plaintext field | MUST | `TEST` | `no-secret-leaks` (both cases); `json-roundtrip`: *encrypts as the manager and decrypts as a member added later* |
| 10.3-1 | A client MUST NOT treat an application's own device directory as evidence that a device belongs to a member | MUST | `DESIGN` | No device endpoints exist on the `Transport` port; device membership is read only from verified chain state. `devices`: *rejects a device action signed by a non-member* |
| 10.4-1 | Clients MUST perform the full §9.1 verification themselves, regardless of backend checks | MUST | `TEST` | The entire §9.1 block above; `group-sync` adversarial suite |
| 10.1-1 | Backends MUST accept **any** previously published `auth_pubkey` for reads and MUST require the **current** epoch's key for writes | MUST | `BACKEND` | `relay-request-auth`: *accepts a read signed under any published epoch key*; *refuses a write signed under a superseded epoch key*; *a member several epochs behind can still catch up*; `capability-reachability`: *no read operation requires the current epoch's key*; *every write operation requires the current epoch's key*; the host-side probe in `host-integration`: *fails a relay that does not enforce spec §10.1 at all* |
| 10.1-2 | The bootstrap exemption MUST cover `createGroup`, a new member's first fetch, and a restored device's first fetch — and MUST NOT extend to writes | MUST | `BACKEND` | `capability-reachability`: *creator — holds nothing, bootstraps through the account layer*; *invitee — holds nothing for this group, and its first fetch delivers the key*; *restored device — credential only, recovers identity then group access*; *outsider — never a member, holds nothing that works*; `relay-request-auth`: *refuses an unsigned write even during bootstrap* |
| 10.1-3 | A client MUST sign every group-scoped request it is able to sign | MUST | `TEST` | `capability-reachability`: *reads and writes records through GroupVault against a strict relay* — driven through the public API, so it covers record operations and not only governance ones |
| 10.2-3 | `sealed_body`, `removal_notice` and `prev_secret_ciphertext` MUST remain opaque and byte-preserved | MUST | `BACKEND` | `mock-transport` stores and returns them verbatim; client-observed by every `sealed-body` and `removal-notice` case, which fail on any mutation |
| 10.2-4 | The relay MUST NOT be able to distinguish transition types, membership size, or whether a removal occurred | MUST | `TEST` | `no-secret-leaks`: *makes every transition the same shape, whatever it did*; *hands the relay no identity, device key, action, or policy* |
| 10.4-2 | The backend MUST enforce an atomic uniqueness constraint on `(group_id, epoch)` | MUST | `BACKEND` | `mock-transport`: *accepts the first submission per epoch and returns conflict to losers*; *creates groups from genesis transitions only, exactly once*; client-observed in `group-sync`: *a losing concurrent submission → ConflictError (spec §10.4)*; recovery in `live-sync`: *two managers converge through concurrent transitions* |

### §10.5 Capability table

Normative in the spec, and the artefact that must be re-derived
whenever a gate is added. A row with no possible holder, or an
impossible bootstrap, is a protocol deadlock rather than an
implementation bug.

| # | Requirement | Strength | Status | Held by |
|---|---|---|---|---|
| 10.5-1 | Every gated operation MUST have at least one holder and a reachable bootstrap | MUST | `TEST` | `capability-reachability` in full — every actor either reaches a working state or is provably refused, with the relay at maximum enforcement |
| 10.5-2 | A conforming implementation SHOULD carry an executable form of the table | *SHOULD* | `TEST` | `test/capability-reachability.test.ts` is exactly that |

> This table exists because of a specific failure mode: an
> authorization rule stated without enumerating who can satisfy it. Such
> a rule reads as correct — every sentence is true — and still leaves an
> operation no actor can reach, because the capability it demands is
> obtainable only through the operation itself. Reasoning about the
> prose does not surface it; switching enforcement on and watching a
> legitimate actor fail does.
>
> That is why the reachability suite exercises every row through the
> **public API** rather than by calling the authorization helpers
> directly. A row that builds its own signed request proves the helper
> works, not that the path a caller actually takes is reachable — and
> the gap between those two is exactly where this class of bug lives.

## §11 Governance Redundancy

No normative (MUST/SHOULD) statements — §11 is advisory discussion of
manager availability. The mechanism it discusses is `min_managers`,
covered by 5.6-1 and 8-1.

## §12 Security Requirements

Each §12 bullet restates a requirement defined elsewhere; this table maps
the bullet to its canonical row so the §12 checklist can be read
top-to-bottom.

| # | §12 bullet | Status | Canonical row / test |
|---|---|---|---|
| 12-1 | The backend MUST NOT ever receive plaintext, private keys, or group secrets | `TEST` | 5.2-1 — `no-secret-leaks` (both cases) |
| 12-2 | Derived keys MUST NOT be stored beyond their immediate use | `TEST` | `record-crypto`: *zeroes every derived key before returning (spec §12)* |
| 12-3 | All symmetric encryption MUST use authenticated encryption (AES-256-GCM) | `TEST` | `web-crypto-provider`: *matches the NIST empty-plaintext vector (tag-only output)*; *throws CryptoError on any tampering*; *refuses non-256-bit keys*; `record-crypto`: *fails on tampered ciphertext or nonce* |
| 12-4 | Every transition MUST be validated against the full §9.1 checklist before being applied | `TEST` | All of §9.1 above; 9.1-R1 |
| 12-5 | Clients MUST validate epoch monotonicity and hash-chain continuity | `TEST` | 9.1-S1, 9.1-S2 |
| 12-6 | Clients MUST NOT encrypt under an epoch they can verify is superseded; the backend gate MUST NOT be relied on | `TEST` | 9.3-1 — see the note under §9.3 |
| 12-6b | Clients MUST reject a secret envelope whose epoch header does not match the transition carrying it | `TEST` | `envelopes`: *binds the epoch header via AAD — a relabelled epoch fails to open* |
| 12-7 | Clients MUST reject invalid signatures | `TEST` | 9.1-G5, 9.1-S4 |
| 12-8 | Clients MUST enforce `min_managers` locally, independent of backend behavior | `TEST` | 5.6-1, 5.6-2, 8-1, 9.1-S5 |
| 12-9 | Nonces MUST be CSPRNG-only and MUST NOT be reused per key | `TEST` | 6.1-1, 6.1-3 |
| 12-10 | Per-key usage MUST be tracked and bounded well below 2³² | `TEST` | 6.1-3 (incl. the two browser-suite cases) |
| 12-11 | All derived keys MUST use explicit, non-overlapping HKDF `info` labels | `TEST` | 7-1, 7-3 |
| 12-12 | All envelopes MUST carry an explicit suite/version identifier | `TEST` | 6.3-1 |
| 12-13 | Implementations MUST support cryptographic agility via the versioned envelope format | `TEST` | 6.3-1; `backup`: *falls back to PBKDF2 when the provider omits Argon2id*; *refuses an explicit Argon2id request the provider cannot satisfy* — a second suite selected at runtime, exercised end to end |
| 12-14 | Backup enrollment MUST be mandatory, with no opt-out, before a device completes onboarding | `TEST` | 9.6-1, 9.6-2 |
| 12-15 | Session/token revocation SHOULD occur in addition to epoch rotation | `BACKEND` | 9.3-3 |

**Metadata minimization (§5.8)**:

| # | §12 bullet | Status | Canonical row / test |
|---|---|---|---|
| 12-16 | The backend MUST NOT receive identities, device keys, manager flags, policy, or action type | `TEST` | 5.8-1 — `no-secret-leaks` (all four metadata cases) |
| 12-17 | `group_id` and `record_id` MUST be random or PRF-derived, never application-supplied | `TEST` | 6.5-18b (`group_id`), 6.5-18 (`record_id`) |
| 12-18 | Clients MUST address backup blobs by blinded handle and MUST NOT transmit `user_id` | `TEST` | 6.5-19; `no-secret-leaks`: *hands the relay no identity, device key, action, or policy* |
| 12-19 | `secret_envelopes` MUST be padded to the slot count with indistinguishable decoys at CSPRNG positions | `TEST` | 6.5-11 |
| 12-20 | Sealed bodies and record plaintexts MUST be padded before encryption | `TEST` | 6.5-10, 6.5-16 |
| 12-21 | Decoders MUST verify padding rather than assume it | `TEST` | 6.5-17 |
| 12-22 | Implementations MUST NOT claim metadata properties beyond those §13.1 concedes | `PROCESS` | Editorial restraint; §13.1 rows below are the concession, and README/spec state it |
| 12-23 | Every transition at epoch ≥ 1 MUST carry a fixed-size `removal_notice` under the previous epoch's secret | `TEST` | 6.5-13 |
| 12-24 | A removal notice MUST be signed by the transition's signer; clients MUST reject one that is not | `TEST` | 6.5-14 |
| 12-25 | Holders of `group_secret[e-1]` MUST verify the notice in both directions | `TEST` | 9.1-S10, 9.1-S11 |
| 12-26 | Backends MUST accept any published `auth_pubkey` for reads and require the current key for writes | `BACKEND` | 10.1-1 |
| 12-27 | Implementations MUST NOT present `"suppressed"` as a silence guarantee, nor `removed_at` as verified time | `PROCESS` | 9.3-6 |

## §13 Threat Model — residual exposure

| # | Item | Strength | Status | Held by |
|---|---|---|---|---|
| 13.1-1 | A relay still observes group size *bounds* (the capacity profile), activity timing, and record count | — | `PROCESS` | Conceded, not defended. |
| 13.1-2 | A relay still observes which network origin talks to which `group_id` | — | `PROCESS` | Conceded. IP-blindness is deployment policy, not cryptography (§13.2) |
| 13.2-1 | Clients MAY reduce timing correlation via transport-level measures (VPN, batching) | *MAY* | `N/A` | Outside a client library's control; named so hosts know it is theirs |

A compromised endpoint, or a malicious member exfiltrating decrypted
content, are examples of threats that remain out of scope.

---

## Summary

Counting the **102 canonical requirement rows** in the tables above —
every normative statement in §5–§10 and §13, plus 12-2 and 12-6b (the
two §12 bullets that state a requirement not defined elsewhere). The
remaining §12 bullets are cross-references to those rows and are not
double-counted.

Metadata minimization accounts to 35 rows: three §5.8 rules, thirteen §6.5 wire
formats, ten §9.1 checks (five outer, five successor), six §10 rows
(including the §10.5 capability table), and three §13 concessions.

Three §13 rows state what a relay *can* still observe rather than an
obligation, so they carry no strength marker and appear in the "—"
column.

| | MUST | SHOULD | — | Total |
|---|---|---|---|---|
| `TEST` | 74 | 9 | 0 | 83 |
| `BACKEND` | 5 | 1 | 0 | 6 |
| `PROCESS` | 3 | 1 | 2 | 6 |
| `DESIGN` | 4 | 0 | 0 | 4 |
| `N/A` | 1 | 1 | 1 | 3 |
| **Total** | **87** | **12** | **3** | **102** |

**Every client-observable MUST in §5–§13 now maps to a named test.** By
spec [§14](https://github.com/groupvault/protocol/blob/main/README.md#14-conformance), **CircleKey therefore conforms
to GroupVault Protocol v1** for the client role it implements. The
`BACKEND` rows above are the host's obligations, not CircleKey's; see
[backend-checklist.md](./backend-checklist.md). This claim is
independent of, and not a substitute for, third-party security review
— see caveat 2 below.

> `group_id` is worth dwelling on, because it is the field where an
> application would most naturally supply a name — and it is the single
> most repeated value in the protocol, present in plaintext on every
> request. A host passing `"acme-workspace"` would hand the relay a
> label for everything that follows, so the client generates the id and
> returns it on the state rather than accepting one (5.8-2, 6.5-18b,
> 12-17).
>
> Note the asymmetry with `record_id`, which is *derived*. `group_id`
> has to be **generated** from randomness instead: it must exist before
> the genesis transition, and therefore before the genesis secret it
> would otherwise be derived from.

The requirements not held by a CircleKey test are, exhaustively:

- **6 backend obligations** (9.3-2, 10.4-2, 10.1-1, 10.1-2, 10.2-3, and
  9.3-3 = 12-15) — the host's server, not this library. `MockTransport`
  is the executable reference and `runHostIntegrationScenario` now
  probes the §10.1 split directly;
  [backend-checklist.md](./backend-checklist.md) is the contract.
- **7 process/forward-looking items** (5.5-1, 6.2-2, 6.4-3, 8.1-1,
  9.3-6, 12-22, and the §13.1 concessions) — KDF parameter review, a v2
  suite's key binding, deployment guidance, and the claims an
  implementation must refrain from making.
- **3 not applicable** (8.1-2 host UI, 9.6-3 no user-chosen
  passphrases, 13.2-1 transport-level measures).
- **4 held by construction** (7-2, 7-3, 9.5-1, 10.3-1) — enforced by a
  closed enum or by the absence of an API, each with a regression test
  named above.

### Caveats on the claim

1. **Two §6.1 rows depend on the manual browser suite.** Nothing in CI
   runs `test/browser/`; it can rot while the Node suite stays green.
   Re-run it when touching the IndexedDB, locks, or hints adapters.
2. **Conformance is not a security audit.** This document says the
   implementation matches the specification. It does not say the
   specification is sound, nor that the implementation is free of
   memory-safety, side-channel, or supply-chain problems. CircleKey has
   **not** been independently audited.
3. **The rows are mutation-verified, not merely written.** For each
   one, the guarantee was broken and the named test watched go red
   before the row was recorded. This matters because the failure a
   conformance map is most prone to is a row naming a test that passes
   for some reason unrelated to the requirement — which reading the code
   and agreeing with it will never reveal.
4. **`DESIGN` rows are weaker than `TEST` rows.** They hold as long as
   the structure holds — adding a device endpoint to `Transport`, or a
   free-form string to `deriveKey`, would break them without failing the
   named regression test. They are called out so a reviewer can watch
   those seams.

### Maintaining this document

A spec change that adds or alters a normative requirement must land here
in the same change, with its test. The audit method that produced this
table — and that should be repeated — is not reading the code and
agreeing with it, but **breaking the implementation and confirming a
test goes red**. The case to watch for is a requirement that is
correctly implemented but not actually guarded: disable it, and if the
suite still passes, the row names a test that was never holding it.
