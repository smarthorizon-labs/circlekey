/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Epoch chain verification and construction — the security core
 * (spec §9.1).
 *
 * `verifyTransition` implements the full client-side validation
 * checklist. Nothing here trusts the backend: every check depends
 * only on signatures, hashes, and previously verified local state
 * (spec §5.7). A transition that fails any check throws a
 * `TransitionRejectedError` subclass naming the exact check, and MUST
 * NOT be applied (spec §9.1).
 *
 * Structural note: inputs are typed `EpochTransition`, but content is
 * treated as hostile — keys must decode to valid curve points, member
 * sets and envelopes are validated exhaustively, and canonicalization
 * itself rejects non-protocol values during hashing. Wire-shape
 * parsing of raw backend JSON happens at the boundary, in
 * `core/wire.ts` via `SyncManager.fetchNewTransitions`, so this
 * module can rely on the declared shape while still trusting none of
 * the content.
 */

import { base64UrlToBytes, bytesToBase64Url, utf8String } from "./bytes";
import {
  canonicalBytes,
  genesisMarker,
  hashTransition,
  transitionSigningBytes,
  type Sha256Fn,
  type UnsignedEpochTransition,
} from "./codec";
import {
  envelopeEpoch,
  openHistoryLink,
  openRemovalNotice,
  sealRemovalNotice,
  openTransitionBody,
  placeEnvelopes,
  sealEnvelope,
  sealHistoryLink,
  sealTransitionBody,
  validateHistoryLinkShape,
  GROUP_SECRET_LENGTH,
} from "./envelopes";
import {
  BadSignatureError,
  ChainMismatchError,
  EncodingError,
  EpochGapError,
  MalformedTransitionError,
  PolicyViolationError,
  UnauthorizedSignerError,
} from "./errors";
import {
  cloneMembers,
  findMember,
  memberDevices,
  satisfiesPolicy,
  type GroupState,
} from "./group-state";
import type { DeviceKeys } from "./key-manager";
import { DEFAULT_CAPACITY, isCapacityName, profileForPolicy } from "./profiles";
import { deriveRelayAuthPublicKey } from "./relay-auth";
import {
  GOVERNANCE_ACTIONS,
  type EpochTransition,
  type GroupPolicy,
  type MemberEntry,
  type RemovalNotice,
  type RemovalNoticePolicy,
  type SecretEnvelope,
  type WireTransition,
} from "./types";
import { parseEpochTransition, parseRemovalNotice } from "./wire";
import type { CryptoProvider } from "../ports/crypto-provider";

const KEY_LENGTH = 32;
const SIGNATURE_LENGTH = 64;

/** spec §8.1: silence should be the deliberate choice, not the default. */
export const DEFAULT_REMOVAL_NOTICE: RemovalNoticePolicy = "required";

const REMOVAL_NOTICE_POLICIES: readonly string[] = ["required", "suppressed"];

// ---------------------------------------------------------------------------
// Verification (spec §9.1 checklist)
// ---------------------------------------------------------------------------

/**
 * Verify one **inner** transition against the last verified state
 * (`null` for genesis) and return the resulting state. Check order:
 * epoch (1), chain hash (2), member-set structure, signer
 * authorization (3), signature (4), action semantics, policy
 * invariant (5).
 *
 * This is the §9.1 checklist proper and it is unchanged by the sealed
 * body: the outer layer is transport. Envelope and `auth_pubkey`
 * checks need the outer structure and live in
 * {@link verifyWireTransition}, which is the entry point callers
 * should use — this one is exported for tests that exercise the
 * checklist directly.
 */
export async function verifyTransition(
  crypto: CryptoProvider,
  prevState: GroupState | null,
  transition: EpochTransition,
): Promise<GroupState> {
  return prevState === null
    ? verifyGenesis(crypto, transition)
    : verifySuccessor(crypto, prevState, transition);
}

/**
 * Open a sealed body: spec §9.1 outer checks **O2–O4**.
 *
 * O2 decrypts under `group_secret[epoch]` with the *outer* group and
 * epoch as AAD; O4 verifies the padding; O3 requires the inner routing
 * values to equal the outer ones. O1 (finding the envelope that yields
 * the secret) is the caller's, because only the caller knows whether it
 * holds this device's envelope or a secret walked back from the §9.7
 * history chain.
 *
 * **Opening proves membership, never authorization** (spec §9.1). The
 * returned body is untrusted: it has been shown to come from *someone*
 * holding this epoch's secret, and nothing more. Callers MUST run the
 * §9.1 checklist on it — {@link verifyWireTransition} does.
 */
export async function openWireTransition(
  crypto: CryptoProvider,
  wire: WireTransition,
  groupSecret: Uint8Array,
): Promise<{ transition: EpochTransition; paddedSize: number }> {
  // O2 + O4. A relay that relabels the body onto another epoch or
  // group breaks the AAD here rather than producing a plausible body.
  const opened = await openTransitionBody(
    crypto,
    wire.group_id,
    wire.epoch,
    groupSecret,
    wire.sealed_body,
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8String(opened.innerBytes)) as unknown;
  } catch {
    throw new MalformedTransitionError("sealed body does not contain valid JSON");
  }
  // The body is relay-supplied bytes: shape-validate before use, and
  // drop anything unknown rather than carrying it into the hash.
  const transition = parseEpochTransition(parsed);

  // O3. Redundant with the AAD by construction, and required anyway:
  // it is the check that still holds if an implementation gets the AAD
  // wrong, which is exactly the bug nobody would notice.
  if (transition.group_id !== wire.group_id) {
    throw new MalformedTransitionError(
      "sealed body group_id does not match the routing group_id (spec §9.1 check O3)",
    );
  }
  if (transition.epoch !== wire.epoch) {
    throw new MalformedTransitionError(
      "sealed body epoch does not match the routing epoch (spec §9.1 check O3)",
    );
  }
  return { transition, paddedSize: opened.paddedSize };
}

/**
 * Full verification of a wire transition (spec §9.1, checks O1–O4 plus
 * the whole inner checklist).
 *
 * `groupSecret` is `group_secret[wire.epoch]`, obtained by the caller
 * from check O1 — trial-decrypting the envelopes for a current
 * transition, or walking the §9.7 history chain when catching up on
 * older ones.
 */
export async function verifyWireTransition(
  crypto: CryptoProvider,
  prevState: GroupState | null,
  wire: WireTransition,
  groupSecret: Uint8Array,
  /**
   * `group_secret[epoch-1]`, when this device holds it. Required to
   * perform §9.1 check 11; its absence is an ordinary state (a device
   * catching up from a backup restore), not a failure.
   */
  previousGroupSecret?: Uint8Array,
): Promise<{ state: GroupState; transition: EpochTransition; noticeChecked: boolean }> {
  const { transition, paddedSize } = await openWireTransition(crypto, wire, groupSecret);

  // The §9.1 checklist decides. Decryption bought us nothing here.
  const state = await verifyTransition(crypto, prevState, transition);

  // Profile-dependent checks, only knowable once the body is open:
  // the genesis carries the policy that fixes the profile, and a
  // `set_policy` must not have moved it (spec §8.1, §9.1 check 8).
  const profile = profileForPolicy(state.policy);
  if (paddedSize !== profile.sealedBodySize) {
    throw new MalformedTransitionError(
      `sealed body is padded to ${String(paddedSize)} bytes, but this group's ` +
        `capacity profile fixes ${String(profile.sealedBodySize)} (spec §6.5)`,
    );
  }
  if (prevState !== null && prevState.policy.capacity !== state.policy.capacity) {
    throw new MalformedTransitionError(
      "capacity profile is immutable after genesis (spec §8.1)",
    );
  }

  validateEnvelopes(transition, wire, memberDevices(transition.members), profile.envelopeSlots);

  // spec §9.1 checks 10-11 — the removal notice.
  let noticeChecked = false;
  if (wire.epoch === 0) {
    if (wire.removal_notice !== undefined) {
      throw new MalformedTransitionError(
        "genesis must not carry a removal_notice (spec §6.5)",
      );
    }
  } else if (wire.removal_notice === undefined) {
    throw new MalformedTransitionError(
      "missing removal_notice (spec §6.5, §9.1 check 10)",
    );
  } else if (previousGroupSecret !== undefined && prevState !== null) {
    // Only a holder of group_secret[epoch-1] can perform check 11.
    // Recording *whether* it ran matters: spec §9.1 says skipping a
    // check you cannot perform is not the same as passing it, so the
    // caller is told rather than left to assume.
    await verifyRemovalNotice({
      crypto,
      wire,
      transition,
      prevState,
      policy: state.policy,
      previousGroupSecret,
      noticeSize: profile.removalNoticeSize,
    });
    noticeChecked = true;
  }

  // spec §9.1 check 6 — the §9.7 history link, now an outer field.
  // Structural only: proving it decrypts to the *right* previous secret
  // needs a client that holds it, and happens in
  // `GroupManager.recoverSecretsLocked` (HistoryIntegrityError).
  if (wire.epoch === 0) {
    if (wire.prev_secret_ciphertext !== undefined) {
      throw new MalformedTransitionError(
        "genesis must not carry prev_secret_ciphertext (spec §9.7)",
      );
    }
  } else {
    if (wire.prev_secret_ciphertext === undefined) {
      throw new MalformedTransitionError(
        "missing prev_secret_ciphertext (spec §9.7 history chain)",
      );
    }
    try {
      validateHistoryLinkShape(wire.prev_secret_ciphertext);
    } catch {
      throw new MalformedTransitionError("malformed prev_secret_ciphertext blob");
    }
  }

  // spec §9.1 check 7/8: `auth_pubkey` must be the key every member can
  // derive from this epoch's secret. A value nobody can reproduce would
  // lock the whole membership out of submitting at the next epoch
  // (spec §10.1), so it is rejected rather than tolerated.
  const expectedAuth = await deriveRelayAuthPublicKey(crypto, groupSecret);
  if (wire.auth_pubkey !== bytesToBase64Url(expectedAuth)) {
    throw new MalformedTransitionError(
      "auth_pubkey is not derivable from this epoch's group_secret (spec §9.1 check 7)",
    );
  }

  return { state, transition, noticeChecked };
}

/** Re-verify a full chain of inner bodies from genesis. */
export async function replayChain(
  crypto: CryptoProvider,
  transitions: readonly EpochTransition[],
): Promise<GroupState> {
  const [genesis, ...rest] = transitions;
  if (genesis === undefined) {
    throw new MalformedTransitionError("cannot replay an empty chain");
  }
  let state = await verifyTransition(crypto, null, genesis);
  for (const transition of rest) {
    state = await verifyTransition(crypto, state, transition);
  }
  return state;
}

/**
 * Re-verify a full wire chain from genesis (startup reload, vectors).
 *
 * This is the **backward-then-forward** order spec §9.1 requires of a
 * client catching up. The caller supplies `secrets` — every epoch's
 * `group_secret`, obtained by opening the newest envelope (check O1)
 * and walking the §9.7 history chain backward from it
 * ({@link recoverSecretHistory}). Only then can the bodies be opened,
 * and only then can the chain be verified forward from genesis.
 *
 * Verifying forward is not optional and is not implied by the bodies
 * decrypting: a body opens for anyone holding the epoch secret, which
 * every member is. Authorization is decided here, transition by
 * transition.
 */
export async function replayWireChain(
  crypto: CryptoProvider,
  wires: readonly WireTransition[],
  secrets: ReadonlyMap<number, Uint8Array>,
): Promise<{ state: GroupState; transitions: EpochTransition[] }> {
  if (wires.length === 0) {
    throw new MalformedTransitionError("cannot replay an empty chain");
  }
  let state: GroupState | null = null;
  const transitions: EpochTransition[] = [];
  for (const wire of wires) {
    const secret = secrets.get(wire.epoch);
    if (secret === undefined) {
      throw new MalformedTransitionError(
        `no group_secret for epoch ${String(wire.epoch)} — cannot open its sealed body`,
      );
    }
    const verified = await verifyWireTransition(
      crypto,
      state,
      wire,
      secret,
      secrets.get(wire.epoch - 1),
    );
    state = verified.state;
    transitions.push(verified.transition);
  }
  if (state === null) {
    throw new MalformedTransitionError("cannot replay an empty chain");
  }
  return { state, transitions };
}

async function verifyGenesis(
  crypto: CryptoProvider,
  transition: EpochTransition,
): Promise<GroupState> {
  if (transition.action !== "create") {
    throw new MalformedTransitionError(
      "no verified state for this group — expected a genesis `create` transition",
    );
  }
  // spec §9.1 genesis check 1.
  if (transition.epoch !== 0) {
    throw new EpochGapError(`genesis epoch must be 0, got ${String(transition.epoch)}`);
  }
  // spec §9.1 genesis check 2.
  const marker = await genesisMarker(sha256Of(crypto), transition.group_id);
  if (transition.prev_transition_hash !== marker) {
    throw new ChainMismatchError("genesis prev_transition_hash is not the genesis marker");
  }
  validateMemberSet(transition.members);
  // spec §9.1 genesis check 3.
  const creator = transition.members[0];
  if (transition.members.length !== 1 || !creator?.is_manager) {
    throw new MalformedTransitionError(
      "genesis must contain exactly one member, the creator, as manager",
    );
  }
  const policy = requirePolicy(transition);
  // spec §9.1 genesis check 7 — the profile is fixed here and nowhere
  // else, so a genesis that omits it leaves every later transition's
  // padded sizes undefined.
  if (policy.capacity === undefined) {
    throw new MalformedTransitionError(
      "genesis policy must declare a capacity profile (spec §9.1 genesis check 7)",
    );
  }
  if (policy.removal_notice === undefined) {
    throw new MalformedTransitionError(
      "genesis policy must declare removal_notice (spec §9.1 genesis check 7)",
    );
  }
  // spec §9.1 genesis check 4.
  await verifySignerBinding(crypto, transition, [creator]);
  // spec §9.1 genesis check 5.
  await verifySignature(crypto, transition);
  // Genesis checks 6-9 concern the outer structure (history link,
  // envelopes, auth_pubkey) and are performed by
  // `verifyWireTransition`, which is the only caller that has it.
  return await acceptedState(crypto, transition, policy);
}

async function verifySuccessor(
  crypto: CryptoProvider,
  prevState: GroupState,
  transition: EpochTransition,
): Promise<GroupState> {
  if (transition.action === "create") {
    throw new MalformedTransitionError("`create` is only valid as the genesis transition");
  }
  if (transition.group_id !== prevState.group_id) {
    throw new MalformedTransitionError("transition group_id does not match this chain");
  }
  // spec §9.1 check 1 — rejects gaps and rollback.
  if (transition.epoch !== prevState.epoch + 1) {
    throw new EpochGapError(
      `expected epoch ${String(prevState.epoch + 1)}, got ${String(transition.epoch)}`,
    );
  }
  // spec §9.1 check 2 — rejects forked/equivocated history.
  if (transition.prev_transition_hash !== prevState.last_transition_hash) {
    throw new ChainMismatchError(
      "prev_transition_hash does not match the last accepted transition",
    );
  }
  validateMemberSet(transition.members);
  // spec §9.1 check 3 — the signing device was authorized *before*
  // this transition: a manager for governance, the affected member
  // themselves for the self-scoped device actions (spec §9.5).
  const isGovernance = (GOVERNANCE_ACTIONS as readonly string[]).includes(
    transition.action,
  );
  const signer = await verifySignerBinding(
    crypto,
    transition,
    prevState.members,
    isGovernance,
  );
  // spec §9.1 check 4.
  await verifySignature(crypto, transition);

  validateActionSemantics(prevState, transition, signer);
  const policy = effectivePolicy(prevState, transition);
  // spec §9.1 check 5 — enforced after every individual transition (§5.6, §8.1).
  if (!satisfiesPolicy(transition.members, policy)) {
    throw new PolicyViolationError(
      `resulting member set has fewer than min_managers=${String(policy.min_managers)} managers`,
    );
  }
  // Checks 6-9 concern the outer structure and are performed by
  // `verifyWireTransition`.
  return await acceptedState(crypto, transition, policy);
}

// ---------------------------------------------------------------------------
// Verification internals
// ---------------------------------------------------------------------------

function sha256Of(crypto: CryptoProvider): Sha256Fn {
  return (data) => crypto.sha256(data);
}

async function acceptedState(
  crypto: CryptoProvider,
  transition: EpochTransition,
  policy: GroupPolicy,
): Promise<GroupState> {
  // Copy the whole policy, not just `min_managers`. Both optional
  // fields are load-bearing for verification: `capacity` selects every
  // padded size (spec §6.5) and `removal_notice` decides check 11
  // (spec §8.1). Dropping them here silently resolved every group to
  // the default profile and made the capacity-immutability check
  // compare undefined with undefined — which is to say, enforce
  // nothing. Rebuilt field by field so an unknown key cannot ride in.
  const carried: GroupPolicy = { min_managers: policy.min_managers };
  if (policy.capacity !== undefined) carried.capacity = policy.capacity;
  if (policy.removal_notice !== undefined) carried.removal_notice = policy.removal_notice;
  return {
    group_id: transition.group_id,
    epoch: transition.epoch,
    members: cloneMembers(transition.members),
    policy: carried,
    last_transition_hash: await hashTransition(sha256Of(crypto), transition),
  };
}

function validateMemberSet(members: readonly MemberEntry[]): void {
  if (members.length === 0) {
    throw new MalformedTransitionError("member set must not be empty");
  }
  const userIds = new Set<string>();
  const deviceKeys = new Set<string>();
  for (const member of members) {
    if (userIds.has(member.user_id)) {
      throw new MalformedTransitionError(`duplicate user_id: ${member.user_id}`);
    }
    userIds.add(member.user_id);
    if (member.device_pubkeys.length === 0) {
      throw new MalformedTransitionError(
        `member ${member.user_id} has no device pubkeys`,
      );
    }
    for (const deviceKey of member.device_pubkeys) {
      decodeKey(deviceKey, "device pubkey");
      if (deviceKeys.has(deviceKey)) {
        throw new MalformedTransitionError(`duplicate device pubkey: ${deviceKey}`);
      }
      deviceKeys.add(deviceKey);
    }
  }
}

/**
 * spec §9.1 check 3, via the device key model:
 * `signed_by` (Ed25519) binds to a member's X25519 device key through
 * the birational map — verified locally, no backend mapping trusted.
 */
async function verifySignerBinding(
  crypto: CryptoProvider,
  transition: EpochTransition,
  membersBefore: readonly MemberEntry[],
  requireManager = false,
): Promise<MemberEntry> {
  const identityKey = decodeKey(transition.signed_by, "signed_by");
  let signerDeviceKey: string;
  try {
    signerDeviceKey = bytesToBase64Url(await crypto.ed25519ToX25519PublicKey(identityKey));
  } catch {
    throw new MalformedTransitionError("signed_by is not a valid Ed25519 public key");
  }
  const signer = membersBefore.find((member) =>
    member.device_pubkeys.includes(signerDeviceKey),
  );
  if (signer === undefined) {
    throw new UnauthorizedSignerError(
      "signed_by does not belong to any member of the pre-transition member set",
    );
  }
  // spec §9.1 check 3: governance needs a manager; device actions
  // instead need self-scoping, enforced in validateActionSemantics.
  if (requireManager && !signer.is_manager) {
    throw new UnauthorizedSignerError(
      `signer ${signer.user_id} was not a manager before this transition`,
    );
  }
  return signer;
}

/** spec §9.1 check 4. */
async function verifySignature(
  crypto: CryptoProvider,
  transition: EpochTransition,
): Promise<void> {
  let signature: Uint8Array;
  try {
    signature = base64UrlToBytes(transition.signature);
  } catch {
    throw new BadSignatureError("signature is not valid base64url");
  }
  if (signature.length !== SIGNATURE_LENGTH) {
    throw new BadSignatureError("signature must be 64 bytes");
  }
  const valid = await crypto.ed25519Verify(
    decodeKey(transition.signed_by, "signed_by"),
    transitionSigningBytes(transition),
    signature,
  );
  if (!valid) {
    throw new BadSignatureError("Ed25519 signature over the transition is invalid");
  }
}

/**
 * Validates that the member-set delta matches the declared action.
 *
 * Device lists of *existing* members may change only through the
 * self-scoped `add_device` / `remove_device` actions (spec §9.5), and
 * only for the member who signed — enforced below against `signer`.
 * Every other action must leave every device list untouched.
 */
function validateActionSemantics(
  prevState: GroupState,
  transition: EpochTransition,
  signer: MemberEntry,
): void {
  const prev = prevState.members;
  const next = transition.members;
  const added: MemberEntry[] = [];
  const flagChanged: { before: MemberEntry; after: MemberEntry }[] = [];
  const deviceChanged: { before: MemberEntry; after: MemberEntry }[] = [];
  let removedCount = 0;

  for (const member of next) {
    const before = findMember(prev, member.user_id);
    if (before === undefined) {
      added.push(member);
      continue;
    }
    if (!sameDevices(before.device_pubkeys, member.device_pubkeys)) {
      deviceChanged.push({ before, after: member });
    }
    if (before.is_manager !== member.is_manager) {
      flagChanged.push({ before, after: member });
    }
  }
  for (const member of prev) {
    if (findMember(next, member.user_id) === undefined) removedCount++;
  }

  const isDeviceAction =
    transition.action === "add_device" || transition.action === "remove_device";
  if (!isDeviceAction && deviceChanged.length > 0) {
    throw new MalformedTransitionError(
      `device set of an existing member changed inside a ${transition.action} transition`,
    );
  }

  const requireDelta = (
    condition: boolean,
    description: string,
  ): void => {
    if (!condition) {
      throw new MalformedTransitionError(
        `${transition.action} transition must ${description}`,
      );
    }
  };

  switch (transition.action) {
    case "add":
      requireDelta(
        added.length === 1 && removedCount === 0 && flagChanged.length === 0,
        "add exactly one new member and change nothing else",
      );
      return;
    case "remove":
      requireDelta(
        removedCount === 1 && added.length === 0 && flagChanged.length === 0,
        "remove exactly one member and change nothing else",
      );
      return;
    case "promote": {
      const change = flagChanged[0];
      requireDelta(
        flagChanged.length === 1 &&
          change !== undefined &&
          !change.before.is_manager &&
          added.length === 0 &&
          removedCount === 0,
        "promote exactly one non-manager and change nothing else",
      );
      return;
    }
    case "demote": {
      const change = flagChanged[0];
      requireDelta(
        flagChanged.length === 1 &&
          change !== undefined &&
          change.before.is_manager &&
          added.length === 0 &&
          removedCount === 0,
        "demote exactly one manager and change nothing else",
      );
      return;
    }
    case "set_policy":
      requireDelta(
        added.length === 0 && removedCount === 0 && flagChanged.length === 0,
        "leave the member set untouched",
      );
      return;
    // spec §9.5: self-scoped device actions. The signer may only touch
    // their own entry, and only its device list.
    case "add_device":
    case "remove_device": {
      const change = deviceChanged[0];
      requireDelta(
        deviceChanged.length === 1 &&
          change !== undefined &&
          added.length === 0 &&
          removedCount === 0 &&
          flagChanged.length === 0,
        "change exactly one member's device list and nothing else",
      );
      if (change === undefined) return; // unreachable; narrows the type
      if (change.after.user_id !== signer.user_id) {
        // spec §9.1 check 3: not even a manager may edit someone
        // else's devices this way.
        throw new UnauthorizedSignerError(
          `${transition.action} may only modify the signer's own devices — signer is ${signer.user_id}, target is ${change.after.user_id}`,
        );
      }
      validateDeviceDelta(transition.action, change.before, change.after);
      return;
    }
    default:
      // Hostile input can carry an action outside the type.
      throw new MalformedTransitionError("unknown transition action");
  }
}

/**
 * A device action adds or removes exactly one key, leaving the other
 * keys and their order intact (spec §9.5). Requiring the rest to be
 * untouched keeps the delta unambiguous and makes a swap — drop one
 * device while adding another — impossible to disguise as either.
 */
function validateDeviceDelta(
  action: "add_device" | "remove_device",
  before: MemberEntry,
  after: MemberEntry,
): void {
  const [shorter, longer] =
    action === "add_device"
      ? [before.device_pubkeys, after.device_pubkeys]
      : [after.device_pubkeys, before.device_pubkeys];
  if (longer.length !== shorter.length + 1) {
    throw new MalformedTransitionError(
      `${action} must change the device list by exactly one key`,
    );
  }
  // The unchanged keys must remain, in order.
  const remaining = longer.filter((key) => shorter.includes(key));
  if (!sameDevices(remaining, shorter)) {
    throw new MalformedTransitionError(
      `${action} must leave the member's other devices untouched`,
    );
  }
  if (action === "remove_device" && after.device_pubkeys.length === 0) {
    // validateMemberSet already rejects this; stated here so the
    // reason is explicit rather than incidental.
    throw new MalformedTransitionError(
      "remove_device must not remove a member's last device",
    );
  }
}

function effectivePolicy(
  prevState: GroupState,
  transition: EpochTransition,
): GroupPolicy {
  if (transition.action === "set_policy") {
    return requirePolicy(transition);
  }
  if (transition.policy !== undefined) {
    throw new MalformedTransitionError(
      "policy may only be present on create/set_policy transitions (spec §9.1)",
    );
  }
  return prevState.policy;
}

function requirePolicy(transition: EpochTransition): GroupPolicy {
  const policy = transition.policy;
  if (policy === undefined) {
    throw new MalformedTransitionError(
      `${transition.action} transition requires a policy (spec §9.1)`,
    );
  }
  validatePolicyValue(policy);
  return policy;
}

function validatePolicyValue(policy: GroupPolicy): void {
  if (!Number.isSafeInteger(policy.min_managers) || policy.min_managers < 1) {
    throw new MalformedTransitionError("min_managers must be an integer >= 1");
  }
  if (policy.capacity !== undefined && !isCapacityName(policy.capacity)) {
    throw new MalformedTransitionError(
      `unknown capacity profile: ${JSON.stringify(policy.capacity)}`,
    );
  }
  // Compared against a widened list rather than the union literals: a
  // host calling from JavaScript can pass anything, and the type
  // narrowing that makes the direct comparison "provably false" is a
  // compile-time fact, not a runtime one.
  const notice: string | undefined = policy.removal_notice;
  if (notice !== undefined && !REMOVAL_NOTICE_POLICIES.includes(notice)) {
    throw new MalformedTransitionError(
      `unknown removal_notice policy: ${JSON.stringify(notice)}`,
    );
  }
}

/**
 * Every transition re-envelopes the fresh `group_secret` to every
 * current device — no more, no fewer (spec §9.1 simplification), in an
 * array padded to the capacity profile's slot count with decoys.
 *
 * Envelopes are unaddressed (spec §6.5), so this cannot check
 * recipients directly. `envelope_slots` carries the mapping instead:
 * one distinct in-range slot per device in the canonical order. That is
 * what keeps all three properties provable — no device skipped, no
 * device served twice, and no slot left over for an envelope sealed to
 * a non-member, since every unclaimed slot must be a decoy.
 *
 * What it cannot prove on its own is that the envelope at a device's
 * claimed slot actually opens for that device; only that device can
 * check that, and spec §9.1 check 9 requires it to (see
 * `GroupManager.recoverSecretsLocked`).
 */
function validateEnvelopes(
  transition: EpochTransition,
  wire: WireTransition,
  currentDevices: readonly string[],
  slotCount: number,
): void {
  if (wire.secret_envelopes.length !== slotCount) {
    throw new MalformedTransitionError(
      `secret_envelopes must hold exactly ${String(slotCount)} slots for this capacity ` +
        `profile, got ${String(wire.secret_envelopes.length)} (spec §6.5)`,
    );
  }
  for (const envelope of wire.secret_envelopes) {
    if (readEnvelopeEpoch(envelope) !== transition.epoch) {
      throw new MalformedTransitionError(
        "secret envelope epoch header does not match the transition epoch",
      );
    }
  }

  const slots = transition.envelope_slots;
  if (slots.length !== currentDevices.length) {
    throw new MalformedTransitionError(
      `envelope_slots must name one slot per member device: expected ` +
        `${String(currentDevices.length)}, got ${String(slots.length)}`,
    );
  }
  const seen = new Set<number>();
  for (const slot of slots) {
    if (!Number.isSafeInteger(slot) || slot < 0 || slot >= slotCount) {
      throw new MalformedTransitionError(
        `envelope_slots entry ${String(slot)} is outside [0, ${String(slotCount)})`,
      );
    }
    if (seen.has(slot)) {
      throw new MalformedTransitionError(
        `two devices claim envelope slot ${String(slot)} — one of them was not enveloped`,
      );
    }
    seen.add(slot);
  }
}

function readEnvelopeEpoch(envelope: SecretEnvelope): number {
  try {
    return envelopeEpoch(envelope);
  } catch {
    throw new MalformedTransitionError("malformed secret envelope blob");
  }
}

function sameDevices(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function decodeKey(value: string, what: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(value);
  } catch (error) {
    if (error instanceof EncodingError) {
      throw new MalformedTransitionError(`${what} is not valid base64url`);
    }
    throw error;
  }
  if (bytes.length !== KEY_LENGTH) {
    throw new MalformedTransitionError(`${what} must be 32 bytes`);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Construction (manager side)
// ---------------------------------------------------------------------------

export interface BuildResult {
  /** What goes to the relay (spec §6.5). */
  wire: WireTransition;
  /** The inner body, already sealed into `wire.sealed_body`. */
  transition: EpochTransition;
  /** The fresh `group_secret` for the new epoch. Persist only after acceptance. */
  groupSecret: Uint8Array;
}

/** Devices present before a transition but absent after it (spec §6.5). */
export function removedDevices(
  before: readonly MemberEntry[],
  after: readonly MemberEntry[],
): string[] {
  const remaining = new Set(memberDevices(after));
  return memberDevices(before)
    .filter((device) => !remaining.has(device))
    .sort();
}

/** spec §8.1: absent policy reads as the default. */
export function noticePolicy(policy: GroupPolicy): RemovalNoticePolicy {
  return policy.removal_notice ?? DEFAULT_REMOVAL_NOTICE;
}

/**
 * Build and sign a removal notice (spec §6.5), or return empty bytes
 * when nothing was removed or the policy suppresses it.
 */
async function buildRemovalNotice(options: {
  crypto: CryptoProvider;
  groupId: string;
  epoch: number;
  removed: readonly string[];
  policy: GroupPolicy;
  signer: DeviceKeys;
  now: string;
}): Promise<Uint8Array> {
  const { crypto, groupId, epoch, removed, policy, signer, now } = options;
  if (removed.length === 0 || noticePolicy(policy) === "suppressed") {
    return new Uint8Array(0);
  }
  const unsigned = {
    group_id: groupId,
    epoch,
    removed_devices: [...removed],
    removed_at: now,
    signed_by: bytesToBase64Url(signer.identity.publicKey),
  };
  const signature = await crypto.ed25519Sign(
    signer.identity.privateKey,
    canonicalBytes(unsigned),
  );
  const notice: RemovalNotice = {
    ...unsigned,
    signature: bytesToBase64Url(signature),
  };
  return canonicalBytes(notice);
}

/**
 * spec §9.1 check 11 — the notice agrees with the body and the policy.
 *
 * Runs only for a client holding `group_secret[epoch-1]`. A device
 * catching up from a backup restore may not, and spec §9.1 is explicit
 * that this is not a failure: skipping a check you cannot perform is
 * not the same as passing it, so the caller is told which happened.
 */
async function verifyRemovalNotice(options: {
  crypto: CryptoProvider;
  wire: WireTransition;
  transition: EpochTransition;
  prevState: GroupState;
  policy: GroupPolicy;
  previousGroupSecret: Uint8Array;
  noticeSize: number;
}): Promise<void> {
  const { crypto, wire, transition, prevState, policy, previousGroupSecret } = options;
  if (wire.removal_notice === undefined) {
    throw new MalformedTransitionError(
      "missing removal_notice (spec §6.5, §9.1 check 10)",
    );
  }
  const bytes = await openRemovalNotice(
    crypto,
    wire.group_id,
    wire.epoch,
    previousGroupSecret,
    wire.removal_notice,
    options.noticeSize,
  );
  const removed = removedDevices(prevState.members, transition.members);
  const mode = noticePolicy(policy);

  if (bytes.length === 0) {
    // Empty is correct only when there was nothing to announce, or the
    // group chose silence.
    if (removed.length > 0 && mode === "required") {
      throw new MalformedTransitionError(
        `transition removes ${String(removed.length)} device(s) but carries no removal ` +
          "notice, and this group's policy requires one (spec §8.1, §9.1 check 11)",
      );
    }
    return;
  }

  if (mode === "suppressed") {
    throw new MalformedTransitionError(
      "removal notice present but this group's policy suppresses notices (spec §8.1)",
    );
  }
  if (removed.length === 0) {
    throw new MalformedTransitionError(
      "removal notice present but this transition removes nothing (spec §9.1 check 11)",
    );
  }

  const notice = parseRemovalNotice(JSON.parse(utf8String(bytes)) as unknown);
  if (notice.group_id !== wire.group_id || notice.epoch !== wire.epoch) {
    throw new MalformedTransitionError(
      "removal notice group_id/epoch does not match its transition (spec §9.1 check 11)",
    );
  }
  if (
    notice.removed_devices.length !== removed.length ||
    notice.removed_devices.some((device: string, index: number) => device !== removed[index])
  ) {
    throw new MalformedTransitionError(
      "removal notice does not list exactly the devices this transition removed " +
        "(spec §9.1 check 11)",
    );
  }
  // Binding the notice to the transition's own signer is what makes it
  // authorized: the §9.1 checklist has already established that this
  // actor was a manager before the transition. Any other signer — even
  // another manager — is refused, so a notice cannot be detached from
  // the action it describes.
  if (notice.signed_by !== transition.signed_by) {
    throw new MalformedTransitionError(
      "removal notice signer differs from the transition signer (spec §6.5)",
    );
  }
  const { signature, ...unsigned } = notice;
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlToBytes(signature);
  } catch {
    throw new MalformedTransitionError("removal notice signature is not valid base64url");
  }
  if (signatureBytes.length !== SIGNATURE_LENGTH) {
    throw new MalformedTransitionError("removal notice signature must be 64 bytes");
  }
  const valid = await crypto.ed25519Verify(
    decodeKey(notice.signed_by, "removal notice signed_by"),
    canonicalBytes(unsigned),
    signatureBytes,
  );
  if (!valid) {
    throw new BadSignatureError("removal notice signature is invalid (spec §6.5)");
  }
}

/**
 * Wrap a signed inner body in its outer structure (spec §6.5): seal it
 * under the new epoch's secret, attach the padded envelope array, the
 * history link, and the epoch's derived `auth_pubkey`.
 *
 * Sealing happens *after* signing, so the signature and chain hash
 * cover the inner body exactly as they always have — which is why
 * `core/codec.ts` is unchanged by the outer/inner split.
 */
async function sealWire(options: {
  crypto: CryptoProvider;
  transition: EpochTransition;
  groupSecret: Uint8Array;
  envelopes: SecretEnvelope[];
  policy: GroupPolicy;
  prevSecretCiphertext?: string;
  removalNotice?: string;
}): Promise<WireTransition> {
  const { crypto, transition, groupSecret, envelopes, policy } = options;
  const wire: WireTransition = {
    group_id: transition.group_id,
    epoch: transition.epoch,
    sealed_body: await sealTransitionBody(
      crypto,
      transition.group_id,
      transition.epoch,
      groupSecret,
      canonicalBytes(transition),
      profileForPolicy(policy).sealedBodySize,
    ),
    secret_envelopes: envelopes,
    auth_pubkey: bytesToBase64Url(await deriveRelayAuthPublicKey(crypto, groupSecret)),
  };
  if (options.prevSecretCiphertext !== undefined) {
    wire.prev_secret_ciphertext = options.prevSecretCiphertext;
  }
  if (options.removalNotice !== undefined) {
    wire.removal_notice = options.removalNotice;
  }
  return wire;
}

interface BuildOptions {
  crypto: CryptoProvider;
  /** Current verified state (pre-transition). */
  state: GroupState;
  /** Acting manager's device keys. */
  signer: DeviceKeys;
  /**
   * `group_secret[state.epoch]` — sealed into the transition's
   * history chain link (spec §9.7).
   */
  currentGroupSecret: Uint8Array;
}

/** Genesis: creates the group with the signer as sole manager (spec §9.1). */
export async function buildGenesis(options: {
  crypto: CryptoProvider;
  signer: DeviceKeys;
  groupId: string;
  creatorUserId: string;
  policy: GroupPolicy;
}): Promise<BuildResult> {
  const { crypto, signer, groupId, creatorUserId } = options;
  // spec §9.1 genesis check 7: the genesis must *declare* the capacity
  // profile, since it fixes every padded size for the group's life
  // (§8.1). Defaulting at the API is fine; leaving it off the wire is
  // not, so it is materialized here rather than inferred by readers.
  const policy: GroupPolicy = {
    ...options.policy,
    capacity: options.policy.capacity ?? DEFAULT_CAPACITY,
    removal_notice: options.policy.removal_notice ?? DEFAULT_REMOVAL_NOTICE,
  };
  validatePolicyValue(policy);
  const devicePubkey = bytesToBase64Url(signer.encryption.publicKey);
  const members: MemberEntry[] = [
    { user_id: creatorUserId, device_pubkeys: [devicePubkey], is_manager: true },
  ];
  const groupSecret = crypto.randomBytes(GROUP_SECRET_LENGTH);
  // spec §6.5: pad to the profile's slot count with decoys, real
  // envelope at a CSPRNG-chosen position.
  const placed = placeEnvelopes(
    crypto,
    [await sealEnvelope(crypto, devicePubkey, 0, groupSecret)],
    0,
    profileForPolicy(policy).envelopeSlots,
  );
  const unsigned: UnsignedEpochTransition = {
    group_id: groupId,
    epoch: 0,
    prev_transition_hash: await genesisMarker(sha256Of(crypto), groupId),
    action: "create",
    members,
    envelope_slots: placed.slots,
    policy,
    signed_by: bytesToBase64Url(signer.identity.publicKey),
  };
  const transition = await signTransition(crypto, unsigned, signer.identity.privateKey);
  return {
    wire: await sealWire({ crypto, transition, groupSecret, envelopes: placed.envelopes, policy }),
    transition,
    groupSecret,
  };
}

/**
 * spec §9.2: add one member, enveloping the fresh secret to everyone
 * including the new device. Earlier secrets need no envelopes — the
 * new member recovers them via the history chain (spec §9.7,
 * {@link recoverSecretHistory}).
 */
export async function buildAddMember(
  options: BuildOptions & { newMember: MemberEntry },
): Promise<BuildResult> {
  const { state, newMember } = options;
  if (findMember(state.members, newMember.user_id) !== undefined) {
    throw new MalformedTransitionError(
      `user ${newMember.user_id} is already a member`,
    );
  }
  return buildMembershipTransition({
    ...options,
    action: "add",
    members: [...cloneMembers(state.members), { ...newMember }],
  });
}

/** spec §9.3: remove one member; the fresh secret goes to remaining devices only. */
export async function buildRemoveMember(
  options: BuildOptions & { userId: string },
): Promise<BuildResult> {
  const { state, userId } = options;
  if (findMember(state.members, userId) === undefined) {
    throw new MalformedTransitionError(`user ${userId} is not a member`);
  }
  return buildMembershipTransition({
    ...options,
    action: "remove",
    members: cloneMembers(state.members).filter((member) => member.user_id !== userId),
  });
}

/** spec §9.4. */
export async function buildPromoteMember(
  options: BuildOptions & { userId: string },
): Promise<BuildResult> {
  return buildFlagTransition(options, "promote", false);
}

/** spec §9.4 — a transfer is promote + demote, and the `min_managers`
 * invariant must hold after each individual step (spec §8). */
export async function buildDemoteMember(
  options: BuildOptions & { userId: string },
): Promise<BuildResult> {
  return buildFlagTransition(options, "demote", true);
}

/**
 * spec §9.5: link a new device to the *signing member's own* entry.
 * Needs no manager. The fresh secret is enveloped to every device
 * including the new one, so the linked device joins by the same
 * verify → open-envelope → walk-history path a new member uses.
 */
export async function buildAddDevice(
  options: BuildOptions & { newDevicePubkey: string },
): Promise<BuildResult> {
  const { state, signer, newDevicePubkey } = options;
  const signerDeviceKey = bytesToBase64Url(signer.encryption.publicKey);
  const self = state.members.find((member) =>
    member.device_pubkeys.includes(signerDeviceKey),
  );
  if (self === undefined) {
    throw new UnauthorizedSignerError(
      "acting device is not a member of this group — cannot link a device",
    );
  }
  if (memberDevices(state.members).includes(newDevicePubkey)) {
    throw new MalformedTransitionError(
      `device ${newDevicePubkey} is already present in this group`,
    );
  }
  decodeKey(newDevicePubkey, "new device pubkey");

  const members = cloneMembers(state.members).map((member) =>
    member.user_id === self.user_id
      ? { ...member, device_pubkeys: [...member.device_pubkeys, newDevicePubkey] }
      : member,
  );
  return buildMembershipTransition({ ...options, action: "add_device", members });
}

/**
 * spec §9.5: drop a device from the *signing member's own* entry.
 *
 * Because every transition rekeys, the removed device receives no
 * envelope for the new epoch and is cut off from all future data —
 * the same guarantee as member removal (§9.3), with the same
 * limitation: whatever it already decrypted, and the historical
 * secrets it already holds, remain readable to it (§13).
 *
 * A device may remove itself (decommissioning), which naturally
 * provides no cut-off from itself — it builds the new secret. Cutting
 * off a lost device requires acting from a *different* device.
 */
export async function buildRemoveDevice(
  options: BuildOptions & { devicePubkey: string },
): Promise<BuildResult> {
  const { state, signer, devicePubkey } = options;
  const signerDeviceKey = bytesToBase64Url(signer.encryption.publicKey);
  const self = state.members.find((member) =>
    member.device_pubkeys.includes(signerDeviceKey),
  );
  if (self === undefined) {
    throw new UnauthorizedSignerError(
      "acting device is not a member of this group — cannot remove a device",
    );
  }
  if (!self.device_pubkeys.includes(devicePubkey)) {
    throw new MalformedTransitionError(
      `device ${devicePubkey} is not one of ${self.user_id}'s devices — a member may only remove their own (spec §9.5)`,
    );
  }
  if (self.device_pubkeys.length === 1) {
    throw new MalformedTransitionError(
      `cannot remove ${self.user_id}'s last device — restore from backup to regain access (spec §9.6), or have a manager remove and re-add the member (spec §9.5)`,
    );
  }

  const members = cloneMembers(state.members).map((member) =>
    member.user_id === self.user_id
      ? {
          ...member,
          device_pubkeys: member.device_pubkeys.filter((key) => key !== devicePubkey),
        }
      : member,
  );
  return buildMembershipTransition({ ...options, action: "remove_device", members });
}

/** spec §8.1/§9.4. */
export async function buildSetPolicy(
  options: BuildOptions & { policy: GroupPolicy },
): Promise<BuildResult> {
  validatePolicyValue(options.policy);
  const current = options.state.policy;

  // `capacity` is immutable (spec §8.1) and every `set_policy` must
  // restate it, because the transition's policy — not the previous
  // state — is what verifiers fold. Inheriting it here means callers
  // set `min_managers` without having to know the profile exists; an
  // explicit attempt to change it is refused rather than ignored.
  if (options.policy.capacity !== undefined && options.policy.capacity !== current.capacity) {
    throw new PolicyViolationError(
      `capacity profile is immutable after genesis: cannot change ` +
        `${String(current.capacity)} to ${options.policy.capacity} (spec §8.1)`,
    );
  }
  // `removal_notice` is mutable, but omitting it must not silently
  // reset a "suppressed" group to the default — an omission means
  // "leave it alone", not "make it required".
  const merged: GroupPolicy = { min_managers: options.policy.min_managers };
  const capacity = current.capacity ?? DEFAULT_CAPACITY;
  merged.capacity = capacity;
  merged.removal_notice =
    options.policy.removal_notice ?? current.removal_notice ?? DEFAULT_REMOVAL_NOTICE;

  return buildMembershipTransition({
    ...options,
    action: "set_policy",
    members: cloneMembers(options.state.members),
    policy: merged,
  });
}

/** Attach the Ed25519 signature over the canonical signing bytes. */
export async function signTransition(
  crypto: CryptoProvider,
  unsigned: UnsignedEpochTransition,
  identityPrivateKey: Uint8Array,
): Promise<EpochTransition> {
  const signature = await crypto.ed25519Sign(
    identityPrivateKey,
    transitionSigningBytes(unsigned),
  );
  return { ...unsigned, signature: bytesToBase64Url(signature) };
}

async function buildFlagTransition(
  options: BuildOptions & { userId: string },
  action: "promote" | "demote",
  fromManager: boolean,
): Promise<BuildResult> {
  const { state, userId } = options;
  const target = findMember(state.members, userId);
  if (target === undefined) {
    throw new MalformedTransitionError(`user ${userId} is not a member`);
  }
  if (target.is_manager !== fromManager) {
    throw new MalformedTransitionError(
      `cannot ${action} ${userId}: is_manager is already ${String(target.is_manager)}`,
    );
  }
  const members = cloneMembers(state.members).map((member) =>
    member.user_id === userId ? { ...member, is_manager: !fromManager } : member,
  );
  return buildMembershipTransition({ ...options, action, members });
}

async function buildMembershipTransition(options: {
  crypto: CryptoProvider;
  state: GroupState;
  signer: DeviceKeys;
  currentGroupSecret: Uint8Array;
  action: EpochTransition["action"];
  members: MemberEntry[];
  policy?: GroupPolicy;
  /** Clock injection for deterministic tests; returns RFC 3339. */
  now?: () => string;
}): Promise<BuildResult> {
  const { crypto, state, signer, currentGroupSecret, action, members, policy } = options;

  // Build-side authorization mirror of §9.1 check 3: refuse to
  // construct what every verifier would reject anyway. Device actions
  // need membership, not managership (spec §9.5).
  const signerDeviceKey = bytesToBase64Url(signer.encryption.publicKey);
  const signerMember = state.members.find((member) =>
    member.device_pubkeys.includes(signerDeviceKey),
  );
  const needsManager = (GOVERNANCE_ACTIONS as readonly string[]).includes(action);
  if (signerMember === undefined) {
    throw new UnauthorizedSignerError(
      "acting device is not a member of the current member set",
    );
  }
  if (needsManager && !signerMember.is_manager) {
    throw new UnauthorizedSignerError(
      "acting device is not a manager in the current member set",
    );
  }
  // Build-side §8.1 invariant — holds after every individual transition.
  const effective = policy ?? state.policy;
  if (!satisfiesPolicy(members, effective)) {
    throw new PolicyViolationError(
      `transition would leave fewer than min_managers=${String(effective.min_managers)} managers`,
    );
  }

  const epoch = state.epoch + 1;
  // spec §9.1 simplification: always rekey, re-envelope to every device.
  const groupSecret = crypto.randomBytes(GROUP_SECRET_LENGTH);
  const envelopes: SecretEnvelope[] = [];
  for (const device of memberDevices(members)) {
    envelopes.push(await sealEnvelope(crypto, device, epoch, groupSecret));
  }
  // spec §6.5: decoy-pad to the profile's slots; `envelope_slots`
  // records where each device's real envelope landed, in the same
  // canonical order `memberDevices` produced.
  const placed = placeEnvelopes(crypto, envelopes, epoch, profileForPolicy(effective).envelopeSlots);

  const base = {
    group_id: state.group_id,
    epoch,
    prev_transition_hash: state.last_transition_hash,
    action,
    members,
    envelope_slots: placed.slots,
    signed_by: bytesToBase64Url(signer.identity.publicKey),
  };
  const unsigned: UnsignedEpochTransition =
    policy === undefined ? base : { ...base, policy };
  const transition = await signTransition(crypto, unsigned, signer.identity.privateKey);
  const profile = profileForPolicy(effective);
  // spec §6.5: the notice is sealed under the *previous* epoch's secret
  // so the people just removed can read it — they never receive this
  // epoch's. Padding is sealed when nothing was removed, so the blob is
  // the same size on every transition.
  const noticeBytes = await buildRemovalNotice({
    crypto,
    groupId: state.group_id,
    epoch,
    removed: removedDevices(state.members, members),
    policy: effective,
    signer,
    now: options.now?.() ?? new Date().toISOString(),
  });
  return {
    wire: await sealWire({
      crypto,
      transition,
      groupSecret,
      envelopes: placed.envelopes,
      policy: effective,
      removalNotice: await sealRemovalNotice(
        crypto,
        state.group_id,
        epoch,
        currentGroupSecret,
        noticeBytes,
        profile.removalNoticeSize,
      ),
      // spec §9.7: the previous secret rides under the new one.
      prevSecretCiphertext: await sealHistoryLink(
        crypto,
        state.group_id,
        epoch,
        groupSecret,
        currentGroupSecret,
      ),
    }),
    transition,
    groupSecret,
  };
}

/**
 * Walk the secret history chain backward (spec §9.7): given the
 * verified chain from genesis and the secret of the last transition's
 * epoch, recover every earlier `group_secret`. This is how a newly
 * added member obtains the group's full history from a single
 * envelope.
 */
export async function recoverSecretHistory(
  crypto: CryptoProvider,
  chain: readonly WireTransition[],
  latestGroupSecret: Uint8Array,
): Promise<Map<number, Uint8Array>> {
  const secrets = new Map<number, Uint8Array>();
  let secret = latestGroupSecret;
  for (let index = chain.length - 1; index >= 0; index--) {
    const transition = chain[index];
    if (transition === undefined) break;
    secrets.set(transition.epoch, secret);
    if (transition.epoch === 0) break;
    if (transition.prev_secret_ciphertext === undefined) {
      throw new MalformedTransitionError(
        `transition for epoch ${String(transition.epoch)} lacks a history link (spec §9.7)`,
      );
    }
    secret = await openHistoryLink(
      crypto,
      transition.group_id,
      transition.epoch,
      secret,
      transition.prev_secret_ciphertext,
    );
  }
  return secrets;
}
