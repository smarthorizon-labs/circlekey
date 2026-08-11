/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * GroupVault Protocol wire types (spec §9.1, §10.3).
 *
 * Single source of truth for protocol data shapes — no other module
 * redeclares them. Types only; no logic.
 *
 * Encoding convention: every binary value —
 * public keys, hashes, ciphertexts, nonces, signatures, salts — is a
 * base64url string without padding.
 */

import type { CapacityName } from "./profiles";

/**
 * Versioned cryptographic suite identifier (spec §6.3), carried by
 * every envelope, record ciphertext, and backup blob. Suite `gv1` =
 * X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM (spec §6).
 */
export const SUITE_V1 = "gv1";

/**
 * Every suite this build can read and write, newest last.
 *
 * This — not the package version — is the machine-checkable statement
 * of which protocol versions CircleKey speaks, because it travels
 * inside each artifact rather than describing the library as a whole.
 * Spec §6.3 requires a new suite to be introduced *alongside* the ones
 * already in use, without breaking existing data, so one build is
 * expected to support several at once and this list is expected to
 * grow rather than be replaced.
 */
export const SUPPORTED_SUITES = [SUITE_V1] as const;

/** spec §8.1 */
export interface GroupPolicy {
  /** Minimum manager count the group must maintain (spec §5.6). */
  min_managers: number;
  /**
   * Padding profile, fixed at genesis and immutable thereafter
   * (spec §6.5, §8.1) — `set_policy` MUST NOT change it.
   *
   * Required at genesis (spec §9.1 genesis check 7); `buildGenesis`
   * materializes it, so a policy that omits it reads as `lite` only
   * when constructed by hand.
   */
  capacity?: CapacityName;
  /**
   * Whether a removed member is told (spec §8.1, §9.3).
   *
   * Enforced by the §9.1 checklist in **both** directions: under
   * `"required"` a transition that removes devices without a matching
   * notice is rejected; under `"suppressed"` a non-empty notice is
   * rejected. That two-way enforceability is why it belongs in the
   * policy rather than being a client convention.
   *
   * Unlike `capacity` it MAY change via `set_policy` — the change sits
   * in the sealed body, so every member including a future subject sees
   * it while still a member.
   */
  removal_notice?: RemovalNoticePolicy;
}

/** spec §8.1. Default `"required"`: silence should be deliberate. */
export type RemovalNoticePolicy = "required" | "suppressed";

/**
 * The signed contents of a removal notice (spec §6.5).
 *
 * Sealed under `group_secret[epoch-1]` so it reaches every remaining
 * member *and* the members just removed — the latter never receive the
 * current epoch's secret, which is the entire point.
 *
 * The signature is not optional: everyone holds `group_secret[epoch-1]`,
 * so without it any peer could forge a notice telling another member
 * they had been removed, and applications act on these.
 */
export interface RemovalNotice {
  group_id: string;
  /** The epoch that performs the removal. */
  epoch: number;
  /** X25519 device keys removed by this transition, ascending. */
  removed_devices: string[];
  /**
   * RFC 3339, supplied by the acting manager's client. A claim, not a
   * fact — nothing verifies it against real time, and the
   * authoritative ordering is the epoch number (spec §6.5).
   */
  removed_at: string;
  /** MUST equal the enclosing transition's `signed_by` (spec §9.1). */
  signed_by: string;
  signature: string;
}

/** spec §9.1 */
export type TransitionAction =
  | "create"
  | "add"
  | "remove"
  | "promote"
  | "demote"
  | "set_policy"
  /** Self-scoped device-list changes (spec §9.5) — not governance. */
  | "add_device"
  | "remove_device";

/**
 * Actions that only a manager may sign (spec §9.1 check 3). Device
 * actions are excluded: they are self-scoped and need no manager.
 */
export const GOVERNANCE_ACTIONS = [
  "add",
  "remove",
  "promote",
  "demote",
  "set_policy",
] as const satisfies readonly TransitionAction[];

/** One member entry inside a transition's member set (spec §9.1). */
export interface MemberEntry {
  user_id: string;
  /** X25519 public keys, one per device. */
  device_pubkeys: string[];
  is_manager: boolean;
}

/**
 * A sealed `group_secret`, opaque to the backend (spec §10.2).
 *
 * Deliberately a bare base64url string with no recipient field: an
 * addressed envelope disclosed the group's exact device roster, the
 * single most linkable value in the protocol (spec §6.5). Recipients
 * find their own by trial decryption; `EpochTransition.envelope_slots`
 * carries the mapping that verification needs.
 */
export type SecretEnvelope = string;

/**
 * spec §9.1 — the **inner** transition body, sealed under
 * `group_secret[epoch]` on the wire (spec §6.5). This is
 * the structure that is signed and hashed; the signing bytes and chain
 * hash rules of §6.5 operate on it and nothing else. The relay never
 * sees any of it.
 *
 * `secret_envelopes` and `prev_secret_ciphertext` deliberately live on
 * {@link WireTransition}, not here: envelopes cannot ride inside the
 * body they unlock (a joining device needs them *before* it can open
 * anything), and the history link must be walkable backward before the
 * older bodies it unlocks are readable.
 */
export interface EpochTransition {
  group_id: string;
  /** 0 for genesis; strictly `current + 1` afterward (spec §5.4). */
  epoch: number;
  /** Deterministic genesis marker (`hash(group_id)`) for epoch 0. */
  prev_transition_hash: string;
  action: TransitionAction;
  members: MemberEntry[];
  /**
   * Slot of each device's envelope in the outer array, parallel to the
   * canonical device list — members in order, each member's
   * `device_pubkeys` in order (spec §6.5, §9.1 check 9).
   *
   * This is what verification uses instead of the recipient field that
   * addressed envelopes carried. Without it, "every member device got
   * exactly one envelope, and no non-member got any" is unprovable: a
   * leaked envelope is byte-identical to a decoy. It rides in the
   * signed, sealed body so the relay can neither read nor forge it.
   */
  envelope_slots: number[];
  /** Present for `create` and `set_policy`. */
  policy?: GroupPolicy;
  /** Ed25519 identity pubkey of the acting manager. */
  signed_by: string;
  /** Ed25519 signature over the transition. */
  signature: string;
}

/**
 * spec §6.5/§9.1 — what the relay stores and routes.
 * Everything here is either opaque or demonstrably needed for routing,
 * ordering, or request authorization (spec §5.8 rule 1).
 */
export interface WireTransition {
  /** Opaque random identifier (spec §6.5). */
  group_id: string;
  /** Plaintext for the uniqueness constraint and freshness gate. */
  epoch: number;
  /**
   * AES-256-GCM of `JCS(inner)`, padded to the capacity profile's
   * fixed size, under HKDF(group_secret[epoch], "transition-body")
   * with AAD `group_id || epoch` (spec §6.5).
   */
  sealed_body: string;
  /**
   * Exactly the profile's slot count: real envelopes at CSPRNG-chosen
   * positions, the rest indistinguishable decoys (spec §6.5).
   */
  secret_envelopes: SecretEnvelope[];
  /**
   * Secret history chain link (spec §9.7): `group_secret[epoch-1]`
   * under a key derived from `group_secret[epoch]`. REQUIRED for
   * epoch >= 1, absent for genesis. Outer by necessity — catch-up
   * walks it backward to obtain the very secrets that open the bodies.
   */
  prev_secret_ciphertext?: string;
  /**
   * Fixed-size blob sealed under `group_secret[epoch-1]` (spec §6.5),
   * carrying a {@link RemovalNotice} or padding. Present on every
   * transition at epoch >= 1 and absent for genesis; identically sized
   * either way, so the relay can read neither the fact of a removal nor
   * the group's policy.
   */
  removal_notice?: string;
  /**
   * Ed25519 public key derived from `group_secret[epoch]`
   * (spec §6.5, §10.1): the relay verifies request signatures against
   * it, learning only "a current member is calling".
   */
  auth_pubkey: string;
}

// --- Backend contract shapes (spec §10.3) ---

export interface GroupHandle {
  group_id: string;
}

/**
 * Routing hint only (spec §5.7, §10.3).
 *
 * `members` and `policy` are deliberately absent:
 * they are sealed in the transition body, and §5.7 forbade a client
 * trusting them anyway — so transmitting them only ever served the
 * relay. `last_transition_hash` is gone for the same reason: the chain
 * hash now chains inner bodies, which the relay cannot compute.
 */
export interface GroupStateSnapshot {
  group_id: string;
  current_epoch: number;
}

export interface EncryptedRecord {
  record_id: string;
  /** Epoch under which this record is encrypted. */
  epoch: number;
  ciphertext: string;
  nonce: string;
  /** Crypto agility identifier (spec §6.3). */
  suite: string;
}

export interface RecordPage {
  records: EncryptedRecord[];
  next_cursor?: string;
}

// Device certificates intentionally do not exist (spec §9.5, §10.3):
// a device's membership is established by the epoch chain itself,
// which every client verifies, not by a certificate only its holder
// can produce.

/** spec §9.6, §10.3. KDF params travel with the blob (spec §6.2). */
export interface EncryptedBackupBlob {
  ciphertext: string;
  salt: string;
  kdf: "argon2id" | "pbkdf2-sha256";
  kdf_params: {
    memory_kib?: number;
    iterations: number;
    parallelism?: number;
  };
  suite: string;
}

export type SubmitResult =
  | { accepted: true }
  | {
      accepted: false;
      reason: "stale_epoch" | "invalid_signature" | "policy_violation" | "conflict";
    };

export type PutResult = { accepted: true } | { accepted: false; reason: "stale_epoch" };

export type Unsubscribe = () => void;
