/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Wire-shape validation for data arriving from the backend
 * (spec §9.1, §10.2).
 *
 * `verifyTransition` assumes it is handed something *shaped* like an
 * `EpochTransition`; the TypeScript annotation is a claim about JSON
 * from an untrusted party, not a guarantee. Without this guard a
 * backend returning `members: null` produces a bare `TypeError` from
 * deep inside the verifier rather than a typed rejection — which
 * would both violate the library's error contract and mean the
 * hostile-backend posture depends on the backend being well-behaved.
 *
 * This checks *shape only*. Everything that matters cryptographically
 * — signatures, hashes, authorization, policy — remains
 * `verifyTransition`'s job (spec §9.1); passing here proves nothing
 * about authenticity.
 */

import { MalformedTransitionError } from "./errors";
import { isCapacityName } from "./profiles";
import type {
  EpochTransition,
  GroupPolicy,
  MemberEntry,
  RemovalNotice,
  SecretEnvelope,
  WireTransition,
} from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== "string") {
    throw new MalformedTransitionError(`${what} must be a string`);
  }
  return value;
}

/**
 * Epochs are compared and canonicalized as integers; a float or a
 * numeric string would sail past `===` comparisons in surprising ways.
 */
function requireEpoch(value: unknown, what: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new MalformedTransitionError(`${what} must be a non-negative safe integer`);
  }
  return value;
}

function parseMember(value: unknown, index: number): MemberEntry {
  if (!isRecord(value)) {
    throw new MalformedTransitionError(`members[${String(index)}] must be an object`);
  }
  const devices = value.device_pubkeys;
  if (!Array.isArray(devices)) {
    throw new MalformedTransitionError(
      `members[${String(index)}].device_pubkeys must be an array`,
    );
  }
  if (typeof value.is_manager !== "boolean") {
    throw new MalformedTransitionError(
      `members[${String(index)}].is_manager must be a boolean`,
    );
  }
  return {
    user_id: requireString(value.user_id, `members[${String(index)}].user_id`),
    device_pubkeys: devices.map((device, i) =>
      requireString(device, `members[${String(index)}].device_pubkeys[${String(i)}]`),
    ),
    is_manager: value.is_manager,
  };
}

/**
 * An envelope is a bare base64url string since spec §6.5 — the
 * recipient field is gone, so there is no object shape left to check.
 */
function parseEnvelope(value: unknown, index: number): SecretEnvelope {
  return requireString(value, `secret_envelopes[${String(index)}]`);
}

/**
 * `envelope_slots` is a relay-supplied array of array indices, so it is
 * checked strictly here: a non-integer, a negative, or an unsafe value
 * would otherwise reach the slot arithmetic in `validateEnvelopes`.
 * Range and distinctness are checked there, against the profile.
 */
function parseEnvelopeSlots(value: unknown): number[] {
  if (!Array.isArray(value)) {
    throw new MalformedTransitionError("envelope_slots must be an array");
  }
  return value.map((slot, index) => {
    if (typeof slot !== "number" || !Number.isSafeInteger(slot) || slot < 0) {
      throw new MalformedTransitionError(
        `envelope_slots[${String(index)}] must be a non-negative safe integer`,
      );
    }
    return slot;
  });
}

/**
 * Validate that `value` has the spec §9.1 wire shape, returning a
 * normalized copy. Unknown members are dropped rather than carried
 * through, so a backend cannot smuggle extra fields into the object
 * that gets canonicalized, hashed and stored.
 */
export function parseEpochTransition(value: unknown): EpochTransition {
  if (!isRecord(value)) {
    throw new MalformedTransitionError("transition must be an object");
  }
  const members = value.members;
  if (!Array.isArray(members)) {
    throw new MalformedTransitionError("members must be an array");
  }
  const parsed: EpochTransition = {
    group_id: requireString(value.group_id, "group_id"),
    epoch: requireEpoch(value.epoch, "epoch"),
    prev_transition_hash: requireString(
      value.prev_transition_hash,
      "prev_transition_hash",
    ),
    // The action is only checked to be a string here; whether it is a
    // *known* action is decided by `validateActionSemantics`, which
    // already fails closed on anything it does not recognise.
    action: requireString(value.action, "action") as EpochTransition["action"],
    members: members.map(parseMember),
    envelope_slots: parseEnvelopeSlots(value.envelope_slots),
    signed_by: requireString(value.signed_by, "signed_by"),
    signature: requireString(value.signature, "signature"),
  };

  // Optional members: present-but-wrong is an error, absent is fine.
  // They must be omitted rather than set to undefined, since the
  // canonical encoding rejects undefined values outright (spec §6.5).
  const policy = value.policy;
  if (policy !== undefined) {
    if (!isRecord(policy)) {
      throw new MalformedTransitionError("policy must be an object");
    }
    const minManagers = policy.min_managers;
    if (typeof minManagers !== "number" || !Number.isSafeInteger(minManagers)) {
      throw new MalformedTransitionError("policy.min_managers must be an integer");
    }
    // Optional policy fields must survive parsing. `capacity` fixes
    // every padded size for the group's life (spec §8.1) and
    // `removal_notice` decides an enforced §9.1 check — dropping either
    // here would silently reset the group to a default the moment its
    // body round-tripped this parser, and the padded sizes or the
    // notice rule would then disagree with what was signed. This has
    // already gone wrong once for `capacity`.
    const built: GroupPolicy = { min_managers: minManagers };
    const capacity = policy.capacity;
    if (capacity !== undefined) {
      if (!isCapacityName(capacity)) {
        throw new MalformedTransitionError(
          `policy.capacity must be a known profile, got ${JSON.stringify(capacity)}`,
        );
      }
      built.capacity = capacity;
    }
    const removalNotice = policy.removal_notice;
    if (removalNotice !== undefined) {
      if (removalNotice !== "required" && removalNotice !== "suppressed") {
        throw new MalformedTransitionError(
          `policy.removal_notice must be "required" or "suppressed", got ${JSON.stringify(removalNotice)}`,
        );
      }
      built.removal_notice = removalNotice;
    }
    parsed.policy = built;
  }
  return parsed;
}

/**
 * Validate the shape of an outer {@link WireTransition} (spec §6.5).
 *
 * This is the boundary the relay's JSON crosses. The inner body is
 * validated separately by {@link parseEpochTransition}, after it has
 * been decrypted — a relay cannot reach inside it.
 */
export function parseWireTransition(value: unknown): WireTransition {
  if (!isRecord(value)) {
    throw new MalformedTransitionError("wire transition must be an object");
  }
  const envelopes = value.secret_envelopes;
  if (!Array.isArray(envelopes)) {
    throw new MalformedTransitionError("secret_envelopes must be an array");
  }
  const parsed: WireTransition = {
    group_id: requireString(value.group_id, "group_id"),
    epoch: requireEpoch(value.epoch, "epoch"),
    sealed_body: requireString(value.sealed_body, "sealed_body"),
    secret_envelopes: envelopes.map(parseEnvelope),
    auth_pubkey: requireString(value.auth_pubkey, "auth_pubkey"),
  };
  const link = value.prev_secret_ciphertext;
  if (link !== undefined) {
    parsed.prev_secret_ciphertext = requireString(link, "prev_secret_ciphertext");
  }
  const notice = value.removal_notice;
  if (notice !== undefined) {
    parsed.removal_notice = requireString(notice, "removal_notice");
  }
  return parsed;
}

/**
 * Validate the shape of a decrypted {@link RemovalNotice} (spec §6.5).
 *
 * The notice comes out of a blob any member could have sealed, so it is
 * shape-checked before its signature is examined — same posture as the
 * transition body itself.
 */
export function parseRemovalNotice(value: unknown): RemovalNotice {
  if (!isRecord(value)) {
    throw new MalformedTransitionError("removal notice must be an object");
  }
  const devices = value.removed_devices;
  if (!Array.isArray(devices)) {
    throw new MalformedTransitionError("removal notice removed_devices must be an array");
  }
  return {
    group_id: requireString(value.group_id, "removal notice group_id"),
    epoch: requireEpoch(value.epoch, "removal notice epoch"),
    removed_devices: devices.map((device, index) =>
      requireString(device, `removal notice removed_devices[${String(index)}]`),
    ),
    removed_at: requireString(value.removed_at, "removal notice removed_at"),
    signed_by: requireString(value.signed_by, "removal notice signed_by"),
    signature: requireString(value.signature, "removal notice signature"),
  };
}

/** Validate a batch of wire transitions, reporting which entry failed. */
export function parseWireTransitions(values: unknown): WireTransition[] {
  if (!Array.isArray(values)) {
    throw new MalformedTransitionError("expected an array of transitions");
  }
  return values.map((value, index) => {
    try {
      return parseWireTransition(value);
    } catch (error) {
      throw new MalformedTransitionError(
        `transition[${String(index)}]: ${error instanceof Error ? error.message : "invalid"}`,
      );
    }
  });
}

/** Validate a batch, reporting which entry failed. */
export function parseEpochTransitions(values: unknown): EpochTransition[] {
  if (!Array.isArray(values)) {
    throw new MalformedTransitionError("expected an array of transitions");
  }
  return values.map((value, index) => {
    try {
      return parseEpochTransition(value);
    } catch (error) {
      throw new MalformedTransitionError(
        `transition[${String(index)}]: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });
}
