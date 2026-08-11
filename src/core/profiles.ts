/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Capacity profiles (spec §6.5, §8.1).
 *
 * A group commits at genesis to a profile, which fixes every padded
 * size on the wire: how many envelope slots each transition carries and
 * how large its sealed body is. Padding to these constants is what makes
 * a two-member group indistinguishable in shape from a full one
 * (spec §5.8 rule 3).
 *
 * The profile is deliberately immutable for the life of a group
 * (spec §8.1): changing it would alter every padded size — breaking
 * verification of the existing history — and would signal to the relay
 * that the group crossed a size threshold, which is the exact fact the
 * padding exists to hide.
 *
 * Envelope slots bound total *devices*, not members: 45 slots serve 15
 * members averaging three devices each.
 */

import { MalformedTransitionError } from "./errors";
// Type-only, so the mutual reference with types.ts erases at compile
// time and creates no runtime cycle.
import type { GroupPolicy } from "./types";

export interface CapacityProfile {
  /** Maximum members the profile admits (spec §5.5 caps `lite` at 15). */
  readonly maxMembers: number;
  /** Envelope array length, real + decoy, on every transition. */
  readonly envelopeSlots: number;
  /** Padded plaintext size of the sealed transition body, in bytes. */
  readonly sealedBodySize: number;
  /**
   * Padded plaintext size of the removal notice (spec §6.5). Present
   * and identically sized on every transition, so the relay cannot tell
   * a removal from any other epoch, nor read the group's
   * `removal_notice` policy.
   */
  readonly removalNoticeSize: number;
}

export const CAPACITY_PROFILES = {
  lite: { maxMembers: 15, envelopeSlots: 45, sealedBodySize: 8192, removalNoticeSize: 2048 },
  x: { maxMembers: 30, envelopeSlots: 90, sealedBodySize: 16384, removalNoticeSize: 4096 },
} as const satisfies Record<string, CapacityProfile>;

export type CapacityName = keyof typeof CAPACITY_PROFILES;

/**
 * Applied when a policy omits `capacity`.
 *
 * The field is required at genesis (spec §9.1 genesis check 7); a policy
 * constructed by hand without it reads as `lite`
 * so the existing suite keeps its meaning.
 */
export const DEFAULT_CAPACITY: CapacityName = "lite";

export function isCapacityName(value: unknown): value is CapacityName {
  return value === "lite" || value === "x";
}

/**
 * Resolve a profile by name, rejecting anything unrecognized rather
 * than falling back — an unknown capacity arriving from the wire means
 * a newer peer or a tampered policy, and guessing a profile would
 * produce padded sizes that silently fail to verify.
 */
export function profileFor(capacity: CapacityName | undefined): CapacityProfile {
  if (capacity === undefined) return CAPACITY_PROFILES[DEFAULT_CAPACITY];
  if (!isCapacityName(capacity)) {
    throw new MalformedTransitionError(
      `unknown capacity profile: ${JSON.stringify(capacity)}`,
    );
  }
  return CAPACITY_PROFILES[capacity];
}

/** Convenience for the common case of reading it off a group policy. */
export function profileForPolicy(policy: GroupPolicy): CapacityProfile {
  return profileFor(policy.capacity);
}
