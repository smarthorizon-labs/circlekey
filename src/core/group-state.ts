/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Verified local group state and governance invariants
 * (spec §5.6/§8.1).
 *
 * `GroupState` is only ever produced by `verifyTransition`
 * (core/epoch-chain.ts) folding the signed chain — never seeded from
 * a backend snapshot (spec §5.7). Pure data + pure helpers.
 */

import type { GroupPolicy, MemberEntry } from "./types";

export interface GroupState {
  group_id: string;
  epoch: number;
  members: MemberEntry[];
  policy: GroupPolicy;
  /** Chain hash of the transition that produced this state. */
  last_transition_hash: string;
}

export function managerCount(members: readonly MemberEntry[]): number {
  let count = 0;
  for (const member of members) {
    if (member.is_manager) count++;
  }
  return count;
}

export function findMember(
  members: readonly MemberEntry[],
  userId: string,
): MemberEntry | undefined {
  return members.find((member) => member.user_id === userId);
}

/** Every device pubkey across the member set, in member order. */
export function memberDevices(members: readonly MemberEntry[]): string[] {
  return members.flatMap((member) => member.device_pubkeys);
}

/**
 * spec §5.6/§8.1 hard invariant: manager count never below
 * `min_managers`, checked after every individual transition.
 */
export function satisfiesPolicy(
  members: readonly MemberEntry[],
  policy: GroupPolicy,
): boolean {
  return managerCount(members) >= policy.min_managers;
}

/** Deep copy so verified state never aliases untrusted input. */
export function cloneMembers(members: readonly MemberEntry[]): MemberEntry[] {
  return members.map((member) => ({
    user_id: member.user_id,
    device_pubkeys: [...member.device_pubkeys],
    is_manager: member.is_manager,
  }));
}
