/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Startup state reload.
 *
 * The `transitions` store is the on-device source of truth; the
 * `groups` store is only a cache of the chain fold. On startup every
 * stored chain is re-verified from genesis through the full §9.1
 * checklist — a corrupted or tampered local history fails loudly with
 * a `TransitionRejectedError` instead of being trusted — and the
 * cache is repaired whenever it disagrees with the replay.
 */

import { replayWireChain } from "../core/epoch-chain";
import { StorageError } from "../core/errors";
import type { GroupState } from "../core/group-state";
import type { WireTransition } from "../core/types";
import type { CryptoProvider } from "../ports/crypto-provider";
import type { StorageAdapter } from "../ports/storage";

/**
 * Re-verify every stored chain and return the verified states,
 * repairing the `groups` cache where it disagrees.
 */
export async function reloadVerifiedGroups(
  crypto: CryptoProvider,
  storage: StorageAdapter,
): Promise<Map<string, GroupState>> {
  const states = new Map<string, GroupState>();
  for (const groupId of await storage.listGroupIds()) {
    const transitions = await storage.getTransitions(groupId);
    // Sealed bodies (spec §6.5) cannot be opened without their epoch's
    // secret, so replay needs the secrets this device persisted as it
    // synced. They are always present for the whole stored chain:
    // `GroupManager` only persists a transition it could open and
    // verify, so a device that lost access simply has a shorter chain
    // rather than an unopenable tail.
    const secrets = new Map<number, Uint8Array>();
    for (const transition of transitions) {
      const secret = await storage.getGroupSecret(groupId, transition.epoch);
      if (secret !== undefined) secrets.set(transition.epoch, secret);
    }
    const { state } = await replayWireChain(crypto, transitions, secrets);
    const cached = await storage.getGroupState(groupId);
    if (
      cached?.epoch !== state.epoch ||
      cached.last_transition_hash !== state.last_transition_hash
    ) {
      await storage.putGroupState(state);
    }
    states.set(groupId, state);
  }
  return states;
}

/**
 * Persist one *already verified* transition: append to the chain
 * history (append-only), update the state cache, and store the
 * epoch's secret. `state` must be the output of `verifyTransition`
 * for this exact transition.
 */
export async function persistVerifiedTransition(
  storage: StorageAdapter,
  wire: WireTransition,
  state: GroupState,
  groupSecret: Uint8Array,
): Promise<void> {
  if (state.group_id !== wire.group_id || state.epoch !== wire.epoch) {
    throw new StorageError(
      "state does not correspond to the transition being persisted",
    );
  }
  await storage.appendTransition(wire); // source of truth first
  await storage.putGroupState(state);
  await storage.putGroupSecret(state.group_id, state.epoch, groupSecret);
}
