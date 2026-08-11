/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * MockTransport: an in-memory reference
 * backend at full spec §10 fidelity. It is the executable
 * specification of what a real backend MUST do, and the target every
 * host-team `Transport` adapter is tested against:
 *
 * - `(group_id, epoch)` uniqueness: the first submission for an epoch
 *   wins, later ones get `"conflict"` (spec §10.4).
 * - Freshness gate: record writes tagged with an epoch below the
 *   group's plaintext `current_epoch` counter are rejected with
 *   `"stale_epoch"` (spec §9.3) — a plain integer comparison, no
 *   cryptographic capability required.
 * - Everything sensitive stays opaque: envelopes, history links,
 *   record ciphertexts, and backup blobs are stored and served as-is
 *   (spec §10.2).
 *
 * The backend cannot compute chain hashes without hashing support; a
 * `computeTransitionHash` hook may be injected so `getGroupState`
 * snapshots carry `last_transition_hash` (optional backend behavior —
 * clients never trust the snapshot anyway, spec §5.7).
 */

import { TransportError } from "../../core/errors";
import {
  isRelayWriteOp,
  relayRequestBytes,
  type RelayOp,
  type RelayRequestAuth,
} from "../../core/relay-auth";
import type {
  EncryptedBackupBlob,
  EncryptedRecord,
  WireTransition,
  GroupHandle,
  GroupStateSnapshot,
  PutResult,
  RecordPage,
  SubmitResult,
} from "../../core/types";
import type { Transport } from "../../ports/transport";

interface MockGroup {
  transitions: WireTransition[];
  records: Map<string, EncryptedRecord>;
  lastTransitionHash: string;
  listeners: Set<(transition: WireTransition) => void>;
  /**
   * Every `auth_pubkey` this group has ever published, by epoch
   * (spec §10.1). Retained rather than replaced: reads accept a
   * signature under any of them, so a client at `e-1` can still fetch
   * the transition that lets it catch up. Writes take only the newest.
   */
  authKeys: Map<number, string>;
}

export interface MockTransportOptions {
  /** Optional hash hook so snapshots can carry `last_transition_hash`. */
  computeTransitionHash?: (transition: WireTransition) => Promise<string>;
  /**
   * Enforce request signatures (spec §10.1). Off by default so the
   * suites that predate relay auth keep exercising what they are about;
   * the relay-auth tests turn it on, and a real relay MUST behave as
   * though it were always on.
   */
  requireAuth?: boolean;
  /**
   * Stands in for the relay's own account layer (spec §10.1
   * bootstrap). A client that holds no epoch key yet — a new member's
   * first fetch, a device restored from backup — cannot sign, because
   * signing needs the very secret the fetch would deliver.
   *
   * A **real relay MUST NOT** simply accept unauthenticated reads: it
   * has to decide, from an invite token or an authenticated account,
   * that this caller may bootstrap. The mock has no account layer to
   * model, so it takes a flag and says so loudly rather than pretending
   * the problem does not exist. A signature that *is* present is still
   * verified strictly.
   */
  allowUnauthenticatedReads?: boolean;
  /** Injected verifier, so the mock stays dependency-free. */
  verifyAuth?: (
    authPublicKey: string,
    requestBytes: Uint8Array,
    signature: string,
  ) => Promise<boolean>;
}

export class MockTransport implements Transport {
  private readonly groups = new Map<string, MockGroup>();
  private readonly backups = new Map<string, EncryptedBackupBlob>();

  constructor(private readonly options: MockTransportOptions = {}) {}

  /**
   * spec §10.1: verify a request signature against the keys this group
   * has published.
   *
   * Reads accept **any** published key; writes require the newest.
   * Getting this backwards deadlocks the protocol — a member one epoch
   * behind holds only the previous key, and cannot fetch what would
   * bring it current.
   */
  private async authorize(
    group: MockGroup,
    groupId: string,
    op: RelayOp,
    auth: RelayRequestAuth | undefined,
  ): Promise<void> {
    if (this.options.requireAuth !== true) return;
    const verify = this.options.verifyAuth;
    if (verify === undefined) {
      throw new TransportError("requireAuth needs a verifyAuth hook");
    }
    if (auth === undefined) {
      if (!isRelayWriteOp(op) && this.options.allowUnauthenticatedReads === true) {
        return; // bootstrap, per the relay's account layer (spec §10.1)
      }
      throw new TransportError(`unauthorized: ${op} requires a request signature`);
    }
    const current = group.transitions[group.transitions.length - 1]?.epoch ?? 0;
    if (isRelayWriteOp(op) && auth.epoch !== current) {
      throw new TransportError(
        `unauthorized: ${op} requires the current epoch's key ` +
          `(got ${String(auth.epoch)}, current ${String(current)})`,
      );
    }
    const key = group.authKeys.get(auth.epoch);
    if (key === undefined) {
      throw new TransportError(
        `unauthorized: no auth key published for epoch ${String(auth.epoch)}`,
      );
    }
    if (!(await verify(key, relayRequestBytes(groupId, op, auth.epoch), auth.signature))) {
      throw new TransportError(`unauthorized: bad request signature for ${op}`);
    }
  }

  async createGroup(genesis: WireTransition): Promise<GroupHandle> {
    if (this.groups.has(genesis.group_id)) {
      throw new TransportError(`group ${genesis.group_id} already exists`);
    }
    // The relay cannot see `action` any more (spec §6.5) — the body is
    // sealed. Epoch 0 is the whole of what it can check, and that is
    // sufficient: whether the body really is a well-formed genesis is
    // decided by every client through §9.1, never here.
    if (genesis.epoch !== 0) {
      throw new TransportError("createGroup requires a genesis transition at epoch 0");
    }
    const group: MockGroup = {
      transitions: [structuredClone(genesis)],
      records: new Map(),
      lastTransitionHash: await this.hashOf(genesis),
      listeners: new Set(),
      authKeys: new Map([[genesis.epoch, genesis.auth_pubkey]]),
    };
    this.groups.set(genesis.group_id, group);
    return { group_id: genesis.group_id };
  }

  async submitTransition(
    groupId: string,
    transition: WireTransition,
    auth?: RelayRequestAuth,
  ): Promise<SubmitResult> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "submitTransition", auth);
    if (transition.group_id !== groupId) {
      throw new TransportError("transition group_id does not match the target group");
    }
    const current = currentEpoch(group);
    if (transition.epoch <= current) {
      // spec §10.4: atomic uniqueness on (group_id, epoch) — the
      // first submission won; this one loses.
      return { accepted: false, reason: "conflict" };
    }
    if (transition.epoch !== current + 1) {
      throw new TransportError(
        `epoch gap: group is at ${String(current)}, got ${String(transition.epoch)}`,
      );
    }
    group.transitions.push(structuredClone(transition));
    // Published, not replaced: spec §10.1 requires old keys to keep
    // working for reads.
    group.authKeys.set(transition.epoch, transition.auth_pubkey);
    group.lastTransitionHash = await this.hashOf(transition);
    for (const listener of group.listeners) {
      listener(structuredClone(transition));
    }
    return { accepted: true };
  }

  /**
   * spec §10.3. A real backend pushes over WebSocket/SSE; conforming
   * clients treat the delivered transition as a *hint* and re-fetch
   * from their own verified head, so this only
   * needs to fire reliably, not to guarantee ordering or delivery.
   */
  subscribeToTransitions(
    groupId: string,
    onTransition: (transition: WireTransition) => void,
  ): () => void {
    const group = this.require(groupId);
    group.listeners.add(onTransition);
    return () => {
      group.listeners.delete(onTransition);
    };
  }

  async getTransitions(
    groupId: string,
    sinceEpoch?: number,
    auth?: RelayRequestAuth,
  ): Promise<WireTransition[]> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "getTransitions", auth);
    const matching = group.transitions.filter(
      (transition) => sinceEpoch === undefined || transition.epoch > sinceEpoch,
    );
    return Promise.resolve(structuredClone(matching));
  }

  async getGroupState(
    groupId: string,
    auth?: RelayRequestAuth,
  ): Promise<GroupStateSnapshot> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "getGroupState", auth);
    const last = group.transitions[group.transitions.length - 1];
    if (last === undefined) {
      throw new TransportError(`group ${groupId} has no transitions`);
    }
    return Promise.resolve(
      structuredClone({
        group_id: groupId,
        current_epoch: last.epoch,
      }),
    );
  }

  async putRecord(
    groupId: string,
    record: EncryptedRecord,
    auth?: RelayRequestAuth,
  ): Promise<PutResult> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "putRecord", auth);
    const current = currentEpoch(group);
    if (record.epoch < current) {
      // spec §9.3 freshness gate: plain integer comparison.
      return Promise.resolve({ accepted: false, reason: "stale_epoch" });
    }
    if (record.epoch > current) {
      throw new TransportError(
        `record epoch ${String(record.epoch)} is ahead of the group (${String(current)})`,
      );
    }
    group.records.set(record.record_id, structuredClone(record));
    return Promise.resolve({ accepted: true });
  }

  async getRecord(
    groupId: string,
    recordId: string,
    auth?: RelayRequestAuth,
  ): Promise<EncryptedRecord> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "getRecord", auth);
    const record = group.records.get(recordId);
    if (record === undefined) {
      throw new TransportError(`record ${recordId} not found in group ${groupId}`);
    }
    return Promise.resolve(structuredClone(record));
  }

  // Single page — the mock never paginates, so the cursor is unused.
  async listRecords(
    groupId: string,
    cursor?: string,
    auth?: RelayRequestAuth,
  ): Promise<RecordPage> {
    const group = this.require(groupId);
    await this.authorize(group, groupId, "listRecords", auth);
    void cursor;
    return { records: structuredClone([...group.records.values()]) };
  }

  putBackupBlob(handle: string, blob: EncryptedBackupBlob): Promise<void> {
    this.backups.set(handle, structuredClone(blob));
    return Promise.resolve();
  }

  async getBackupBlob(handle: string): Promise<EncryptedBackupBlob> {
    const blob = this.backups.get(handle);
    if (blob === undefined) {
      // Deliberately says nothing about *why*. A wrong credential and a
      // user with no backup derive different handles and must be
      // indistinguishable here, or the relay becomes a credential
      // guessing oracle (spec §6.5, §10.5).
      throw new TransportError("no backup blob stored under that handle");
    }
    return Promise.resolve(structuredClone(blob));
  }

  private require(groupId: string): MockGroup {
    const group = this.groups.get(groupId);
    if (group === undefined) {
      throw new TransportError(`unknown group: ${groupId}`);
    }
    return group;
  }

  private async hashOf(transition: WireTransition): Promise<string> {
    return this.options.computeTransitionHash === undefined
      ? ""
      : this.options.computeTransitionHash(transition);
  }
}

function currentEpoch(group: MockGroup): number {
  return group.transitions[group.transitions.length - 1]?.epoch ?? -1;
}
