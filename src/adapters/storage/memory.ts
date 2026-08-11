/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * In-memory `StorageAdapter`: reference
 * implementation of the port semantics, used by tests and ephemeral
 * environments. Values are deep-copied on the way in and out so
 * callers can never alias store internals.
 */

import { StorageError } from "../../core/errors";
import type { GroupState } from "../../core/group-state";
import type { EncryptedRecord, WireTransition } from "../../core/types";
import type { StorageAdapter, StoredIdentity } from "../../ports/storage";

export class MemoryStore implements StorageAdapter {
  private identity: StoredIdentity | undefined;
  private readonly transitions = new Map<string, Map<number, WireTransition>>();
  private readonly groupStates = new Map<string, GroupState>();
  private readonly secrets = new Map<string, Map<number, Uint8Array>>();
  private readonly keyUsage = new Map<string, number>();
  private readonly cachedRecords = new Map<string, Map<string, EncryptedRecord>>();

  getIdentity(): Promise<StoredIdentity | undefined> {
    return Promise.resolve(
      this.identity === undefined ? undefined : structuredClone(this.identity),
    );
  }

  putIdentity(identity: StoredIdentity): Promise<void> {
    this.identity = structuredClone(identity);
    return Promise.resolve();
  }

  appendTransition(transition: WireTransition): Promise<void> {
    let chain = this.transitions.get(transition.group_id);
    if (chain === undefined) {
      chain = new Map();
      this.transitions.set(transition.group_id, chain);
    }
    if (chain.has(transition.epoch)) {
      return Promise.reject(
        new StorageError(
          `transition for ${transition.group_id} epoch ${String(transition.epoch)} already stored — history is append-only`,
        ),
      );
    }
    chain.set(transition.epoch, structuredClone(transition));
    return Promise.resolve();
  }

  getTransitions(groupId: string): Promise<WireTransition[]> {
    const chain = this.transitions.get(groupId);
    if (chain === undefined) return Promise.resolve([]);
    const ordered = [...chain.entries()]
      .sort(([a], [b]) => a - b)
      .map(([, transition]) => structuredClone(transition));
    return Promise.resolve(ordered);
  }

  listGroupIds(): Promise<string[]> {
    return Promise.resolve([...this.transitions.keys()]);
  }

  getGroupState(groupId: string): Promise<GroupState | undefined> {
    const state = this.groupStates.get(groupId);
    return Promise.resolve(state === undefined ? undefined : structuredClone(state));
  }

  putGroupState(state: GroupState): Promise<void> {
    this.groupStates.set(state.group_id, structuredClone(state));
    return Promise.resolve();
  }

  putGroupSecret(groupId: string, epoch: number, secret: Uint8Array): Promise<void> {
    let perGroup = this.secrets.get(groupId);
    if (perGroup === undefined) {
      perGroup = new Map();
      this.secrets.set(groupId, perGroup);
    }
    const existing = perGroup.get(epoch);
    if (existing !== undefined) {
      return sameBytes(existing, secret)
        ? Promise.resolve()
        : Promise.reject(
            new StorageError(
              `conflicting group_secret for ${groupId} epoch ${String(epoch)}`,
            ),
          );
    }
    perGroup.set(epoch, structuredClone(secret));
    return Promise.resolve();
  }

  getGroupSecret(groupId: string, epoch: number): Promise<Uint8Array | undefined> {
    const secret = this.secrets.get(groupId)?.get(epoch);
    return Promise.resolve(secret === undefined ? undefined : structuredClone(secret));
  }

  getGroupSecrets(groupId: string): Promise<Map<number, Uint8Array>> {
    const perGroup = this.secrets.get(groupId) ?? new Map<number, Uint8Array>();
    return Promise.resolve(
      new Map([...perGroup.entries()].map(([epoch, s]) => [epoch, structuredClone(s)])),
    );
  }

  incrementKeyUsage(groupId: string, epoch: number): Promise<number> {
    const key = `${groupId}|${String(epoch)}`;
    const next = (this.keyUsage.get(key) ?? 0) + 1;
    this.keyUsage.set(key, next);
    return Promise.resolve(next);
  }

  putCachedRecord(groupId: string, record: EncryptedRecord): Promise<void> {
    let perGroup = this.cachedRecords.get(groupId);
    if (perGroup === undefined) {
      perGroup = new Map();
      this.cachedRecords.set(groupId, perGroup);
    }
    perGroup.set(record.record_id, structuredClone(record));
    return Promise.resolve();
  }

  getCachedRecord(
    groupId: string,
    recordId: string,
  ): Promise<EncryptedRecord | undefined> {
    const record = this.cachedRecords.get(groupId)?.get(recordId);
    return Promise.resolve(record === undefined ? undefined : structuredClone(record));
  }

  listCachedRecords(groupId: string): Promise<EncryptedRecord[]> {
    const perGroup = this.cachedRecords.get(groupId);
    return Promise.resolve(
      perGroup === undefined ? [] : structuredClone([...perGroup.values()]),
    );
  }

  deleteCachedRecord(groupId: string, recordId: string): Promise<void> {
    this.cachedRecords.get(groupId)?.delete(recordId);
    return Promise.resolve();
  }

  clear(): Promise<void> {
    this.identity = undefined;
    this.transitions.clear();
    this.groupStates.clear();
    this.secrets.clear();
    this.keyUsage.clear();
    this.cachedRecords.clear();
    return Promise.resolve();
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
