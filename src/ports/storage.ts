/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Storage port: typed persistence over the
 * local object stores — `identity`, `groups`, `transitions`,
 * `secrets`, `key_usage`, `records_meta`.
 *
 * Semantics every adapter must honor:
 * - `transitions` is the on-device source of truth and is
 *   append-only: storing a second transition for an existing
 *   `(group_id, epoch)` throws `StorageError` — verified history is
 *   never silently replaced.
 * - `groups` is a rebuildable cache of the chain fold; on integrity
 *   doubt it is recomputed from `transitions` (see
 *   `managers/startup.ts`).
 * - Group secrets are write-once per epoch: re-putting the same value
 *   is a no-op, a different value throws `StorageError`.
 * - Counter updates are atomic read-modify-writes, even across
 *   browser tabs sharing one database.
 * - Adapters return defensive copies — mutating a returned object
 *   never mutates the store.
 */

import type { GroupState } from "../core/group-state";
import type { EncryptedRecord, WireTransition } from "../core/types";

export interface KeyUsageStore {
  /**
   * Atomically increment the encryption-operation counter for
   * `(groupId, epoch)` and return the incremented value.
   *
   * MUST be an atomic read-modify-write even across browser tabs
   * sharing one database — the counter is
   * security-relevant: callers refuse to encrypt once the returned
   * count exceeds the configured bound (spec §6.1), and a racing
   * duplicate count could let nonce usage slip past it.
   */
  incrementKeyUsage(groupId: string, epoch: number): Promise<number>;
}

/** The `identity` store record. */
export interface StoredIdentity {
  userId: string;
  /** Ed25519 device identity private key; X25519 keys derive from it. */
  identityPrivateKey: Uint8Array;
  /** spec §9.6: group operations stay blocked until this is true. */
  backupEnrolled: boolean;
}

export interface StorageAdapter extends KeyUsageStore {
  // --- identity ---
  getIdentity(): Promise<StoredIdentity | undefined>;
  putIdentity(identity: StoredIdentity): Promise<void>;

  // --- transitions: verified, append-only chain history ---
  /** Throws `StorageError` if `(group_id, epoch)` already exists. */
  appendTransition(transition: WireTransition): Promise<void>;
  /** Full stored chain for the group, ordered by epoch ascending. */
  getTransitions(groupId: string): Promise<WireTransition[]>;
  /** Distinct group ids present in the transitions store. */
  listGroupIds(): Promise<string[]>;

  // --- groups: derived-state cache ---
  getGroupState(groupId: string): Promise<GroupState | undefined>;
  putGroupState(state: GroupState): Promise<void>;

  // --- secrets: decrypted historical group_secrets ---
  /** Write-once per epoch: same value is a no-op, different value throws. */
  putGroupSecret(groupId: string, epoch: number, secret: Uint8Array): Promise<void>;
  getGroupSecret(groupId: string, epoch: number): Promise<Uint8Array | undefined>;
  /** All cached secrets for a group, keyed by epoch. */
  getGroupSecrets(groupId: string): Promise<Map<number, Uint8Array>>;

  // --- records_meta: offline cache of encrypted records ---
  /**
   * Cache an encrypted record for offline reads.
   *
   * Only ciphertext is ever cached — the stored value is exactly the
   * `EncryptedRecord` the backend holds, so this store adds no
   * plaintext at rest. Last write wins: a newer copy of a record
   * replaces the older one.
   */
  putCachedRecord(groupId: string, record: EncryptedRecord): Promise<void>;
  getCachedRecord(groupId: string, recordId: string): Promise<EncryptedRecord | undefined>;
  /** Every cached record for a group, in unspecified order. */
  listCachedRecords(groupId: string): Promise<EncryptedRecord[]>;
  deleteCachedRecord(groupId: string, recordId: string): Promise<void>;

  // --- lifecycle ---
  /** Wipe every store (tests, device reset). */
  clear(): Promise<void>;
}
