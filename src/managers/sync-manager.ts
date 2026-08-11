/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * SyncManager: the only module that touches
 * the `Transport` port. It relays fetches and submissions and maps
 * backend rejections to typed errors — zero cryptography, zero trust
 * decisions. Verification lives in `GroupManager`/`core`; the
 * backend's opinion is never authoritative (spec §10.1).
 *
 * Polls by default; uses `subscribeToTransitions` where the transport
 * offers it, and rebuilds-and-retries automatically on conflict.
 */

import {
  ConflictError,
  StaleEpochError,
  SubmitRejectedError,
} from "../core/errors";
import { parseWireTransitions } from "../core/wire";
import type {
  EncryptedBackupBlob,
  EncryptedRecord,
  WireTransition,
  GroupHandle,
  RecordPage,
  Unsubscribe,
} from "../core/types";
import type { RelayRequestAuth } from "../core/relay-auth";
import type { Transport } from "../ports/transport";

export class SyncManager {
  constructor(private readonly transport: Transport) {}

  createGroup(genesis: WireTransition): Promise<GroupHandle> {
    return this.transport.createGroup(genesis);
  }

  /**
   * Transitions with `epoch > sinceEpoch`, shape-checked but
   * cryptographically **unverified** — `verifyTransition` still owns
   * every §9.1 check.
   *
   * The shape guard is what keeps a hostile or simply broken backend
   * to typed rejections: without it, `members: null` reaches the
   * verifier and surfaces as a bare `TypeError` from deep inside it.
   */
  async fetchNewTransitions(
    groupId: string,
    sinceEpoch?: number,
    auth?: RelayRequestAuth,
  ): Promise<WireTransition[]> {
    return parseWireTransitions(
      await this.transport.getTransitions(groupId, sinceEpoch, auth),
    );
  }

  /**
   * Subscribe to backend pushes, if the Transport supports them.
   *
   * The pushed transition is deliberately **discarded**: `onChanged`
   * receives no payload at all. A push means "you may be behind", and
   * the caller responds with an ordinary sync from its own verified
   * head — applying a pushed transition directly would take an
   * untrusted party's word for both the content *and* the ordering
   * that makes gap and replay detection meaningful.
   *
   * Returns `undefined` when the Transport is polling-only.
   */
  subscribe(groupId: string, onChanged: () => void): Unsubscribe | undefined {
    const subscribeToTransitions = this.transport.subscribeToTransitions?.bind(
      this.transport,
    );
    if (subscribeToTransitions === undefined) return undefined;
    return subscribeToTransitions(groupId, () => {
      onChanged();
    });
  }

  async submitTransition(
    groupId: string,
    transition: WireTransition,
    auth?: RelayRequestAuth,
  ): Promise<void> {
    const result = await this.transport.submitTransition(groupId, transition, auth);
    if (result.accepted) return;
    switch (result.reason) {
      case "conflict":
        throw new ConflictError(
          `another manager won epoch ${String(transition.epoch)} of group ${groupId} — re-sync and rebuild (spec §10.4)`,
        );
      case "stale_epoch":
        throw new StaleEpochError(
          `backend rejected transition for group ${groupId} as stale (spec §9.3)`,
        );
      default:
        throw new SubmitRejectedError(
          `backend rejected transition for group ${groupId}: ${result.reason}`,
        );
    }
  }

  async putRecord(
    groupId: string,
    record: EncryptedRecord,
    auth?: RelayRequestAuth,
  ): Promise<void> {
    const result = await this.transport.putRecord(groupId, record, auth);
    if (!result.accepted) {
      throw new StaleEpochError(
        `backend freshness gate rejected record ${record.record_id} (epoch ${String(record.epoch)}) — sync and re-encrypt under the current epoch (spec §9.3)`,
      );
    }
  }

  getRecord(
    groupId: string,
    recordId: string,
    auth?: RelayRequestAuth,
  ): Promise<EncryptedRecord> {
    return this.transport.getRecord(groupId, recordId, auth);
  }

  listRecords(
    groupId: string,
    cursor?: string,
    auth?: RelayRequestAuth,
  ): Promise<RecordPage> {
    return cursor === undefined
      ? this.transport.listRecords(groupId, undefined, auth)
      : this.transport.listRecords(groupId, cursor, auth);
  }

  putBackupBlob(handle: string, blob: EncryptedBackupBlob): Promise<void> {
    return this.transport.putBackupBlob(handle, blob);
  }

  getBackupBlob(handle: string): Promise<EncryptedBackupBlob> {
    return this.transport.getBackupBlob(handle);
  }
}
