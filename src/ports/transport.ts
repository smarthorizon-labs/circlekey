/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Transport port: the client ⇄ backend
 * contract of spec §10.3, transport-agnostic exactly as the spec
 * frames it. CircleKey ships no production adapter — the host
 * application implements this interface against its own backend
 * (REST, GraphQL, WebSocket, …); `MockTransport`
 * (`adapters/transport/mock.ts`) is the executable reference of the
 * backend-side obligations for tests and backend teams.
 *
 * Trust reminder (spec §10.1, §5.7): nothing returned by a Transport
 * is authoritative. Only `SyncManager` talks to this port, and every
 * transition it fetches goes through the full §9.1 checklist before
 * touching state or storage.
 *
 * This port is also the boundary spec §12's first requirement is
 * about — "the backend MUST NOT ever receive plaintext, private keys,
 * or group secrets". `test/no-secret-leaks.test.ts` asserts it
 * directly: it runs a full lifecycle through a recording Transport
 * and searches everything handed over for record plaintext, identity
 * and device private keys, the recovery credential, and every epoch's
 * group secret, in both base64url and raw-byte spellings.
 */

import type { RelayRequestAuth } from "../core/relay-auth";
import type {
  EncryptedBackupBlob,
  EncryptedRecord,
  WireTransition,
  GroupHandle,
  GroupStateSnapshot,
  PutResult,
  RecordPage,
  SubmitResult,
  Unsubscribe,
} from "../core/types";

/**
 * Every group-scoped call carries a request signature under the group's
 * per-epoch relay key (spec §10.1). It is optional in the type so a
 * host transport that authenticates by other means — or a test — can
 * ignore it; `MockTransport` is the reference for what a relay MUST
 * enforce.
 */
export interface Transport {
  // --- Group lifecycle (spec §10.3) ---
  createGroup(genesis: WireTransition): Promise<GroupHandle>;
  /** Routing hint only — never folded into local state (spec §5.7). */
  getGroupState(groupId: string, auth?: RelayRequestAuth): Promise<GroupStateSnapshot>;

  // --- Epoch transitions ---
  submitTransition(groupId: string, transition: WireTransition, auth?: RelayRequestAuth): Promise<SubmitResult>;
  /** Transitions with `epoch > sinceEpoch` (all when omitted), ascending. */
  getTransitions(groupId: string, sinceEpoch?: number, auth?: RelayRequestAuth): Promise<WireTransition[]>;
  /** Live push, where the backend supports it; clients otherwise poll. */
  subscribeToTransitions?(
    groupId: string,
    onTransition: (transition: WireTransition) => void,
  ): Unsubscribe;

  // --- Records ---
  putRecord(groupId: string, record: EncryptedRecord, auth?: RelayRequestAuth): Promise<PutResult>;
  getRecord(groupId: string, recordId: string, auth?: RelayRequestAuth): Promise<EncryptedRecord>;
  listRecords(groupId: string, cursor?: string, auth?: RelayRequestAuth): Promise<RecordPage>;

  // No device endpoints, deliberately (spec §10.3): devices live in
  // the epoch chain's member set and arrive over `getTransitions`
  // like everything else. A backend-held device registry would be a
  // second, untrusted source of truth for the same fact.

  // --- Backup (spec §9.6) ---
  //
  // `handle` is a *blinded* identifier derived from the user's recovery
  // credential (spec §6.5), never a user id: a relay that stored blobs
  // under account names would hold a list of who has a backup, and the
  // credential is the one thing a restoring device has before it has
  // anything else. Treat it as an opaque key.
  putBackupBlob(handle: string, blob: EncryptedBackupBlob): Promise<void>;
  getBackupBlob(handle: string): Promise<EncryptedBackupBlob>;
}
