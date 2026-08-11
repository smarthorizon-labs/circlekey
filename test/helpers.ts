/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/** Shared test utilities (not a test suite). */

import type { GroupVault } from "../src/api/group-vault";
import type {
  BackupManager,
  BackupManagerOptions,
} from "../src/managers/backup-manager";

import type { EpochTransition, WireTransition } from "../src/core/types";
import type { KeyUsageStore } from "../src/ports/storage";
import type { Transport } from "../src/ports/transport";
import { openAnyEnvelope } from "../src/core/envelopes";
import { deriveRelayHandle } from "../src/core/handles";
import { DEFAULT_RELAY_ID } from "../src/managers/backup-manager";
import type { DeviceKeys } from "../src/core/key-manager";
import type { CryptoProvider } from "../src/ports/crypto-provider";

/**
 * Run both phases of the spec §9.6 enrollment flow. Most tests only
 * care that the device ends up enrolled; the tests that care about
 * the gate itself call the two phases separately.
 */
export async function completeEnrollment(vault: GroupVault): Promise<string> {
  const credential = await vault.enrollBackup();
  await vault.confirmBackupStored(credential);
  return credential;
}

/** The same, one layer down, for tests that drive `BackupManager`. */
export async function completeBackupEnrollment(
  backup: BackupManager,
): Promise<string> {
  const credential = await backup.enroll();
  await backup.confirmEnrollment(credential);
  return credential;
}

/**
 * Backup options for tests: the real Argon2id code path (the
 * production default) at a fraction of the spec §6.2 cost, so suites
 * exercise the primary KDF without paying 19 MiB × 2 per enrollment.
 * Dedicated tests in `backup.test.ts` cover the real spec parameters.
 */
export const FAST_BACKUP: BackupManagerOptions = {
  argon2Params: { memoryKiB: 64, iterations: 1, parallelism: 1 },
  kdfIterations: 1000,
};

/**
 * Delegates to a real Transport. `override` poisons getTransitions;
 * `failReads` simulates an unreachable backend for record reads.
 */
export class SwitchableTransport implements Transport {
  override: ((groupId: string, sinceEpoch?: number) => WireTransition[]) | null = null;
  /** When set, record reads reject with this error. */
  failReads: Error | null = null;

  constructor(private readonly inner: Transport) {}

  getTransitions(groupId: string, sinceEpoch?: number): Promise<WireTransition[]> {
    if (this.override !== null) {
      return Promise.resolve(structuredClone(this.override(groupId, sinceEpoch)));
    }
    return this.inner.getTransitions(groupId, sinceEpoch);
  }

  createGroup: Transport["createGroup"] = (genesis) => this.inner.createGroup(genesis);
  getGroupState: Transport["getGroupState"] = (g) => this.inner.getGroupState(g);
  submitTransition: Transport["submitTransition"] = (g, t) =>
    this.inner.submitTransition(g, t);
  putRecord: Transport["putRecord"] = (g, r) => this.inner.putRecord(g, r);
  getRecord: Transport["getRecord"] = (g, r) =>
    this.failReads === null
      ? this.inner.getRecord(g, r)
      : Promise.reject(this.failReads);
  listRecords: Transport["listRecords"] = (g, c) => {
    if (this.failReads !== null) return Promise.reject(this.failReads);
    return c === undefined ? this.inner.listRecords(g) : this.inner.listRecords(g, c);
  };
  putBackupBlob: Transport["putBackupBlob"] = (u, b) => this.inner.putBackupBlob(u, b);
  getBackupBlob: Transport["getBackupBlob"] = (u) => this.inner.getBackupBlob(u);
}

/** In-memory `KeyUsageStore` — single-process stand-in. */
export class MemoryKeyUsageStore implements KeyUsageStore {
  readonly counts = new Map<string, number>();

  incrementKeyUsage(groupId: string, epoch: number): Promise<number> {
    const key = `${groupId}|${String(epoch)}`;
    const next = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, next);
    return Promise.resolve(next);
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replaceAll(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Can this device open any envelope in the transition (spec §6.5)?
 *
 * Envelopes are unaddressed, so "who was enveloped"
 * is no longer readable off the wire — by design. Tests assert it by
 * trial decryption instead, which is a stronger claim than the old
 * `device_pubkey` label was: it proves the recipient can actually
 * derive the secret, not merely that someone wrote their name on it.
 */
export async function canOpenEnvelope(
  crypto: CryptoProvider,
  deviceKeys: DeviceKeys,
  wire: WireTransition,
): Promise<boolean> {
  const opened = await openAnyEnvelope(crypto, deviceKeys.encryption, wire.secret_envelopes);
  return opened !== undefined;
}

/** The `envelope_slots` entry a transition claims for one device. */
export function claimedSlot(transition: EpochTransition, devicePubkey: string): number {
  const index = transition.members.flatMap((m) => m.device_pubkeys).indexOf(devicePubkey);
  return index < 0 ? -1 : (transition.envelope_slots[index] ?? -1);
}

/**
 * A structurally valid {@link WireTransition} for tests that exercise
 * routing, storage and transport rather than cryptography — the relay
 * and the store treat `sealed_body` and the envelopes as opaque
 * (spec §10.2), so opaque placeholders are the honest fixture here.
 * Tests that need a body that actually opens build one with the real
 * builders instead.
 */
export function wireStub(groupId: string, epoch: number): WireTransition {
  const wire: WireTransition = {
    group_id: groupId,
    epoch,
    sealed_body: `sealed-${String(epoch)}`,
    secret_envelopes: ["opaque"],
    auth_pubkey: `auth-${String(epoch)}`,
  };
  if (epoch > 0) wire.prev_secret_ciphertext = `link-${String(epoch)}`;
  return wire;
}

/**
 * Group history from one Transport, backup blobs from another.
 *
 * Used to give a restored device its own relay for group data while it
 * still reads the backup blob it was enrolled against — the only way to
 * grow a second honest branch, since a fork can no longer be forged
 * (spec §6.5: bodies are sealed to the epoch secret).
 */
export class SplitTransport implements Transport {
  constructor(
    private readonly groups: Transport,
    private readonly backups: Transport,
  ) {}

  createGroup: Transport["createGroup"] = (genesis) => this.groups.createGroup(genesis);
  getGroupState: Transport["getGroupState"] = (groupId) =>
    this.groups.getGroupState(groupId);
  submitTransition: Transport["submitTransition"] = (groupId, transition) =>
    this.groups.submitTransition(groupId, transition);
  getTransitions: Transport["getTransitions"] = (groupId, sinceEpoch) =>
    this.groups.getTransitions(groupId, sinceEpoch);
  putRecord: Transport["putRecord"] = (groupId, record) =>
    this.groups.putRecord(groupId, record);
  getRecord: Transport["getRecord"] = (groupId, recordId) =>
    this.groups.getRecord(groupId, recordId);
  listRecords: Transport["listRecords"] = (groupId, cursor) =>
    this.groups.listRecords(groupId, cursor);
  putBackupBlob: Transport["putBackupBlob"] = (userId, blob) =>
    this.backups.putBackupBlob(userId, blob);
  getBackupBlob: Transport["getBackupBlob"] = (userId) =>
    this.backups.getBackupBlob(userId);
}

/**
 * The blinded handle a backup blob lives under (spec §6.5).
 *
 * Tests that inspect the stored blob need this because the relay is
 * addressed by handle, never by user id — which is the point. Mirrors
 * `BackupManager`'s own derivation.
 */
export function backupHandleFor(
  crypto: CryptoProvider,
  credential: string,
  relayId = DEFAULT_RELAY_ID,
): Promise<string> {
  return deriveRelayHandle(
    (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
      crypto.hkdfSha256(ikm, salt, info, length),
    credential,
    relayId,
  );
}
