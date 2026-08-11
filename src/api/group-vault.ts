/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * GroupVault — the public facade.
 *
 * The single class applications construct. It contains no protocol
 * logic: it wires ports to managers and enforces preconditions so
 * misuse is hard by construction — backup enrollment before any group
 * operation (spec §9.6, enforced in `GroupManager`), a freshness sync
 * before every record encryption (spec §9.3), and fail-fast
 * `InsecureContextError` outside secure contexts. During onboarding
 * it requests persistent storage so the browser does not silently
 * evict the local database.
 *
 * Defaults (browser): `WebCryptoProvider`, `IndexedDbStore`, Web
 * Locks (with an in-process fallback outside browsers). All three are
 * loaded lazily so hosts that inject their own adapters do not pull
 * the defaults into their bundle.
 */

import { EventHub } from "./events";
import type { JsonValue } from "../core/codec";
import {
  InsecureContextError,
  StaleEpochError,
  StorageError,
  TransportError,
  type ForkDetectedError,
} from "../core/errors";
import type { GroupState } from "../core/group-state";
import { KeyManager, type DeviceKeys } from "../core/key-manager";
import { deriveRecordId, RecordCrypto } from "../core/record-crypto";
import type { EncryptedRecord, GroupPolicy } from "../core/types";
import { BackupManager, type BackupManagerOptions } from "../managers/backup-manager";
import {
  DeviceManager,
  type LinkDeviceResult,
  type LostDeviceRoute,
  type UnlinkDeviceResult,
} from "../managers/device-manager";
import { GroupManager } from "../managers/group-manager";
import { SyncManager } from "../managers/sync-manager";
import { authorizeRelayRequest, type RelayOp, type RelayRequestAuth } from "../core/relay-auth";
import type { CryptoProvider } from "../ports/crypto-provider";
import type { HintChannel } from "../ports/hints";
import type { LockProvider } from "../ports/locks";
import type { StorageAdapter } from "../ports/storage";
import type { Transport } from "../ports/transport";

export interface GroupVaultEvents extends Record<string, unknown[]> {
  /** Equivocation signal (spec §9.1) — surface it to the user. */
  forkDetected: [groupId: string, error: ForkDetectedError];
  /**
   * A read was served from the offline cache because the backend was
   * unreachable. The payload is decrypted normally, but it is
   * whatever this device last saw — possibly stale. Listen if "is
   * this the current version?" matters to your application.
   *
   * Reported under the application's own key, not the derived
   * identifier the relay sees (spec §5.8 rule 2).
   */
  servedFromCache: [groupId: string, appKey: string];
}

export interface AddMemberInput {
  userId: string;
  /** The invitee's X25519 device pubkey, obtained out of band (spec §9.2). */
  devicePubkey: string;
  isManager?: boolean;
}

export interface GroupVaultOptions {
  /** The host application's backend adapter (spec §10). */
  transport: Transport;
  /** The application-level account this device belongs to (spec §10.1). */
  userId: string;
  /** Default: `IndexedDbStore` on the `"circlekey"` database. */
  storage?: StorageAdapter;
  /** Default: `WebCryptoProvider`. */
  crypto?: CryptoProvider;
  /** Default: Web Locks; in-process fallback outside browsers. */
  locks?: LockProvider;
  /** Set `false` to skip the `navigator.storage.persist()` request. */
  requestPersistentStorage?: boolean;
  /**
   * Backup KDF selection and cost overrides (spec §6.2). Defaults are
   * conforming — Argon2id at the spec baseline — so most hosts omit
   * this; reduce costs only in tests, or opt into
   * `ARGON2ID_PARAMS_HIGH_MEMORY` where memory allows.
   */
  backup?: BackupManagerOptions;
  /**
   * Cross-tab wake-up channel. Defaults to `BroadcastChannel` in the
   * browser and to none elsewhere. Hints are a latency optimization:
   * losing them never costs correctness, since every operation syncs
   * under the group lock regardless.
   */
  hints?: HintChannel;
}

interface VaultContext {
  userId: string;
  keys: DeviceKeys;
  keyManager: KeyManager;
  crypto: CryptoProvider;
  storage: StorageAdapter;
  sync: SyncManager;
  backup: BackupManager;
  groups: GroupManager;
  devices: DeviceManager;
  records: RecordCrypto;
  events: EventHub<GroupVaultEvents>;
  persistentStorage: boolean | undefined;
}

export class GroupVault {
  private constructor(private readonly ctx: VaultContext) {}

  /**
   * Open (or first-time onboard) this device: bootstraps the identity
   * if none is stored and re-verifies every persisted chain.
   */
  static async open(options: GroupVaultOptions): Promise<GroupVault> {
    return GroupVault.bootstrap(options);
  }

  /**
   * Recover a lost device (spec §9.6): fetches the backup blob,
   * unseals it with the recovery credential, then continues like
   * `open` with the restored identity. Follow with `syncGroup` per
   * group to recover secrets via the §9.7 history chain.
   */
  static async restore(
    options: GroupVaultOptions & { credential: string },
  ): Promise<GroupVault> {
    return GroupVault.bootstrap(options, options.credential);
  }

  private static async bootstrap(
    options: GroupVaultOptions,
    credential?: string,
  ): Promise<GroupVault> {
    const crypto = options.crypto ?? (await defaultCrypto());
    const storage = options.storage ?? (await defaultStorage());
    const locks = options.locks ?? (await defaultLocks());
    const hints = options.hints ?? (await defaultHints());
    const persistentStorage =
      options.requestPersistentStorage === false
        ? undefined
        : await requestPersistentStorage();

    const sync = new SyncManager(options.transport);
    const backup = new BackupManager(crypto, storage, sync, options.backup ?? {});
    const keyManager = new KeyManager(crypto);

    if (credential !== undefined) {
      await backup.restore(options.userId, credential);
    }

    let identity = await storage.getIdentity();
    if (identity === undefined) {
      const keys = await keyManager.generateDeviceKeys();
      identity = {
        userId: options.userId,
        identityPrivateKey: keys.identity.privateKey,
        backupEnrolled: false,
      };
      await storage.putIdentity(identity);
    } else if (identity.userId !== options.userId) {
      throw new StorageError(
        `local storage belongs to ${identity.userId}, not ${options.userId} — use a separate database per account`,
      );
    }
    const keys = await keyManager.deviceKeysFromIdentity(identity.identityPrivateKey);

    const events = new EventHub<GroupVaultEvents>();
    const groups = new GroupManager({
      crypto,
      storage,
      transport: options.transport,
      locks,
      deviceKeys: keys,
      userId: options.userId,
      onForkDetected: (groupId, error) => {
        events.emit("forkDetected", groupId, error);
      },
      ...(hints === undefined ? {} : { hints }),
    });
    await groups.start(); // reload + re-verify persisted chains

    return new GroupVault({
      userId: options.userId,
      keys,
      keyManager,
      crypto,
      storage,
      sync,
      backup,
      groups,
      devices: new DeviceManager(crypto, storage, groups),
      records: new RecordCrypto(crypto, storage),
      events,
      persistentStorage,
    });
  }

  // --- device / events ---

  get userId(): string {
    return this.ctx.userId;
  }

  /** Outcome of the `navigator.storage.persist()` request. */
  get persistentStorage(): boolean | undefined {
    return this.ctx.persistentStorage;
  }

  /** This device's X25519 pubkey — what a manager needs to add you. */
  devicePublicKey(): string {
    return this.ctx.keyManager.devicePublicKey(this.ctx.keys);
  }

  /** This device's Ed25519 identity pubkey (`signed_by` on the wire). */
  identityPublicKey(): string {
    return this.ctx.keyManager.identityPublicKey(this.ctx.keys);
  }

  on<K extends keyof GroupVaultEvents & string>(
    event: K,
    handler: (...args: GroupVaultEvents[K]) => void,
  ): () => void {
    return this.ctx.events.on(event, handler);
  }

  // --- backup (spec §9.6) ---

  isBackupEnrolled(): Promise<boolean> {
    return this.ctx.backup.isEnrolled();
  }

  /**
   * Phase one of the mandatory backup flow (spec §9.6): returns the
   * recovery credential exactly once.
   *
   * Group operations remain blocked until
   * {@link confirmBackupStored} is called with this credential.
   * Display it, and only confirm once the user says they have saved
   * it — there is no "skip for now".
   */
  enrollBackup(): Promise<string> {
    return this.ctx.backup.enroll();
  }

  /**
   * Phase two: record that the user has stored their credential,
   * which completes enrollment and unblocks group operations. The
   * credential is re-checked against the stored blob, so a value that
   * cannot actually open the backup will not open the gate either.
   */
  confirmBackupStored(credential: string): Promise<void> {
    return this.ctx.backup.confirmEnrollment(credential);
  }

  refreshBackup(credential: string): Promise<void> {
    return this.ctx.backup.refresh(credential);
  }

  // --- groups (spec §8, §9) ---

  /**
   * Create a group. The identifier is generated here and returned on
   * the state — the application does not choose it (spec §6.5, §12),
   * because `group_id` is plaintext on every request and a chosen name
   * would leak. Keep your own label against `state.group_id`.
   */
  createGroup(policy: GroupPolicy): Promise<GroupState> {
    return this.ctx.groups.createGroup(policy);
  }

  syncGroup(groupId: string): Promise<GroupState> {
    return this.ctx.groups.syncGroup(groupId);
  }

  /**
   * Follow a group in real time where the backend supports pushes
   * (spec §10.3). Each push triggers a verified sync — the pushed
   * transition itself is discarded. Returns an
   * unsubscribe, or `undefined` on a polling-only backend.
   */
  watchGroup(groupId: string): (() => void) | undefined {
    return this.ctx.groups.watchGroup(groupId);
  }

  /** Stop all subscriptions and release the cross-tab channel. */
  close(): void {
    this.ctx.groups.close();
  }

  getGroupState(groupId: string): GroupState | undefined {
    return this.ctx.groups.getState(groupId);
  }

  addMember(groupId: string, member: AddMemberInput): Promise<GroupState> {
    return this.ctx.groups.addMember(groupId, {
      user_id: member.userId,
      device_pubkeys: [member.devicePubkey],
      is_manager: member.isManager ?? false,
    });
  }

  removeMember(groupId: string, userId: string): Promise<GroupState> {
    return this.ctx.groups.removeMember(groupId, userId);
  }

  promoteMember(groupId: string, userId: string): Promise<GroupState> {
    return this.ctx.groups.promoteMember(groupId, userId);
  }

  demoteMember(groupId: string, userId: string): Promise<GroupState> {
    return this.ctx.groups.demoteMember(groupId, userId);
  }

  setPolicy(groupId: string, policy: GroupPolicy): Promise<GroupState> {
    return this.ctx.groups.setPolicy(groupId, policy);
  }

  // --- devices (spec §9.5) ---

  /**
   * Link another of this user's devices into every group this device
   * belongs to. Obtain `devicePubkey` from the new device's own
   * `devicePublicKey()` and transfer it out of band (QR, copy-paste).
   * Needs no manager — a device action only touches your own entry.
   */
  linkDevice(devicePubkey: string): Promise<LinkDeviceResult> {
    return this.ctx.devices.linkDevice(devicePubkey);
  }

  /** Link a device into one specific group (spec §9.5). */
  linkDeviceToGroup(groupId: string, devicePubkey: string): Promise<GroupState> {
    return this.ctx.groups.addDevice(groupId, devicePubkey);
  }

  /**
   * Remove one of this user's devices — a lost phone, a decommissioned
   * laptop — from every group where it is listed (spec §9.5). Each
   * group rekeys, so the removed device is cut off from data written
   * afterwards. Run this from a *surviving* device: a device that
   * removes itself still learns the new secret it just generated.
   */
  unlinkDevice(devicePubkey: string): Promise<UnlinkDeviceResult> {
    return this.ctx.devices.unlinkDevice(devicePubkey);
  }

  /** Remove a device from one specific group (spec §9.5). */
  unlinkDeviceFromGroup(groupId: string, devicePubkey: string): Promise<GroupState> {
    return this.ctx.groups.removeDevice(groupId, devicePubkey);
  }

  /**
   * Which recovery route applies to a lost device in this group
   * (spec §9.5, §11): remove it from another device, restore this
   * identity from its backup credential, or escalate to a manager.
   */
  lostDeviceOptions(groupId: string, lostDevicePubkey: string): LostDeviceRoute {
    return this.ctx.devices.lostDeviceOptions(groupId, lostDevicePubkey);
  }

  /** Device public keys currently listed for a user in a group. */
  devicesOf(groupId: string, userId: string): string[] {
    return this.ctx.devices.devicesOf(groupId, userId);
  }

  // --- records (spec §7, §9.3) ---

  /**
   * The opaque identifier the relay will see for an application key
   * (spec §5.8 rule 2, §6.5).
   *
   * Public because {@link listRecords} returns derived identifiers: an
   * application that wants to match a listing against its own keys has
   * to be able to compute the same mapping. It is an identifier, not a
   * secret — but it is also not guessable without the group's genesis
   * secret, which is the point.
   */
  recordIdFor(groupId: string, appKey: string): Promise<string> {
    // Anchored on the genesis secret so an identifier survives every
    // rotation; a record whose id changed each epoch would be
    // unfindable after the first membership change.
    return this.secretForEpoch(groupId, 0).then((genesis) =>
      deriveRecordId(this.ctx.crypto, genesis, appKey),
    );
  }

  async putJsonRecord(
    groupId: string,
    appKey: string,
    payload: JsonValue,
  ): Promise<EncryptedRecord> {
    const recordId = await this.recordIdFor(groupId, appKey);
    return this.putRecordWith(groupId, (epoch, secret) =>
      this.ctx.records.encryptJsonRecord(groupId, epoch, secret, recordId, payload),
    );
  }

  async putRecordBytes(
    groupId: string,
    appKey: string,
    plaintext: Uint8Array,
  ): Promise<EncryptedRecord> {
    const recordId = await this.recordIdFor(groupId, appKey);
    return this.putRecordWith(groupId, (epoch, secret) =>
      this.ctx.records.encryptRecord(groupId, epoch, secret, recordId, plaintext),
    );
  }

  async getJsonRecord(groupId: string, appKey: string): Promise<unknown> {
    const record = await this.fetchRecord(groupId, await this.recordIdFor(groupId, appKey), appKey);
    const secret = await this.secretForEpoch(groupId, record.epoch);
    return this.ctx.records.decryptJsonRecord(groupId, secret, record);
  }

  async getRecordBytes(groupId: string, appKey: string): Promise<Uint8Array> {
    const record = await this.fetchRecord(groupId, await this.recordIdFor(groupId, appKey), appKey);
    const secret = await this.secretForEpoch(groupId, record.epoch);
    return this.ctx.records.decryptRecord(groupId, secret, record);
  }

  /**
   * Raw encrypted records — decrypt selectively via `getJsonRecord`.
   * Falls back to the offline cache when the backend is unreachable.
   */
  async listRecords(groupId: string): Promise<EncryptedRecord[]> {
    try {
      const { records } = await this.ctx.sync.listRecords(
        groupId,
        undefined,
        await this.authFor(groupId, "listRecords"),
      );
      for (const record of records) {
        await this.ctx.storage.putCachedRecord(groupId, record);
      }
      return records;
    } catch (error) {
      if (!(error instanceof TransportError)) throw error;
      return this.ctx.storage.listCachedRecords(groupId);
    }
  }

  /**
   * Fetch a record, caching it, and fall back to the cached copy when
   * the backend is unreachable.
   *
   * Only `TransportError` triggers the fallback: a decryption or
   * verification failure is a real problem and must not be papered
   * over with older data. A cache hit emits `servedFromCache`, since
   * the caller otherwise cannot tell a current record from a stale
   * one — the cost of making the fallback automatic.
   */
  private async fetchRecord(
    groupId: string,
    recordId: string,
    appKey: string,
  ): Promise<EncryptedRecord> {
    try {
      const record = await this.ctx.sync.getRecord(
        groupId,
        recordId,
        await this.authFor(groupId, "getRecord"),
      );
      await this.ctx.storage.putCachedRecord(groupId, record);
      return record;
    } catch (error) {
      if (!(error instanceof TransportError)) throw error;
      const cached = await this.ctx.storage.getCachedRecord(groupId, recordId);
      if (cached === undefined) throw error;
      // Reported under the caller's own key, not the derived id: a host
      // cannot correlate an opaque identifier it never chose.
      this.ctx.events.emit("servedFromCache", groupId, appKey);
      return cached;
    }
  }

  /**
   * spec §9.3 freshness gate, client half: sync to the latest epoch
   * immediately before encrypting; one retry if the backend still
   * reports the write stale (a rotation raced us).
   */
  private async putRecordWith(
    groupId: string,
    encrypt: (epoch: number, secret: Uint8Array) => Promise<EncryptedRecord>,
  ): Promise<EncryptedRecord> {
    let stale: StaleEpochError | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const state = await this.ctx.groups.syncGroup(groupId);
      const secret = await this.ctx.storage.getGroupSecret(groupId, state.epoch);
      if (secret === undefined) {
        throw new StorageError(
          `this device holds no current secret for ${groupId} — it is not (or no longer) a member`,
        );
      }
      const record = await encrypt(state.epoch, secret);
      try {
        await this.ctx.sync.putRecord(
          groupId,
          record,
          await this.authFor(groupId, "putRecord"),
        );
        // Cache what we just stored, so an offline read of our own
        // write succeeds.
        await this.ctx.storage.putCachedRecord(groupId, record);
        return record;
      } catch (error) {
        if (!(error instanceof StaleEpochError)) throw error;
        stale = error;
      }
    }
    throw stale ?? new StaleEpochError("record write kept losing to epoch rotations");
  }

  /**
   * Sign a record request under the group's per-epoch relay key
   * (spec §10.1). Governance requests are signed by `GroupManager`;
   * records go straight to `SyncManager` from here, so they need the
   * same treatment or a conforming relay refuses every one of them.
   *
   * Returns `undefined` when this device holds no secret for the
   * current epoch — the relay's bootstrap exemption (spec §10.5) is
   * what covers a first read; a write with no signature is refused,
   * which is correct.
   */
  private async authFor(groupId: string, op: RelayOp): Promise<RelayRequestAuth | undefined> {
    const epoch = this.ctx.groups.getState(groupId)?.epoch;
    if (epoch === undefined) return undefined;
    const secret = await this.ctx.storage.getGroupSecret(groupId, epoch);
    if (secret === undefined) return undefined;
    return authorizeRelayRequest(this.ctx.crypto, groupId, op, epoch, secret);
  }

  private async secretForEpoch(groupId: string, epoch: number): Promise<Uint8Array> {
    let secret = await this.ctx.storage.getGroupSecret(groupId, epoch);
    if (secret === undefined) {
      await this.ctx.groups.syncGroup(groupId); // may recover via §9.7
      secret = await this.ctx.storage.getGroupSecret(groupId, epoch);
    }
    if (secret === undefined) {
      throw new StorageError(
        `no group_secret for ${groupId} epoch ${String(epoch)} — this device has no access to that epoch`,
      );
    }
    return secret;
  }
}

// --- lazy defaults (kept out of host bundles that inject their own) ---

async function defaultCrypto(): Promise<CryptoProvider> {
  const webCrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (webCrypto?.subtle === undefined) {
    throw new InsecureContextError(
      "WebCrypto is unavailable — CircleKey requires a secure context (HTTPS or localhost) or Node >= 20",
    );
  }
  const { WebCryptoProvider } = await import("../adapters/crypto/web");
  return new WebCryptoProvider();
}

async function defaultStorage(): Promise<StorageAdapter> {
  const { IndexedDbStore } = await import("../adapters/storage/indexeddb");
  return IndexedDbStore.open();
}

async function defaultLocks(): Promise<LockProvider> {
  const { WebLocksProvider, InProcessLockProvider } = await import("../adapters/locks");
  try {
    return new WebLocksProvider();
  } catch {
    // Outside browsers a single process owns the store.
    return new InProcessLockProvider();
  }
}

async function defaultHints(): Promise<HintChannel | undefined> {
  if ((globalThis as { BroadcastChannel?: unknown }).BroadcastChannel === undefined) {
    return undefined; // Node and older browsers: polling only.
  }
  const { BroadcastChannelHints } = await import("../adapters/hints");
  return new BroadcastChannelHints();
}

async function requestPersistentStorage(): Promise<boolean | undefined> {
  const manager = (globalThis.navigator as Navigator | undefined)?.storage;
  if (manager === undefined) return undefined;
  try {
    return await manager.persist();
  } catch {
    return undefined;
  }
}
