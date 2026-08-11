/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * DeviceManager (spec §9.5): linking additional
 * devices to a user's identity.
 *
 * Device lists live in the epoch chain's member set, so linking is an
 * ordinary signed transition (`add_device`) that every client
 * verifies — not an out-of-band certificate. Three properties follow:
 * the linked device can sign immediately, it receives the group
 * secret through the transition's own envelopes, and its authority is
 * publicly auditable.
 *
 * The two halves live on different devices:
 *
 * - **New device** calls {@link DeviceManager.prepareDevice} to create
 *   its identity and publish its public key. Transferring that key to
 *   an existing device (QR, copy-paste) is out of scope, as with
 *   invitations (spec §9.2).
 * - **Existing device** calls {@link DeviceManager.linkDevice} with
 *   that key, which issues one `add_device` transition per group.
 *
 * Removal ({@link DeviceManager.unlinkDevice}) is the mirror image and
 * is what actually cuts a lost device off: every transition rekeys, so
 * the removed key receives no envelope for the new epoch.
 * {@link DeviceManager.lostDeviceOptions} reports which recovery route
 * applies when a device is gone (spec §9.5, §11).
 */

import { KeyManager, type DeviceKeys } from "../core/key-manager";
import type { CryptoProvider } from "../ports/crypto-provider";
import type { StorageAdapter } from "../ports/storage";
import type { GroupManager } from "./group-manager";

export interface LinkDeviceResult {
  /** Groups the device was linked into, with their new epoch. */
  linked: { groupId: string; epoch: number }[];
  /** Groups skipped because this device cannot act in them, with why. */
  skipped: { groupId: string; reason: string }[];
}

export interface UnlinkDeviceResult {
  /** Groups the device was removed from, with their new epoch. */
  unlinked: { groupId: string; epoch: number }[];
  /** Groups skipped (device absent, or this device cannot act), with why. */
  skipped: { groupId: string; reason: string }[];
}

/**
 * Which recovery route applies to a lost device in a given group
 * (spec §9.5, §11). The routes are ordered by cost: act from another
 * device, else restore from backup, else escalate to a manager.
 */
export type LostDeviceRoute =
  | {
      route: "remove-from-other-device";
      /** Devices that can sign the `remove_device` transition. */
      usableDevices: string[];
    }
  | { route: "restore-from-backup" }
  | { route: "escalate-to-manager"; reason: string };

export class DeviceManager {
  private readonly keyManager: KeyManager;

  constructor(
    crypto: CryptoProvider,
    private readonly storage: StorageAdapter,
    private readonly groups: GroupManager,
  ) {
    this.keyManager = new KeyManager(crypto);
  }

  /**
   * Run on the **new** device: generate its identity, persist it, and
   * return the public key to hand to an already-linked device.
   *
   * The new device is marked backup-enrolled only once it runs its own
   * enrollment; until then the mandatory-backup gate (spec §9.6) keeps
   * group operations closed, exactly as for a first device.
   */
  async prepareDevice(userId: string): Promise<{ keys: DeviceKeys; devicePubkey: string }> {
    const existing = await this.storage.getIdentity();
    if (existing !== undefined) {
      const keys = await this.keyManager.deviceKeysFromIdentity(
        existing.identityPrivateKey,
      );
      return { keys, devicePubkey: this.keyManager.devicePublicKey(keys) };
    }
    const keys = await this.keyManager.generateDeviceKeys();
    await this.storage.putIdentity({
      userId,
      identityPrivateKey: keys.identity.privateKey,
      backupEnrolled: false,
    });
    return { keys, devicePubkey: this.keyManager.devicePublicKey(keys) };
  }

  /**
   * Run on an **existing** device: link `newDevicePubkey` into every
   * group this device belongs to (spec §9.5).
   *
   * Groups where this device cannot act — it is not a member, or it
   * lacks the current secret — are reported in `skipped` rather than
   * failing the whole operation, since a user's groups are
   * independent and a partial link is still useful.
   */
  async linkDevice(newDevicePubkey: string): Promise<LinkDeviceResult> {
    const result: LinkDeviceResult = { linked: [], skipped: [] };
    for (const groupId of await this.storage.listGroupIds()) {
      try {
        const state = await this.groups.addDevice(groupId, newDevicePubkey);
        result.linked.push({ groupId, epoch: state.epoch });
      } catch (error) {
        result.skipped.push({
          groupId,
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return result;
  }

  /**
   * Run on a **surviving** device: remove `devicePubkey` from every
   * group where it is listed for this user (spec §9.5). Each removal
   * rekeys the group, so the removed device cannot read anything
   * written afterwards.
   *
   * Groups where the key is absent, or where this device cannot act,
   * are reported in `skipped` rather than failing the operation.
   */
  async unlinkDevice(devicePubkey: string): Promise<UnlinkDeviceResult> {
    const result: UnlinkDeviceResult = { unlinked: [], skipped: [] };
    for (const groupId of await this.storage.listGroupIds()) {
      try {
        const state = await this.groups.removeDevice(groupId, devicePubkey);
        result.unlinked.push({ groupId, epoch: state.epoch });
      } catch (error) {
        result.skipped.push({
          groupId,
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return result;
  }

  /**
   * Advise on a lost device (spec §9.5, §11) for one group, from this
   * device's verified state. Returns the cheapest applicable route.
   */
  lostDeviceOptions(groupId: string, lostDevicePubkey: string): LostDeviceRoute {
    const state = this.groups.getState(groupId);
    if (state === undefined) {
      return {
        route: "escalate-to-manager",
        reason: `no verified state for group ${groupId} on this device`,
      };
    }
    const owner = state.members.find((member) =>
      member.device_pubkeys.includes(lostDevicePubkey),
    );
    if (owner === undefined) {
      return {
        route: "escalate-to-manager",
        reason: `device is not listed in group ${groupId} — nothing to revoke here`,
      };
    }
    const usableDevices = owner.device_pubkeys.filter((key) => key !== lostDevicePubkey);
    if (usableDevices.length > 0) {
      return { route: "remove-from-other-device", usableDevices };
    }
    // The lost device was the user's only one. The identity itself is
    // recoverable from the backup credential (spec §9.6) — which
    // restores the *same* device key, so no device action is needed.
    // Only if that credential is also gone does this become a
    // group-level problem for a manager (spec §11).
    return { route: "restore-from-backup" };
  }

  /** Device public keys currently listed for `userId` in a group. */
  devicesOf(groupId: string, userId: string): string[] {
    const member = this.groups
      .getState(groupId)
      ?.members.find((candidate) => candidate.user_id === userId);
    return member === undefined ? [] : [...member.device_pubkeys];
  }
}
