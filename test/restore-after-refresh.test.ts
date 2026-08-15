/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Restoring a device whose backup carries group secrets.
 *
 * `refreshBackup()` snapshots every group secret this device holds into
 * the blob, so `restore()` writes those secrets into a fresh store —
 * with **no transitions behind them**, because the chain is not backed
 * up and is re-fetched from the relay instead.
 *
 * That combination broke the catch-up walk. It stops at the first epoch
 * whose secret is already stored, on the reasoning that anything older
 * "was verified when it was stored" — true for a device that has been
 * running, false for one that has just restored. The secrets map then
 * omits every restored epoch, the forward loop read the first of them
 * as loss of access, and sync stopped with nothing verified at all.
 *
 * The failure was silent until the moment recovery was needed, which is
 * the one moment a user has no alternative — so these tests pin the
 * whole path rather than the single line that was wrong.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { SecretUnavailableError } from "../src/core/errors";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();

function options(transport: Transport, userId: string) {
  return {
    transport,
    userId,
    crypto,
    storage: new MemoryStore(),
    locks: new InProcessLockProvider(),
    requestPersistentStorage: false,
    backup: FAST_BACKUP,
  };
}

/** A group at epoch 2: genesis, add bob, add carol. */
async function threeEpochGroup(transport: Transport) {
  const alice = await GroupVault.open(options(transport, "alice"));
  const credential = await completeEnrollment(alice);
  const { group_id: groupId } = await alice.createGroup({ min_managers: 1 });

  for (const name of ["bob", "carol"]) {
    const member = await GroupVault.open(options(transport, name));
    await completeEnrollment(member);
    await alice.addMember(groupId, {
      userId: name,
      devicePubkey: member.devicePublicKey(),
      isManager: false,
    });
    member.close();
  }
  return { alice, credential, groupId };
}

describe("restore after refreshBackup", () => {
  it("syncs the full chain when the blob carried group secrets", async () => {
    const transport = new MockTransport();
    const { alice, credential, groupId } = await threeEpochGroup(transport);

    // The step that populates the blob's secrets snapshot.
    await alice.refreshBackup(credential);

    const store = new MemoryStore();
    const restored = await GroupVault.restore({
      ...options(transport, "alice"),
      storage: store,
      credential,
    });

    // Premise: this is the state the walk has to cope with — secrets
    // present, transitions absent. If restore ever changes to persist
    // transitions too, this test stops covering the bug it was written
    // for, so assert the premise rather than assume it.
    expect([...(await store.getGroupSecrets(groupId)).keys()]).toEqual([0, 1, 2]);
    expect(await store.getTransitions(groupId)).toHaveLength(0);

    expect(restored.devicePublicKey()).toBe(alice.devicePublicKey());

    const state = await restored.syncGroup(groupId);
    expect(state.epoch).toBe(2);
    expect(state.members.map((m) => m.user_id).sort()).toEqual([
      "alice",
      "bob",
      "carol",
    ]);

    // Verified, not merely accepted: the whole chain is persisted.
    expect(await store.getTransitions(groupId)).toHaveLength(3);

    alice.close();
    restored.close();
  });

  it("restores read access to records written before the backup", async () => {
    const transport = new MockTransport();
    const { alice, credential, groupId } = await threeEpochGroup(transport);
    await alice.putJsonRecord(groupId, "note", { secret: "hello" });
    await alice.refreshBackup(credential);

    const restored = await GroupVault.restore({
      ...options(transport, "alice"),
      credential,
    });
    await restored.syncGroup(groupId);
    expect(await restored.getJsonRecord(groupId, "note")).toEqual({
      secret: "hello",
    });

    alice.close();
    restored.close();
  });

  it("is unaffected by whether the blob was refreshed", async () => {
    // The two paths must converge: the snapshot is an optimization for
    // groups the device has since lost, never a precondition for
    // recovering the ones it still belongs to.
    for (const refreshed of [false, true]) {
      const transport = new MockTransport();
      const { alice, credential, groupId } = await threeEpochGroup(transport);
      if (refreshed) await alice.refreshBackup(credential);

      const restored = await GroupVault.restore({
        ...options(transport, "alice"),
        credential,
      });
      expect((await restored.syncGroup(groupId)).epoch).toBe(2);

      alice.close();
      restored.close();
    }
  });

  /**
   * The fallback must not paper over genuine loss of access. Removal
   * has two shapes after a restore, depending on whether the blob
   * carried secrets, and they are supposed to end differently.
   */
  describe("a removed member", () => {
    async function removedBob(refreshBeforeRemoval: boolean) {
      const transport = new MockTransport();
      const alice = await GroupVault.open(options(transport, "alice"));
      await completeEnrollment(alice);
      const { group_id: groupId } = await alice.createGroup({ min_managers: 1 });

      const bob = await GroupVault.open(options(transport, "bob"));
      const credential = await completeEnrollment(bob);
      await alice.addMember(groupId, {
        userId: "bob",
        devicePubkey: bob.devicePublicKey(),
        isManager: false,
      });
      await bob.syncGroup(groupId);
      if (refreshBeforeRemoval) await bob.refreshBackup(credential);
      await alice.removeMember(groupId, "bob");

      const restored = await GroupVault.restore({
        ...options(transport, "bob"),
        credential,
      });
      return { alice, bob, restored, groupId };
    }

    it("keeps the history it could read, and does not see its own removal", async () => {
      // Refreshed before removal, so the blob holds the epochs bob
      // could read. He recovers exactly those and stops: the removal
      // transition is sealed to a secret he never had (spec §9.3), so
      // he observes loss of access rather than being told about it.
      const { alice, bob, restored, groupId } = await removedBob(true);

      const state = await restored.syncGroup(groupId);
      expect(state.epoch).toBe(1);
      expect(state.members.map((m) => m.user_id)).toContain("bob");

      alice.close();
      bob.close();
      restored.close();
    });

    it("reports lost access as such, not as a transport fault", async () => {
      // Never refreshed, so the blob predates the group and carries no
      // secrets. Nothing opens at the head and nothing is held, so
      // there is no history to recover at all — the case that used to
      // surface as `TransportError: has no transitions to verify`,
      // sending a host to diagnose the network.
      const { alice, bob, restored, groupId } = await removedBob(false);

      await expect(restored.syncGroup(groupId)).rejects.toBeInstanceOf(
        SecretUnavailableError,
      );
      await expect(restored.syncGroup(groupId)).rejects.toThrow(/not a member/);

      alice.close();
      bob.close();
      restored.close();
    });
  });
});
