/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Recovery crossed with everything else.
 *
 * `restore()` is the one path that puts state into storage from
 * somewhere other than the verified chain, which makes it the natural
 * place for assumptions elsewhere to stop holding. That is exactly how
 * the `refreshBackup()` defect arose: `restore` had tests, `refresh`
 * had tests, and their *interaction* had none.
 *
 * A per-feature suite hides combinations by construction, so this file
 * is organized the other way round — one describe per pairing of
 * recovery with another subsystem. Each case asserts the premise it
 * depends on before asserting behaviour, so a passing test still says
 * what it covers rather than silently drifting into a no-op.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();

function options(
  transport: Transport,
  userId: string,
  storage: MemoryStore = new MemoryStore(),
  locks = new InProcessLockProvider(),
) {
  return {
    transport,
    userId,
    crypto,
    storage,
    locks,
    requestPersistentStorage: false,
    backup: FAST_BACKUP,
  };
}

/** Alice, enrolled, owning a group with bob in it (epoch 1). */
async function groupWithBob(transport: Transport) {
  const alice = await GroupVault.open(options(transport, "alice"));
  const credential = await completeEnrollment(alice);
  const { group_id: groupId } = await alice.createGroup({ min_managers: 1 });

  const bob = await GroupVault.open(options(transport, "bob"));
  const bobCredential = await completeEnrollment(bob);
  await alice.addMember(groupId, {
    userId: "bob",
    devicePubkey: bob.devicePublicKey(),
    isManager: false,
  });
  await bob.syncGroup(groupId);
  return { alice, credential, bob, bobCredential, groupId };
}

describe("restore × device linking", () => {
  it("recovers a second device from its own credential", async () => {
    const transport = new MockTransport();
    const { alice, groupId } = await groupWithBob(transport);

    const phone = await GroupVault.open(options(transport, "alice"));
    const phonePubkey = phone.devicePublicKey();
    await alice.linkDevice(phonePubkey);
    const phoneCredential = await completeEnrollment(phone);
    await phone.syncGroup(groupId);
    await phone.refreshBackup(phoneCredential);

    // Premise: the phone is a distinct device inside the member set.
    expect(phonePubkey).not.toBe(alice.devicePublicKey());
    expect(alice.devicesOf(groupId, "alice")).toContain(phonePubkey);

    const restored = await GroupVault.restore({
      ...options(transport, "alice"),
      credential: phoneCredential,
    });
    expect(restored.devicePublicKey()).toBe(phonePubkey);
    expect((await restored.syncGroup(groupId)).epoch).toBe(2);

    alice.close();
    phone.close();
    restored.close();
  });

  it("recovers the first device after a second was linked to it", async () => {
    // The laptop's blob predates the `add_device` transition, so its
    // snapshot stops one epoch short of the head.
    const transport = new MockTransport();
    const { alice, credential, groupId } = await groupWithBob(transport);
    await alice.refreshBackup(credential);

    const phone = await GroupVault.open(options(transport, "alice"));
    await alice.linkDevice(phone.devicePublicKey());

    const store = new MemoryStore();
    const restored = await GroupVault.restore({
      ...options(transport, "alice", store),
      credential,
    });
    // Premise: the blob is stale — it has no secret for the head epoch.
    expect([...(await store.getGroupSecrets(groupId)).keys()]).toEqual([0, 1]);

    expect((await restored.syncGroup(groupId)).epoch).toBe(2);

    alice.close();
    phone.close();
    restored.close();
  });
});

describe("restore × groups created after the blob", () => {
  it("recovers a group the snapshot never knew about", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(options(transport, "alice"));
    const credential = await completeEnrollment(alice);

    // Both groups run past genesis on purpose. A single-epoch group
    // takes the walk's `epoch === 0` early break before storage is
    // consulted at all, so it would pass this test without exercising
    // the boundary the pairing exists to cross.
    const { group_id: first } = await alice.createGroup({ min_managers: 1 });
    await alice.setPolicy(first, { min_managers: 1 });
    await alice.refreshBackup(credential); // snapshot covers `first` only

    const { group_id: second } = await alice.createGroup({ min_managers: 1 });
    await alice.setPolicy(second, { min_managers: 1 });

    const store = new MemoryStore();
    const restored = await GroupVault.restore({
      ...options(transport, "alice", store),
      credential,
    });
    // Premise: one group in the snapshot, one entirely absent — the
    // two paths this test exists to cross — and the first is deep
    // enough to reach the stored-secret boundary.
    expect([...(await store.getGroupSecrets(first)).keys()]).toEqual([0, 1]);
    expect((await store.getGroupSecrets(second)).size).toBe(0);

    expect((await restored.syncGroup(first)).epoch).toBe(1);
    expect((await restored.syncGroup(second)).epoch).toBe(1);

    alice.close();
    restored.close();
  });
});

describe("restore × removal and re-adding", () => {
  it("recovers a device removed and then re-added", async () => {
    const transport = new MockTransport();
    const { alice, bob, bobCredential, groupId } = await groupWithBob(transport);
    await bob.refreshBackup(bobCredential);

    await alice.removeMember(groupId, "bob"); // epoch 2
    await alice.addMember(groupId, {
      userId: "bob",
      devicePubkey: bob.devicePublicKey(),
      isManager: false,
    }); // epoch 3

    // Premise: same device key, back in the member set at the head.
    const head = alice.getGroupState(groupId);
    expect(head?.epoch).toBe(3);
    expect(head?.members.map((m) => m.user_id)).toContain("bob");

    const restored = await GroupVault.restore({
      ...options(transport, "bob"),
      credential: bobCredential,
    });
    expect((await restored.syncGroup(groupId)).epoch).toBe(3);

    alice.close();
    bob.close();
    restored.close();
  });
});

describe("restore × two instances on one database", () => {
  it("converges when both sync the restored store concurrently", async () => {
    const transport = new MockTransport();
    const { alice, credential, groupId } = await groupWithBob(transport);
    await alice.refreshBackup(credential);

    // One store and one lock provider: two tabs of the same restored
    // browser profile. Per-instance locks would model something that
    // cannot happen on an origin.
    const store = new MemoryStore();
    const locks = new InProcessLockProvider();
    const tabA = await GroupVault.restore({
      ...options(transport, "alice", store, locks),
      credential,
    });
    const tabB = await GroupVault.open(options(transport, "alice", store, locks));

    // Premise: two live instances over one store.
    expect(tabA.devicePublicKey()).toBe(tabB.devicePublicKey());

    const [a, b] = await Promise.all([
      tabA.syncGroup(groupId),
      tabB.syncGroup(groupId),
    ]);
    expect(a.epoch).toBe(1);
    expect(b.epoch).toBe(1);
    expect(await store.getTransitions(groupId)).toHaveLength(2);

    alice.close();
    tabA.close();
    tabB.close();
  });
});

describe("restore × the blob's own KDF", () => {
  it("restores a PBKDF2 blob on a provider that prefers Argon2id", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open({
      ...options(transport, "alice"),
      backup: { ...FAST_BACKUP, kdf: "pbkdf2-sha256" },
    });
    const credential = await completeEnrollment(alice);
    const { group_id: groupId } = await alice.createGroup({ min_managers: 1 });
    await alice.setPolicy(groupId, { min_managers: 1 }); // past genesis
    await alice.refreshBackup(credential);

    // Restore with the default options — Argon2id for *new* blobs. The
    // blob records its own KDF and restore must honor that, not the
    // local preference.
    const restored = await GroupVault.restore({
      ...options(transport, "alice"),
      credential,
    });
    expect((await restored.syncGroup(groupId)).epoch).toBe(1);

    alice.close();
    restored.close();
  });

  it("survives a refresh that re-seals the blob under a different KDF", async () => {
    const transport = new MockTransport();
    const store = new MemoryStore();
    const alice = await GroupVault.open({
      ...options(transport, "alice", store),
      backup: { ...FAST_BACKUP, kdf: "pbkdf2-sha256" },
    });
    const credential = await completeEnrollment(alice);
    const { group_id: groupId } = await alice.createGroup({ min_managers: 1 });
    await alice.setPolicy(groupId, { min_managers: 1 }); // past genesis

    // The same device and credential, reopened on a build that prefers
    // Argon2id, re-sealing the blob it can already open.
    const upgraded = await GroupVault.open({
      ...options(transport, "alice", store),
      backup: FAST_BACKUP,
    });
    await upgraded.refreshBackup(credential);

    const restored = await GroupVault.restore({
      ...options(transport, "alice"),
      credential,
    });
    expect((await restored.syncGroup(groupId)).epoch).toBe(1);

    alice.close();
    upgraded.close();
    restored.close();
  });
});
