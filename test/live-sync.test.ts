/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Live sync (spec §10.3, §10.4).
 *
 * The properties under test are the ones §5.7 warned about: a pushed
 * transition must never become a second path into state, a sibling
 * tab's hint must cause a re-read rather than an apply, and conflict
 * retry must be bounded.
 */

import { describe, expect, it, vi } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessHintChannel } from "../src/adapters/hints";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { ConflictError } from "../src/core/errors";
import { KeyManager } from "../src/core/key-manager";
import { GroupManager } from "../src/managers/group-manager";
import type { WireTransition } from "../src/core/types";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

function vaultOptions(
  transport: Transport,
  userId: string,
  extra: Partial<Parameters<typeof GroupVault.open>[0]> = {},
) {
  return {
    transport,
    userId,
    crypto,
    storage: new MemoryStore(),
    locks: new InProcessLockProvider(),
    requestPersistentStorage: false,
    backup: FAST_BACKUP,
    ...extra,
  };
}

/**
 * Wrap a Transport with selective overrides. Delegation is explicit
 * rather than spread, because spreading a class instance drops its
 * prototype and would silently lose any method not re-listed.
 */
function wrapTransport(inner: Transport, overrides: Partial<Transport>): Transport {
  const subscribe = inner.subscribeToTransitions?.bind(inner);
  const base: Transport = {
    createGroup: (g) => inner.createGroup(g),
    getGroupState: (g) => inner.getGroupState(g),
    submitTransition: (g, t) => inner.submitTransition(g, t),
    getTransitions: (g, s) => inner.getTransitions(g, s),
    putRecord: (g, r) => inner.putRecord(g, r),
    getRecord: (g, r) => inner.getRecord(g, r),
    listRecords: (g, c) =>
      c === undefined ? inner.listRecords(g) : inner.listRecords(g, c),
    putBackupBlob: (u, b) => inner.putBackupBlob(u, b),
    getBackupBlob: (u) => inner.getBackupBlob(u),
    ...(subscribe === undefined ? {} : { subscribeToTransitions: subscribe }),
  };
  return { ...base, ...overrides };
}

/** Wait for a condition without sleeping on a fixed duration. */
async function until(predicate: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`timed out waiting for: ${label}`);
}

describe("conflict rebuild-and-retry (spec §10.4)", () => {
  it("two managers converge through concurrent transitions", async () => {
    const transport = new MockTransport();

    // A group with two managers, so both may legitimately act.
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await alice.promoteMember(g, "bob");
    await bob.syncGroup(g);
    expect(bob.getGroupState(g)?.epoch).toBe(2);

    // Both build against epoch 2 and submit together. One wins the
    // (group_id, epoch) race; the loser must rebuild, not fail.
    const carol = km.devicePublicKey(await km.generateDeviceKeys());
    const dave = km.devicePublicKey(await km.generateDeviceKeys());
    const [fromAlice, fromBob] = await Promise.all([
      alice.addMember(g, { userId: "carol", devicePubkey: carol }),
      bob.addMember(g, { userId: "dave", devicePubkey: dave }),
    ]);

    // Both landed, at consecutive epochs — neither was silently lost.
    expect([fromAlice.epoch, fromBob.epoch].sort()).toEqual([3, 4]);

    const aliceFinal = await alice.syncGroup(g);
    const bobFinal = await bob.syncGroup(g);
    expect(aliceFinal).toEqual(bobFinal);
    expect(aliceFinal.epoch).toBe(4);
    expect(aliceFinal.members.map((m) => m.user_id).sort()).toEqual([
      "alice",
      "bob",
      "carol",
      "dave",
    ]);
  });

  it("gives up with ConflictError once the retry bound is spent", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    await alice.createGroup({ min_managers: 1 });

    // A transport that always reports conflict: the client can never win.
    const alwaysConflict = wrapTransport(transport, {
      submitTransition: () =>
        Promise.resolve({ accepted: false as const, reason: "conflict" as const }),
    });

    const storage = new MemoryStore();
    const stubborn = await GroupVault.open(
      vaultOptions(transport, "alice", { storage }),
    );
    await completeEnrollment(stubborn);
    const h = (await stubborn.createGroup({ min_managers: 1 })).group_id;

    const manager = new GroupManager({
      crypto,
      storage,
      transport: alwaysConflict,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(
        (await storage.getIdentity())?.identityPrivateKey ?? new Uint8Array(32),
      ),
      userId: "alice",
      maxConflictAttempts: 2,
    });
    await manager.start();

    await expect(
      manager.setPolicy(h, { min_managers: 1 }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it("surfaces a rebuilt operation that has become invalid", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await alice.promoteMember(g, "bob");
    await bob.syncGroup(g);

    // Both try to remove carol, who only one of them can remove.
    const carol = km.devicePublicKey(await km.generateDeviceKeys());
    await alice.addMember(g, { userId: "carol", devicePubkey: carol });
    await bob.syncGroup(g);

    const results = await Promise.allSettled([
      alice.removeMember(g, "carol"),
      bob.removeMember(g, "carol"),
    ]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    // One removal commits; the other, rebuilt against a state where
    // carol is already gone, fails loudly rather than committing
    // something the caller did not ask for.
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);

    const final = await alice.syncGroup(g);
    expect(final.members.map((m) => m.user_id).sort()).toEqual(["alice", "bob"]);
    expect(await bob.syncGroup(g)).toEqual(final);
  });
});

describe("backend push subscriptions (spec §10.3)", () => {
  it("treats a push as a hint and converges without polling", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await bob.syncGroup(g);

    const stop = bob.watchGroup(g);
    expect(stop).toBeDefined();

    // Alice acts; bob never calls syncGroup himself.
    await alice.setPolicy(g, { min_managers: 1 });
    await until(() => bob.getGroupState(g)?.epoch === 2, "bob to observe epoch 2");

    expect(bob.getGroupState(g)).toEqual(alice.getGroupState(g));
    stop?.();

    // After unsubscribing, pushes no longer drive bob forward.
    await alice.setPolicy(g, { min_managers: 1 });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(bob.getGroupState(g)?.epoch).toBe(2);
    bob.close();
    alice.close();
  });

  it("never applies the pushed payload — a forged push cannot move state", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    await alice.createGroup({ min_managers: 1 });

    // A transport that pushes a bogus transition on demand.
    let push: ((t: WireTransition) => void) | undefined;
    const pushy = wrapTransport(transport, {
      subscribeToTransitions: (_groupId, onTransition) => {
        push = onTransition;
        return () => {
          push = undefined;
        };
      },
    });

    const storage = new MemoryStore();
    const seeded = await GroupVault.open(vaultOptions(transport, "mallory", { storage }));
    await completeEnrollment(seeded);
    const m = (await seeded.createGroup({ min_managers: 1 })).group_id;
    const before = seeded.getGroupState(m);

    const manager = new GroupManager({
      crypto,
      storage,
      transport: pushy,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(
        (await storage.getIdentity())?.identityPrivateKey ?? new Uint8Array(32),
      ),
      userId: "mallory",
    });
    await manager.start();
    manager.watchGroup(m);
    expect(push).toBeDefined();

    // Push a transition claiming a wild epoch and a forged member set.
    push?.({
      group_id: m,
      epoch: 99,
      sealed_body: "A".repeat(86),
      secret_envelopes: [],
      auth_pubkey: "A".repeat(43),
    });
    await new Promise((resolve) => setTimeout(resolve, 30));

    // The payload was discarded; state is whatever the real chain says.
    expect(manager.getState(m)?.epoch).toBe(before?.epoch);
    expect(manager.getState(m)?.members.map((m) => m.user_id)).toEqual(["mallory"]);
    manager.close();
  });
});

describe("cross-tab hints", () => {
  it("a sibling tab re-reads verified state instead of trusting the hint", async () => {
    const transport = new MockTransport();
    const storage = new MemoryStore();
    const bus = `test-${String(Math.random())}`;

    // Two "tabs": separate managers over ONE shared storage, as tabs
    // on an origin share one IndexedDB.
    const tabA = await GroupVault.open(
      vaultOptions(transport, "alice", {
        storage,
        hints: new InProcessHintChannel(bus),
      }),
    );
    await completeEnrollment(tabA);
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;

    const identity = await storage.getIdentity();
    const tabB = new GroupManager({
      crypto,
      storage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(
        identity?.identityPrivateKey ?? new Uint8Array(32),
      ),
      userId: "alice",
      hints: new InProcessHintChannel(bus),
    });
    await tabB.start();
    expect(tabB.getState(g)?.epoch).toBe(0);

    // Tab A advances the group. Tab B is told only *that* g changed.
    await tabA.setPolicy(g, { min_managers: 1 });
    await until(() => tabB.getState(g)?.epoch === 1, "tab B to adopt epoch 1");

    // What it adopted is the verified fold tab A persisted.
    expect(tabB.getState(g)).toEqual(await storage.getGroupState(g));
    tabB.close();
    tabA.close();
  });

  it("never regresses on a stale hint", async () => {
    const transport = new MockTransport();
    const storage = new MemoryStore();
    const vault = await GroupVault.open(vaultOptions(transport, "alice", { storage }));
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;
    await vault.setPolicy(g, { min_managers: 1 });

    const manager = new GroupManager({
      crypto,
      storage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(
        (await storage.getIdentity())?.identityPrivateKey ?? new Uint8Array(32),
      ),
      userId: "alice",
    });
    await manager.start();
    expect(manager.getState(g)?.epoch).toBe(1);

    // A stale cache entry must not drag a further-ahead tab backwards.
    const stored = await storage.getGroupState(g);
    if (stored) await storage.putGroupState({ ...stored, epoch: 0 });
    expect((await manager.refreshFromStorage(g))?.epoch).toBe(1);

    manager.close();
    vault.close();
  });

  it("syncs correctly when a sibling already persisted the transition", async () => {
    // The hazard the fix above addresses: correctness cannot depend on
    // a hint arriving, so a tab whose in-memory view is behind storage
    // must still sync cleanly rather than re-appending stored history.
    const transport = new MockTransport();
    const storage = new MemoryStore();
    const vault = await GroupVault.open(vaultOptions(transport, "alice", { storage }));
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;

    const identity = await storage.getIdentity();
    const sibling = new GroupManager({
      crypto,
      storage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(
        identity?.identityPrivateKey ?? new Uint8Array(32),
      ),
      userId: "alice",
      // No hint channel at all — the pessimistic case.
    });
    await sibling.start();

    // The first tab advances; the sibling is told nothing.
    await vault.setPolicy(g, { min_managers: 1 });
    expect(sibling.getState(g)?.epoch).toBe(0); // still behind

    // Syncing must reconcile with storage, not re-append its history.
    await expect(sibling.syncGroup(g)).resolves.toMatchObject({ epoch: 1 });
    sibling.close();
    vault.close();
  });

  it("hint delivery failure costs latency, not correctness", async () => {
    const transport = new MockTransport();
    const publish = vi.fn(() => {
      throw new Error("channel closed");
    });
    const broken = { publish, subscribe: () => () => undefined, close: () => undefined };
    const vault = await GroupVault.open(
      vaultOptions(transport, "alice", { hints: broken }),
    );
    await completeEnrollment(vault);

    // Every state-advancing path announces, and every announcement
    // here throws. None of them may fail the operation.
    const created = await vault.createGroup({ min_managers: 1 });
    expect(created).toMatchObject({ epoch: 0 });
    const g = created.group_id;
    await expect(
      vault.setPolicy(g, { min_managers: 1 }),
    ).resolves.toMatchObject({ epoch: 1 });
    await expect(vault.syncGroup(g)).resolves.toMatchObject({ epoch: 1 });

    // The failures were real, not skipped.
    expect(publish.mock.calls.length).toBeGreaterThanOrEqual(2);
    vault.close();
  });
});
