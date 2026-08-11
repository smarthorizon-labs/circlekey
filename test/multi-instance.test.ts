/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Two `GroupManager` instances over one storage — the in-process
 * model of two browser tabs on an origin.
 *
 * This is the shape that produced a real bug: an instance whose
 * in-memory view lagged shared storage re-fetched transitions its
 * sibling had already persisted and tripped the append-only guard.
 * Single-instance suites cannot reach it. The real-browser IndexedDB
 * version of these races lives in test/browser/; everything here runs in-process.
 *
 * Both instances deliberately share ONE `LockProvider`, because Web
 * Locks are origin-wide: giving each its own would model something
 * that cannot happen in a browser and would hide exactly the
 * serialization failures worth catching.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessHintChannel } from "../src/adapters/hints";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { KeyUsageExceededError } from "../src/core/errors";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { RecordCrypto } from "../src/core/record-crypto";
import { BackupManager } from "../src/managers/backup-manager";
import { GroupManager } from "../src/managers/group-manager";
import { SyncManager } from "../src/managers/sync-manager";
import { utf8Bytes } from "../src/core/bytes";
import type { LockProvider } from "../src/ports/locks";
import { completeBackupEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

interface Origin {
  storage: MemoryStore;
  locks: LockProvider;
  transport: MockTransport;
  keys: DeviceKeys;
  /** Build another "tab" against the same origin. */
  tab: (options?: { hints?: string }) => GroupManager;
}

/** One device + one storage, as several instances would share. */
async function makeOrigin(userId = "alice"): Promise<Origin> {
  const storage = new MemoryStore();
  const locks = new InProcessLockProvider();
  const transport = new MockTransport();
  const keys = await km.generateDeviceKeys();

  await storage.putIdentity({
    userId,
    identityPrivateKey: keys.identity.privateKey,
    backupEnrolled: false,
  });
  await completeBackupEnrollment(
    new BackupManager(crypto, storage, new SyncManager(transport), FAST_BACKUP),
  );

  return {
    storage,
    locks,
    transport,
    keys,
    tab: (options = {}) =>
      new GroupManager({
        crypto,
        storage,
        transport,
        locks,
        deviceKeys: keys,
        userId,
        ...(options.hints === undefined
          ? {}
          : { hints: new InProcessHintChannel(options.hints) }),
      }),
  };
}

describe("two instances over one storage", () => {
  let origin: Origin;

  beforeEach(async () => {
    origin = await makeOrigin();
  });

  it("a second instance picks up a group the first created", async () => {
    const tabA = origin.tab();
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;

    const tabB = origin.tab();
    const states = await tabB.start();
    expect(states.get(g)?.epoch).toBe(0);
    expect(await tabB.getCurrentSecret(g)).toBeDefined();

    tabA.close();
    tabB.close();
  });

  it("a lagging instance syncs without re-appending stored history", async () => {
    // The exact regression: tab B holds epoch 0 in memory while
    // storage has already moved to epoch 1.
    const tabA = origin.tab();
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
    const tabB = origin.tab();
    await tabB.start();

    await tabA.setPolicy(g, { min_managers: 1 });
    expect(tabB.getState(g)?.epoch).toBe(0); // stale, no hints wired

    await expect(tabB.syncGroup(g)).resolves.toMatchObject({ epoch: 1 });
    expect(await origin.storage.getTransitions(g)).toHaveLength(2);

    tabA.close();
    tabB.close();
  });

  it("concurrent syncs from both instances leave one clean chain", async () => {
    const tabA = origin.tab();
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
    const tabB = origin.tab();
    await tabB.start();
    await tabA.setPolicy(g, { min_managers: 1 });
    await tabA.setPolicy(g, { min_managers: 1 });

    const [a, b] = await Promise.all([tabA.syncGroup(g), tabB.syncGroup(g)]);
    expect(a).toEqual(b);
    // Epochs 0..2 stored exactly once each.
    const stored = await origin.storage.getTransitions(g);
    expect(stored.map((t) => t.epoch)).toEqual([0, 1, 2]);

    tabA.close();
    tabB.close();
  });

  it("concurrent governance ops serialize under the shared lock", async () => {
    const tabA = origin.tab();
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
    const tabB = origin.tab();
    await tabB.start();

    const bob = km.devicePublicKey(await km.generateDeviceKeys());
    const carol = km.devicePublicKey(await km.generateDeviceKeys());
    const [first, second] = await Promise.all([
      tabA.addMember(g, {
        user_id: "bob",
        device_pubkeys: [bob],
        is_manager: false,
      }),
      tabB.addMember(g, {
        user_id: "carol",
        device_pubkeys: [carol],
        is_manager: false,
      }),
    ]);

    // Both committed, at consecutive epochs — the lock serialized
    // them, so neither built against a stale head.
    expect([first.epoch, second.epoch].sort()).toEqual([1, 2]);
    const stored = await origin.storage.getTransitions(g);
    expect(stored.map((t) => t.epoch)).toEqual([0, 1, 2]);
    const final = await tabA.syncGroup(g);
    expect(final.members.map((m) => m.user_id).sort()).toEqual([
      "alice",
      "bob",
      "carol",
    ]);

    tabA.close();
    tabB.close();
  });

  it("secrets written by one instance are usable by the other", async () => {
    const tabA = origin.tab();
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
    const secretA = await tabA.getCurrentSecret(g);

    const tabB = origin.tab();
    await tabB.start();
    expect(await tabB.getCurrentSecret(g)).toEqual(secretA);

    // A record encrypted in one instance decrypts in the other.
    const recordsA = new RecordCrypto(crypto, origin.storage);
    const recordsB = new RecordCrypto(crypto, origin.storage);
    const record = await recordsA.encryptJsonRecord(
      g,
      0,
      secretA ?? new Uint8Array(32),
      "doc",
      { from: "tab A" },
    );
    expect(
      await recordsB.decryptJsonRecord(g, secretA ?? new Uint8Array(32), record),
    ).toEqual({ from: "tab A" });

    tabA.close();
    tabB.close();
  });

  it("a hint moves the sibling forward without it polling", async () => {
    const bus = `multi-${String(Math.random())}`;
    const tabA = origin.tab({ hints: bus });
    const tabB = origin.tab({ hints: bus });
    const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
    await tabB.start();

    await tabA.setPolicy(g, { min_managers: 1 });
    for (let i = 0; i < 100 && tabB.getState(g)?.epoch !== 1; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(tabB.getState(g)?.epoch).toBe(1);

    tabA.close();
    tabB.close();
  });
});

describe("shared key-usage counters (spec §6.1)", () => {
  it("the encryption bound is per (group, epoch), not per instance", async () => {
    // Two tabs encrypting under the same epoch must not each get a
    // full budget — that is how nonce usage would slip past the bound.
    const storage = new MemoryStore();
    const g = "usage-counter-fixture"; // keys the counter, not a real group
    const limit = 4;
    const tabA = new RecordCrypto(crypto, storage, { keyUsageLimit: limit });
    const tabB = new RecordCrypto(crypto, storage, { keyUsageLimit: limit });
    const secret = crypto.randomBytes(32);

    await tabA.encryptRecord(g, 0, secret, "a", utf8Bytes("1"));
    await tabB.encryptRecord(g, 0, secret, "b", utf8Bytes("2"));
    await tabA.encryptRecord(g, 0, secret, "c", utf8Bytes("3"));
    await tabB.encryptRecord(g, 0, secret, "d", utf8Bytes("4"));

    // Budget spent across both instances; either one must now refuse.
    await expect(
      tabA.encryptRecord(g, 0, secret, "e", utf8Bytes("5")),
    ).rejects.toBeInstanceOf(KeyUsageExceededError);
    await expect(
      tabB.encryptRecord(g, 0, secret, "f", utf8Bytes("6")),
    ).rejects.toBeInstanceOf(KeyUsageExceededError);
  });

  it("counts every concurrent encryption exactly once", async () => {
    const storage = new MemoryStore();
    const g = "usage-counter-fixture"; // keys the counter, not a real group
    const limit = 10;
    const tabA = new RecordCrypto(crypto, storage, { keyUsageLimit: limit });
    const tabB = new RecordCrypto(crypto, storage, { keyUsageLimit: limit });
    const secret = crypto.randomBytes(32);

    // Ten parallel encryptions across two instances must consume the
    // budget exactly — no lost update, no double count.
    const results = await Promise.allSettled(
      Array.from({ length: limit }, (_, i) =>
        (i % 2 === 0 ? tabA : tabB).encryptRecord(
          g,
          0,
          secret,
          `doc-${String(i)}`,
          utf8Bytes("x"),
        ),
      ),
    );
    expect(results.every((r) => r.status === "fulfilled")).toBe(true);

    await expect(
      tabA.encryptRecord(g, 0, secret, "one-too-many", utf8Bytes("x")),
    ).rejects.toBeInstanceOf(KeyUsageExceededError);
  });
});
