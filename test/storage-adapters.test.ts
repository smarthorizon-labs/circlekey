/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * StorageAdapter contract suite, run
 * against both adapters. IndexedDB runs on
 * `fake-indexeddb` under vitest; the real-browser suite and
 * two-instance race tests live in test/browser/.
 */

import "fake-indexeddb/auto";

import { beforeEach, describe, expect, it } from "vitest";

import { IndexedDbStore } from "../src/adapters/storage/indexeddb";
import { MemoryStore } from "../src/adapters/storage/memory";
import { StorageError } from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import type { EncryptedRecord, WireTransition } from "../src/core/types";
import { wireStub } from "./helpers";
import type { StorageAdapter } from "../src/ports/storage";

let dbCounter = 0;
const freshDbName = () => `circlekey-test-${String(++dbCounter)}`;

function transitionStub(groupId: string, epoch: number): WireTransition {
  return wireStub(groupId, epoch);
}

function stateStub(groupId: string, epoch: number): GroupState {
  return {
    group_id: groupId,
    epoch,
    members: [{ user_id: "alice", device_pubkeys: ["devA"], is_manager: true }],
    policy: { min_managers: 1 },
    last_transition_hash: `hash-${String(epoch)}`,
  };
}

function recordStub(recordId: string, epoch: number): EncryptedRecord {
  return {
    record_id: recordId,
    epoch,
    ciphertext: "opaque",
    nonce: "nonce",
    suite: "gv1",
  };
}

function contract(name: string, open: () => Promise<StorageAdapter>) {
  describe(`StorageAdapter contract: ${name}`, () => {
    let store: StorageAdapter;
    beforeEach(async () => {
      store = await open();
    });

    it("round-trips the device identity", async () => {
      expect(await store.getIdentity()).toBeUndefined();
      const identity = {
        userId: "alice",
        identityPrivateKey: new Uint8Array(32).fill(0x11),
        backupEnrolled: false,
      };
      await store.putIdentity(identity);
      expect(await store.getIdentity()).toEqual(identity);

      await store.putIdentity({ ...identity, backupEnrolled: true });
      expect((await store.getIdentity())?.backupEnrolled).toBe(true);
    });

    it("stores transitions per group, ordered by epoch", async () => {
      await store.appendTransition(transitionStub("g1", 1));
      await store.appendTransition(transitionStub("g1", 0));
      await store.appendTransition(transitionStub("g1", 2));
      await store.appendTransition(transitionStub("g2", 0));

      const chain = await store.getTransitions("g1");
      expect(chain.map((t) => t.epoch)).toEqual([0, 1, 2]);
      expect(await store.getTransitions("g2")).toHaveLength(1);
      expect(await store.getTransitions("missing")).toEqual([]);
      expect((await store.listGroupIds()).sort()).toEqual(["g1", "g2"]);
    });

    it("is append-only: refuses to overwrite a stored epoch", async () => {
      await store.appendTransition(transitionStub("g1", 0));
      await expect(
        store.appendTransition({ ...transitionStub("g1", 0), sealed_body: "other" }),
      ).rejects.toBeInstanceOf(StorageError);
      // The original survives.
      const chain = await store.getTransitions("g1");
      expect(chain[0]?.sealed_body).toBe("sealed-0");
    });

    it("caches group state with defensive copies", async () => {
      expect(await store.getGroupState("g1")).toBeUndefined();
      const state = stateStub("g1", 3);
      await store.putGroupState(state);
      state.epoch = 99; // mutating the input must not affect the store

      const loaded = await store.getGroupState("g1");
      expect(loaded?.epoch).toBe(3);
      loaded?.members.push({ user_id: "eve", device_pubkeys: ["x"], is_manager: false });
      expect((await store.getGroupState("g1"))?.members).toHaveLength(1);
    });

    it("treats group secrets as write-once per epoch", async () => {
      const secret = new Uint8Array(32).fill(7);
      await store.putGroupSecret("g1", 0, secret);
      await store.putGroupSecret("g1", 0, new Uint8Array(32).fill(7)); // idempotent
      await expect(
        store.putGroupSecret("g1", 0, new Uint8Array(32).fill(8)),
      ).rejects.toBeInstanceOf(StorageError);

      expect(await store.getGroupSecret("g1", 0)).toEqual(secret);
      expect(await store.getGroupSecret("g1", 1)).toBeUndefined();

      await store.putGroupSecret("g1", 1, new Uint8Array(32).fill(9));
      const all = await store.getGroupSecrets("g1");
      expect([...all.keys()].sort()).toEqual([0, 1]);
      expect(all.get(1)).toEqual(new Uint8Array(32).fill(9));
    });

    it("increments usage counters atomically per (group, epoch)", async () => {
      expect(await store.incrementKeyUsage("g1", 0)).toBe(1);
      expect(await store.incrementKeyUsage("g1", 0)).toBe(2);
      expect(await store.incrementKeyUsage("g1", 1)).toBe(1);
      expect(await store.incrementKeyUsage("g2", 0)).toBe(1);

      // Concurrent increments must yield distinct, gap-free counts.
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.incrementKeyUsage("g1", 5)),
      );
      expect([...results].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });

    it("caches encrypted records per group, last write winning", async () => {
      const record = recordStub("doc-1", 3);
      expect(await store.getCachedRecord("g1", "doc-1")).toBeUndefined();

      await store.putCachedRecord("g1", record);
      expect(await store.getCachedRecord("g1", "doc-1")).toEqual(record);

      // Same id, newer epoch: replaces rather than duplicating.
      const updated = { ...record, epoch: 4, ciphertext: "newer" };
      await store.putCachedRecord("g1", updated);
      expect(await store.getCachedRecord("g1", "doc-1")).toEqual(updated);
      expect(await store.listCachedRecords("g1")).toHaveLength(1);
    });

    it("keeps caches separate per group and lists them", async () => {
      await store.putCachedRecord("g1", recordStub("a", 0));
      await store.putCachedRecord("g1", recordStub("b", 0));
      await store.putCachedRecord("g2", recordStub("c", 0));

      const g1 = await store.listCachedRecords("g1");
      expect(g1.map((r) => r.record_id).sort()).toEqual(["a", "b"]);
      expect(await store.listCachedRecords("g2")).toHaveLength(1);
      expect(await store.listCachedRecords("missing")).toEqual([]);
      // A record id in one group must not resolve in another.
      expect(await store.getCachedRecord("g2", "a")).toBeUndefined();
    });

    it("deletes a cached record without touching its neighbours", async () => {
      await store.putCachedRecord("g1", recordStub("a", 0));
      await store.putCachedRecord("g1", recordStub("b", 0));

      await store.deleteCachedRecord("g1", "a");
      expect(await store.getCachedRecord("g1", "a")).toBeUndefined();
      expect(await store.getCachedRecord("g1", "b")).toBeDefined();
      // Deleting something absent is a no-op, not an error.
      await expect(store.deleteCachedRecord("g1", "gone")).resolves.toBeUndefined();
    });

    it("returns cached records as copies", async () => {
      await store.putCachedRecord("g1", recordStub("a", 0));
      const first = await store.getCachedRecord("g1", "a");
      if (first) first.ciphertext = "mutated";
      expect((await store.getCachedRecord("g1", "a"))?.ciphertext).toBe("opaque");
    });

    it("clear() wipes every store", async () => {
      await store.putIdentity({
        userId: "alice",
        identityPrivateKey: new Uint8Array(32),
        backupEnrolled: true,
      });
      await store.appendTransition(transitionStub("g1", 0));
      await store.putGroupState(stateStub("g1", 0));
      await store.putGroupSecret("g1", 0, new Uint8Array(32));
      await store.incrementKeyUsage("g1", 0);
      await store.putCachedRecord("g1", recordStub("doc", 0));

      await store.clear();
      expect(await store.getIdentity()).toBeUndefined();
      expect(await store.getTransitions("g1")).toEqual([]);
      expect(await store.getGroupState("g1")).toBeUndefined();
      expect(await store.getGroupSecret("g1", 0)).toBeUndefined();
      expect(await store.incrementKeyUsage("g1", 0)).toBe(1);
      expect(await store.listCachedRecords("g1")).toEqual([]);
    });
  });
}

contract("MemoryStore", () => Promise.resolve(new MemoryStore()));
contract("IndexedDbStore (fake-indexeddb)", () => IndexedDbStore.open({ name: freshDbName() }));

describe("IndexedDbStore specifics", () => {
  it("persists across close and reopen", async () => {
    const name = freshDbName();
    const first = await IndexedDbStore.open({ name });
    await first.putIdentity({
      userId: "alice",
      identityPrivateKey: new Uint8Array(32).fill(0x2a),
      backupEnrolled: true,
    });
    await first.appendTransition(transitionStub("g1", 0));
    await first.putGroupSecret("g1", 0, new Uint8Array(32).fill(0x2b));
    await first.incrementKeyUsage("g1", 0);
    first.close();

    const second = await IndexedDbStore.open({ name });
    expect((await second.getIdentity())?.userId).toBe("alice");
    expect(await second.getTransitions("g1")).toHaveLength(1);
    expect(await second.getGroupSecret("g1", 0)).toEqual(new Uint8Array(32).fill(0x2b));
    expect(await second.incrementKeyUsage("g1", 0)).toBe(2); // counter survived
    second.close();
  });

  it("rejects when IndexedDB is unavailable", async () => {
    await expect(
      IndexedDbStore.open({ factory: undefined as unknown as IDBFactory, name: "x" }),
    ).resolves.toBeInstanceOf(IndexedDbStore); // undefined falls back to the global
    const saved = globalThis.indexedDB;
    try {
      Object.defineProperty(globalThis, "indexedDB", { value: undefined, configurable: true });
      await expect(IndexedDbStore.open({ name: "y" })).rejects.toBeInstanceOf(StorageError);
    } finally {
      Object.defineProperty(globalThis, "indexedDB", { value: saved, configurable: true });
    }
  });
});
