/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * CircleKey real-browser suite.
 *
 * Everything else in `test/` runs in Node, where `WebLocksProvider`,
 * `BroadcastChannelHints` and real IndexedDB simply do not exist —
 * their Node tests assert only that they refuse to construct. The
 * claims about them are therefore unverifiable there,
 * and the most important of them is security-relevant: IndexedDB is
 * said to serialize `readwrite` transactions across connections, and
 * that is what stops two tabs from double-spending the AES-GCM nonce
 * budget (spec §6.1). `fake-indexeddb` is a JS reimplementation whose
 * scheduling need not match a real browser's, so only this suite can
 * settle it.
 *
 * Plain ESM against built `dist/`, no bundler and no test framework —
 * see `index.html`.
 */

import { WebCryptoProvider } from "../../dist/adapters/webcrypto.js";
import { IndexedDbStore } from "../../dist/adapters/indexeddb.js";
import {
  InProcessLockProvider,
  WebLocksProvider,
} from "../../dist/adapters/locks.js";
import { BroadcastChannelHints } from "../../dist/adapters/hints.js";
import {
  BackupManager,
  GroupManager,
  KeyManager,
  RecordCrypto,
  SyncManager,
} from "../../dist/index.js";
import { MockTransport } from "../../dist/testing.js";

// --- tiny assertion helpers -------------------------------------------------

class AssertionError extends Error {}

export function assert(condition, message) {
  if (!condition) throw new AssertionError(message);
}

export function assertEqual(actual, expected, message) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) {
    throw new AssertionError(`${message}\n  expected: ${b}\n  actual:   ${a}`);
  }
}

export async function assertRejects(promise, message) {
  try {
    await promise;
  } catch {
    return;
  }
  throw new AssertionError(`${message} (expected a rejection, got success)`);
}

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

/**
 * A plain string key for the storage-level cases, which exercise
 * IndexedDB directly and never create a group. The two multi-tab cases
 * that *do* create one shadow this with the real generated id, since
 * `createGroup` no longer takes one (spec §6.5).
 */
const g = "browser-storage-fixture";

/**
 * Backup parameters for this page. Deliberately trivial: the KDF is
 * not what these cases test, and the real spec §6.2 costs would make
 * an interactive page feel hung. `backup.test.ts` covers both KDFs at
 * their real parameters in Node.
 */
const FAST_BACKUP = { kdf: "pbkdf2-sha256", kdfIterations: 1 };

let dbCounter = 0;
const freshDbName = () => `circlekey-b4-${String(Date.now())}-${String(++dbCounter)}`;

/** Open N independent connections to one database — i.e. N "tabs". */
async function openConnections(name, count) {
  const stores = [];
  for (let i = 0; i < count; i++) {
    stores.push(await IndexedDbStore.open({ name }));
  }
  return stores;
}

// --- the suite --------------------------------------------------------------

export const tests = [
  // =========================================================================
  // 1. The security claim: counter atomicity across real connections.
  // =========================================================================
  {
    name: "usage counter: concurrent increments across two connections are gap-free",
    async run() {
      const name = freshDbName();
      const [tabA, tabB] = await openConnections(name, 2);
      try {
        const perTab = 25;
        const results = await Promise.all([
          ...Array.from({ length: perTab }, () => tabA.incrementKeyUsage(g, 0)),
          ...Array.from({ length: perTab }, () => tabB.incrementKeyUsage(g, 0)),
        ]);
        const sorted = [...results].sort((x, y) => x - y);
        const expected = Array.from({ length: perTab * 2 }, (_, i) => i + 1);
        assertEqual(
          sorted,
          expected,
          "every increment must return a distinct, gap-free count — a repeat " +
            "means two tabs spent the same nonce budget slot",
        );
      } finally {
        tabA.close();
        tabB.close();
      }
    },
  },
  {
    name: "usage counter: independent per (group, epoch)",
    async run() {
      const name = freshDbName();
      const [store] = await openConnections(name, 1);
      try {
        assertEqual(await store.incrementKeyUsage(g, 0), 1, "first g/0");
        assertEqual(await store.incrementKeyUsage(g, 0), 2, "second g/0");
        assertEqual(await store.incrementKeyUsage(g, 1), 1, "g/1 is separate");
        assertEqual(await store.incrementKeyUsage("h", 0), 1, "h/0 is separate");
      } finally {
        store.close();
      }
    },
  },
  {
    name: "usage bound holds across two RecordCrypto instances on one database",
    async run() {
      const name = freshDbName();
      const [tabA, tabB] = await openConnections(name, 2);
      try {
        const limit = 6;
        const recordsA = new RecordCrypto(crypto, tabA, { keyUsageLimit: limit });
        const recordsB = new RecordCrypto(crypto, tabB, { keyUsageLimit: limit });
        const secret = crypto.randomBytes(32);
        const encoder = new TextEncoder();

        for (let i = 0; i < limit; i++) {
          const target = i % 2 === 0 ? recordsA : recordsB;
          await target.encryptRecord(g, 0, secret, `doc-${i}`, encoder.encode("x"));
        }
        // Budget is shared, so BOTH tabs must now refuse.
        await assertRejects(
          recordsA.encryptRecord(g, 0, secret, "over-a", encoder.encode("x")),
          "tab A must refuse past the shared bound",
        );
        await assertRejects(
          recordsB.encryptRecord(g, 0, secret, "over-b", encoder.encode("x")),
          "tab B must refuse past the shared bound",
        );
      } finally {
        tabA.close();
        tabB.close();
      }
    },
  },

  // =========================================================================
  // 2. Web Locks: the positive path Node cannot reach.
  // =========================================================================
  {
    name: "Web Locks: constructs in a real browser",
    async run() {
      const provider = new WebLocksProvider();
      const result = await provider.withLock("circlekey/test/smoke", () =>
        Promise.resolve("ran"),
      );
      assertEqual(result, "ran", "withLock must return its callback's value");
    },
  },
  {
    name: "Web Locks: serialize two independent providers (origin-wide)",
    async run() {
      // Two providers stand in for two tabs. Web Locks are origin-wide,
      // so they must exclude each other — this is precisely what an
      // in-process mutex could never demonstrate.
      const a = new WebLocksProvider();
      const b = new WebLocksProvider();
      const lock = `circlekey/test/excl-${String(Date.now())}`;
      const events = [];
      let releaseFirst;
      const gate = new Promise((resolve) => {
        releaseFirst = resolve;
      });

      const first = a.withLock(lock, async () => {
        events.push("A-enter");
        await gate;
        events.push("A-exit");
      });
      // Give A time to actually acquire before B requests.
      await new Promise((resolve) => setTimeout(resolve, 20));
      const second = b.withLock(lock, () => {
        events.push("B-enter");
        return Promise.resolve();
      });

      await new Promise((resolve) => setTimeout(resolve, 20));
      assertEqual(events, ["A-enter"], "B must be blocked while A holds the lock");

      releaseFirst();
      await Promise.all([first, second]);
      assertEqual(
        events,
        ["A-enter", "A-exit", "B-enter"],
        "B must only enter after A released",
      );
    },
  },
  {
    name: "Web Locks: released when the holder throws",
    async run() {
      const provider = new WebLocksProvider();
      const lock = `circlekey/test/throw-${String(Date.now())}`;
      await assertRejects(
        provider.withLock(lock, () => Promise.reject(new Error("boom"))),
        "the rejection must propagate",
      );
      const after = await provider.withLock(lock, () => Promise.resolve("ok"));
      assertEqual(after, "ok", "lock must be reusable after a throwing holder");
    },
  },
  {
    name: "Web Locks: no lost updates under contention",
    async run() {
      const lock = `circlekey/test/counter-${String(Date.now())}`;
      let counter = 0;
      const providers = [new WebLocksProvider(), new WebLocksProvider()];
      await Promise.all(
        Array.from({ length: 30 }, (_, i) =>
          providers[i % 2].withLock(lock, async () => {
            const read = counter;
            await new Promise((resolve) => setTimeout(resolve, 0));
            counter = read + 1;
          }),
        ),
      );
      assertEqual(counter, 30, "every critical section must observe the last write");
    },
  },

  // =========================================================================
  // 3. BroadcastChannel.
  // =========================================================================
  {
    name: "BroadcastChannel: delivers to a sibling, never to itself",
    async run() {
      const bus = `circlekey/test/hints-${String(Date.now())}`;
      const sender = new BroadcastChannelHints(bus);
      const receiver = new BroadcastChannelHints(bus);
      const received = [];
      const selfReceived = [];
      const offReceiver = receiver.subscribe((hint) => {
        received.push(hint.groupId);
      });
      const offSender = sender.subscribe((hint) => {
        selfReceived.push(hint.groupId);
      });

      try {
        sender.publish({ groupId: "g-1" });
        for (let i = 0; i < 100 && received.length === 0; i++) {
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        assertEqual(received, ["g-1"], "the sibling must receive the hint");
        assertEqual(
          selfReceived,
          [],
          "BroadcastChannel must not loop a message back to its sender",
        );
      } finally {
        offReceiver();
        offSender();
        sender.close();
        receiver.close();
      }
    },
  },
  {
    name: "BroadcastChannel: unsubscribe stops delivery",
    async run() {
      const bus = `circlekey/test/hints-off-${String(Date.now())}`;
      const sender = new BroadcastChannelHints(bus);
      const receiver = new BroadcastChannelHints(bus);
      const received = [];
      const off = receiver.subscribe((hint) => {
        received.push(hint.groupId);
      });
      off();
      try {
        sender.publish({ groupId: "g-1" });
        await new Promise((resolve) => setTimeout(resolve, 40));
        assertEqual(received, [], "no delivery after unsubscribe");
      } finally {
        sender.close();
        receiver.close();
      }
    },
  },

  // =========================================================================
  // 4. IndexedDbStore contract against real IndexedDB.
  // =========================================================================
  {
    name: "IndexedDB: transition history is append-only",
    async run() {
      const name = freshDbName();
      const [store] = await openConnections(name, 1);
      try {
        // The body is sealed, so a store sees
        // opaque blobs and nothing about the group (spec §6.5).
        const transition = {
          group_id: g,
          epoch: 0,
          sealed_body: "sealed",
          secret_envelopes: ["opaque"],
          auth_pubkey: "auth",
        };
        await store.appendTransition(transition);
        await assertRejects(
          store.appendTransition({ ...transition, sealed_body: "other" }),
          "a duplicate (group_id, epoch) must be refused by the real ConstraintError",
        );
        const stored = await store.getTransitions(g);
        assertEqual(stored.length, 1, "the original survives");
        assertEqual(stored[0].sealed_body, "sealed", "the original is unmodified");
      } finally {
        store.close();
      }
    },
  },
  {
    name: "IndexedDB: group secrets are write-once per epoch",
    async run() {
      const name = freshDbName();
      const [store] = await openConnections(name, 1);
      try {
        const secret = new Uint8Array(32).fill(7);
        await store.putGroupSecret(g, 0, secret);
        await store.putGroupSecret(g, 0, new Uint8Array(32).fill(7)); // idempotent
        await assertRejects(
          store.putGroupSecret(g, 0, new Uint8Array(32).fill(8)),
          "a conflicting secret must be refused",
        );
        const loaded = await store.getGroupSecret(g, 0);
        assertEqual(Array.from(loaded), Array.from(secret), "original secret intact");
      } finally {
        store.close();
      }
    },
  },
  {
    name: "IndexedDB: data survives close and reopen",
    async run() {
      const name = freshDbName();
      const first = await IndexedDbStore.open({ name });
      await first.putIdentity({
        userId: "alice",
        identityPrivateKey: new Uint8Array(32).fill(0x2a),
        backupEnrolled: true,
      });
      await first.incrementKeyUsage(g, 0);
      first.close();

      const second = await IndexedDbStore.open({ name });
      try {
        const identity = await second.getIdentity();
        assertEqual(identity.userId, "alice", "identity survives");
        assertEqual(identity.backupEnrolled, true, "enrollment flag survives");
        assertEqual(
          await second.incrementKeyUsage(g, 0),
          2,
          "the usage counter continues rather than restarting",
        );
      } finally {
        second.close();
      }
    },
  },
  {
    name: "IndexedDB: records_meta round-trips with string keys",
    async run() {
      // The offline cache keys on [group_id, record_id] — a STRING
      // second component, unlike every other compound-keyed store.
      const name = freshDbName();
      const [store] = await openConnections(name, 1);
      try {
        const record = {
          record_id: "doc-1",
          epoch: 0,
          ciphertext: "opaque",
          nonce: "nonce",
          suite: "gv1",
        };
        await store.putCachedRecord(g, record);
        await store.putCachedRecord(g, { ...record, record_id: "doc-2" });
        await store.putCachedRecord("other", { ...record, record_id: "doc-3" });

        const one = await store.getCachedRecord(g, "doc-1");
        assertEqual(one.ciphertext, "opaque", "cached record round-trips");

        const listed = await store.listCachedRecords(g);
        assertEqual(
          listed.map((r) => r.record_id).sort(),
          ["doc-1", "doc-2"],
          "listing must span string keys and stay scoped to the group",
        );

        await store.deleteCachedRecord(g, "doc-1");
        assertEqual(
          await store.getCachedRecord(g, "doc-1"),
          undefined,
          "deleted record is gone",
        );
        assertEqual((await store.listCachedRecords(g)).length, 1, "neighbour kept");
      } finally {
        store.close();
      }
    },
  },
  {
    name: "IndexedDB: a v2 database upgrades to v3, dropping group data but keeping identity",
    async run() {
      const name = freshDbName();
      // Recreate a pre-C database by hand: version 2, six stores, with
      // an identity and a stored transition in the old wire shape.
      await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 2);
        request.onupgradeneeded = () => {
          const db = request.result;
          for (const store of [
            "identity",
            "transitions",
            "groups",
            "secrets",
            "key_usage",
            "records_meta",
          ]) {
            if (!db.objectStoreNames.contains(store)) db.createObjectStore(store);
          }
        };
        request.onsuccess = () => {
          const db = request.result;
          const tx = db.transaction(["identity", "transitions"], "readwrite");
          tx.objectStore("identity").put(
            {
              userId: "legacy-user",
              identityPrivateKey: new Uint8Array(32).fill(9),
              backupEnrolled: true,
            },
            "device",
          );
          // Pre-C shape: plaintext members, no sealed_body. This is
          // exactly what cannot be verified by the current code.
          tx.objectStore("transitions").put(
            {
              group_id: "legacy-group",
              epoch: 0,
              action: "create",
              members: [{ user_id: "legacy-user", device_pubkeys: ["d"], is_manager: true }],
              signature: "sig",
            },
            ["legacy-group", 0],
          );
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => reject(tx.error);
        };
        request.onerror = () => reject(request.error);
      });

      // Now open with the current code, which requests version 3.
      const store = await IndexedDbStore.open({ name });
      try {
        const identity = await store.getIdentity();
        assert(
          identity !== undefined && identity.userId === "legacy-user",
          "the v3 upgrade must preserve identity — dropping it would turn a " +
            "resync into an involuntary lost device needing the backup " +
            "credential (spec §9.6)",
        );

        // ...and the unverifiable group data must be gone, not merely
        // ignored. Keeping it would fail replay at every startup.
        assertEqual(
          (await store.getTransitions("legacy-group")).length,
          0,
          "pre-C transitions have no sealed body and cannot be verified, so " +
            "the upgrade drops them (spec §6.5)",
        );
        assertEqual(
          (await store.listGroupIds()).length,
          0,
          "no group survives the wire-format change",
        );

        // The recreated stores must work.
        await store.appendTransition({
          group_id: "fresh",
          epoch: 0,
          sealed_body: "sealed",
          secret_envelopes: ["opaque"],
          auth_pubkey: "auth",
        });
        assertEqual(
          (await store.getTransitions("fresh")).length,
          1,
          "the recreated transitions store is usable after the upgrade",
        );
        await store.putCachedRecord(g, {
          record_id: "doc",
          epoch: 0,
          ciphertext: "c",
          nonce: "n",
          suite: "gv1",
        });
        assertEqual(
          (await store.listCachedRecords(g)).length,
          1,
          "records_meta is usable after the upgrade",
        );
      } finally {
        store.close();
      }
    },
  },

  // =========================================================================
  // 5. The full two-tab stack with real adapters.
  // =========================================================================
  {
    name: "two tabs: concurrent governance serializes into one clean chain",
    async run() {
      const name = freshDbName();
      const transport = new MockTransport();
      const [storageA, storageB] = await openConnections(name, 2);
      const bus = `circlekey/test/tabs-${String(Date.now())}`;
      const keys = await km.generateDeviceKeys();

      await storageA.putIdentity({
        userId: "alice",
        identityPrivateKey: keys.identity.privateKey,
        backupEnrolled: true, // enrollment itself is covered in Node
      });

      const makeTab = (storage) =>
        new GroupManager({
          crypto,
          storage,
          transport,
          locks: new WebLocksProvider(),
          hints: new BroadcastChannelHints(bus),
          deviceKeys: keys,
          userId: "alice",
        });

      const tabA = makeTab(storageA);
      const tabB = makeTab(storageB);
      try {
        const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
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

        assertEqual(
          [first.epoch, second.epoch].sort(),
          [1, 2],
          "the origin-wide lock must serialize the two tabs onto consecutive epochs",
        );
        const stored = await storageA.getTransitions(g);
        assertEqual(
          stored.map((t) => t.epoch),
          [0, 1, 2],
          "each epoch is stored exactly once",
        );
        const final = await tabA.syncGroup(g);
        assertEqual(
          final.members.map((m) => m.user_id).sort(),
          ["alice", "bob", "carol"],
          "both members landed",
        );
      } finally {
        tabA.close();
        tabB.close();
        storageA.close();
        storageB.close();
      }
    },
  },
  {
    name: "two tabs: a hint moves the sibling forward",
    async run() {
      const name = freshDbName();
      const transport = new MockTransport();
      const [storageA, storageB] = await openConnections(name, 2);
      const bus = `circlekey/test/hintmove-${String(Date.now())}`;
      const keys = await km.generateDeviceKeys();
      await storageA.putIdentity({
        userId: "alice",
        identityPrivateKey: keys.identity.privateKey,
        backupEnrolled: true,
      });

      const makeTab = (storage) =>
        new GroupManager({
          crypto,
          storage,
          transport,
          locks: new WebLocksProvider(),
          hints: new BroadcastChannelHints(bus),
          deviceKeys: keys,
          userId: "alice",
        });

      const tabA = makeTab(storageA);
      const tabB = makeTab(storageB);
      try {
        const g = (await tabA.createGroup({ min_managers: 1 })).group_id;
        await tabB.start();
        await tabA.setPolicy(g, { min_managers: 1 });

        for (let i = 0; i < 200 && tabB.getState(g)?.epoch !== 1; i++) {
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        assertEqual(
          tabB.getState(g)?.epoch,
          1,
          "the sibling must adopt the verified state its peer persisted",
        );
      } finally {
        tabA.close();
        tabB.close();
        storageA.close();
        storageB.close();
      }
    },
  },

  // =========================================================================
  // 5b. Recovery against a real database.
  //
  // `restore()` is the one path that writes state into storage from
  // somewhere other than the verified chain: the blob carries group
  // secrets, never transitions. The Node suite covers the logic, but it
  // covers it over `fake-indexeddb`, and the catch-up walk now reads a
  // stored secret back mid-verification — a read whose interleaving with
  // concurrent writers only a real database can settle.
  // =========================================================================
  {
    name: "restore: a refreshed backup recovers the whole chain from real IndexedDB",
    async run() {
      const transport = new MockTransport();
      const keys = await km.generateDeviceKeys();
      const original = await IndexedDbStore.open({ name: freshDbName() });
      const fresh = await IndexedDbStore.open({ name: freshDbName() });
      try {
        await original.putIdentity({
          userId: "alice",
          identityPrivateKey: keys.identity.privateKey,
          backupEnrolled: false, // enroll() refuses if this is already true
        });
        const backup = new BackupManager(
          crypto,
          original,
          new SyncManager(transport),
          FAST_BACKUP,
        );
        const credential = await backup.enroll();
        await backup.confirmEnrollment(credential);

        const tab = new GroupManager({
          crypto,
          storage: original,
          transport,
          locks: new WebLocksProvider(),
          deviceKeys: keys,
          userId: "alice",
        });
        const group = (await tab.createGroup({ min_managers: 1 })).group_id;
        for (const who of ["bob", "carol"]) {
          const device = km.devicePublicKey(await km.generateDeviceKeys());
          await tab.addMember(group, {
            user_id: who,
            device_pubkeys: [device],
            is_manager: false,
          });
        }
        assertEqual(tab.getState(group).epoch, 2, "three epochs before the refresh");
        await backup.refresh(credential);
        tab.close();

        // A different database entirely: the replacement device.
        const restoring = new BackupManager(
          crypto,
          fresh,
          new SyncManager(transport),
          FAST_BACKUP,
        );
        await restoring.restore("alice", credential);

        // The premise this case exists for. Assert it rather than assume
        // it: if `restore` ever starts persisting transitions too, the
        // test would keep passing while covering nothing.
        assertEqual(
          [...(await fresh.getGroupSecrets(group)).keys()],
          [0, 1, 2],
          "the blob's secrets reached real IndexedDB",
        );
        assertEqual(
          (await fresh.getTransitions(group)).length,
          0,
          "and no transitions came with them",
        );

        const identity = await fresh.getIdentity();
        const restoredTab = new GroupManager({
          crypto,
          storage: fresh,
          transport,
          locks: new WebLocksProvider(),
          deviceKeys: await km.deviceKeysFromIdentity(identity.identityPrivateKey),
          userId: "alice",
        });
        try {
          await restoredTab.start();
          const state = await restoredTab.syncGroup(group);
          assertEqual(state.epoch, 2, "the restored device reaches the head");
          assertEqual(
            (await fresh.getTransitions(group)).map((t) => t.epoch),
            [0, 1, 2],
            "and persisted the chain it verified on the way",
          );
        } finally {
          restoredTab.close();
        }
      } finally {
        original.close();
        fresh.close();
      }
    },
  },

  {
    name: "restore: two tabs sync a restored database concurrently",
    async run() {
      // The interleaving `fake-indexeddb` cannot settle: two real
      // connections verifying the same chain at once, each reading back
      // secrets the blob wrote while the other appends transitions. The
      // append-only guard must absorb the loser without either tab
      // ending up short of the head.
      const transport = new MockTransport();
      const keys = await km.generateDeviceKeys();
      const seed = await IndexedDbStore.open({ name: freshDbName() });
      const dbName = freshDbName();
      try {
        await seed.putIdentity({
          userId: "alice",
          identityPrivateKey: keys.identity.privateKey,
          backupEnrolled: false,
        });
        const backup = new BackupManager(
          crypto,
          seed,
          new SyncManager(transport),
          FAST_BACKUP,
        );
        const credential = await backup.enroll();
        await backup.confirmEnrollment(credential);

        const tab = new GroupManager({
          crypto,
          storage: seed,
          transport,
          locks: new WebLocksProvider(),
          deviceKeys: keys,
          userId: "alice",
        });
        const group = (await tab.createGroup({ min_managers: 1 })).group_id;
        const device = km.devicePublicKey(await km.generateDeviceKeys());
        await tab.addMember(group, {
          user_id: "bob",
          device_pubkeys: [device],
          is_manager: false,
        });
        await backup.refresh(credential);
        tab.close();

        const [storageA, storageB] = await openConnections(dbName, 2);
        try {
          await new BackupManager(
            crypto,
            storageA,
            new SyncManager(transport),
            FAST_BACKUP,
          ).restore("alice", credential);

          const restoredKeys = await km.deviceKeysFromIdentity(
            (await storageA.getIdentity()).identityPrivateKey,
          );
          const makeTab = (storage) =>
            new GroupManager({
              crypto,
              storage,
              transport,
              locks: new WebLocksProvider(),
              deviceKeys: restoredKeys,
              userId: "alice",
            });
          const tabA = makeTab(storageA);
          const tabB = makeTab(storageB);
          try {
            const [a, b] = await Promise.all([
              tabA.syncGroup(group),
              tabB.syncGroup(group),
            ]);
            assertEqual(a.epoch, 1, "tab A reaches the head");
            assertEqual(b.epoch, 1, "tab B reaches the head");
            assertEqual(
              (await storageA.getTransitions(group)).map((t) => t.epoch),
              [0, 1],
              "exactly one clean chain, no duplicate epochs",
            );
          } finally {
            tabA.close();
            tabB.close();
          }
        } finally {
          storageA.close();
          storageB.close();
        }
      } finally {
        seed.close();
      }
    },
  },

  // =========================================================================
  // 6. Environment reporting (informational, not assertions).
  // =========================================================================
  {
    name: "environment: secure context, persistence and adapter availability",
    async run() {
      assert(globalThis.isSecureContext === true, "must run in a secure context");
      assert(typeof indexedDB !== "undefined", "IndexedDB present");
      assert(navigator.locks !== undefined, "Web Locks present");
      assert(typeof BroadcastChannel !== "undefined", "BroadcastChannel present");
      // In-process fallbacks must still work in a browser, since a host
      // may deliberately choose them.
      const fallback = new InProcessLockProvider();
      assertEqual(
        await fallback.withLock("x", () => Promise.resolve("ok")),
        "ok",
        "the in-process fallback still functions in a browser",
      );
      if (navigator.storage?.persist !== undefined) {
        const persisted = await navigator.storage.persisted();
        console.info(`[circlekey] storage persisted: ${String(persisted)}`);
      }
    },
  },
];
