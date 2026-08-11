/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Executable form of the spec §10.5 capability table.
 *
 * Three deadlocks in this design turned out to be one bug: an
 * authorization rule written without enumerating who can satisfy it.
 * Fetching epoch `e` needed `auth_sk[e]`, which arrives *in* epoch `e`;
 * a new member had to sign a fetch using the secret that fetch would
 * deliver; a backup handle was derived from a key stored inside the
 * blob it addressed. Each read as correct prose.
 *
 * None was found by reasoning. All three were found by switching
 * enforcement on and watching something legitimate fail — so this file
 * does that deliberately, and for every actor rather than the one that
 * happened to be under test.
 *
 * The shape is a reachability check over a small state space: for each
 * role, either it reaches a working state, or it is *provably refused*.
 * A role that can neither act nor be refused is the deadlock.
 *
 * Everything here runs with the relay at **maximum enforcement**. The
 * default `MockTransport` does not require signatures at all, which is
 * why most of the suite would not notice a capability circle.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { base64UrlToBytes } from "../src/core/bytes";
import { TransportError } from "../src/core/errors";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { authorizeRelayRequest, verifyRelayRequest } from "../src/core/relay-auth";
import { GroupVault } from "../src/api/group-vault";
import { BackupManager } from "../src/managers/backup-manager";
import { GroupManager } from "../src/managers/group-manager";
import { SyncManager } from "../src/managers/sync-manager";
import { completeBackupEnrollment, completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

/**
 * A relay enforcing spec §10.1 in full.
 *
 * `allowUnauthenticatedReads` models the account layer, which the spec
 * requires a real relay to anchor in an invite token or authenticated
 * session. A signature that *is* presented is still verified strictly,
 * so nothing below passes by simply omitting one.
 */
function strictRelay(): MockTransport {
  return new MockTransport({
    requireAuth: true,
    allowUnauthenticatedReads: true,
    verifyAuth: (authPublicKey, requestBytes, signature) =>
      verifyRelayRequest(
        crypto,
        base64UrlToBytes(authPublicKey),
        requestBytes,
        base64UrlToBytes(signature),
      ),
  });
}

interface Actor {
  manager: GroupManager;
  backup: BackupManager;
  storage: MemoryStore;
  keys: DeviceKeys;
  credential?: string;
}

async function actor(
  userId: string,
  transport: MockTransport,
  options: { enroll?: boolean; keys?: DeviceKeys; storage?: MemoryStore } = {},
): Promise<Actor> {
  const keys = options.keys ?? (await km.generateDeviceKeys());
  const storage = options.storage ?? new MemoryStore();
  await storage.putIdentity({
    userId,
    identityPrivateKey: keys.identity.privateKey,
    backupEnrolled: false,
  });
  const backup = new BackupManager(
    crypto,
    storage,
    new SyncManager(transport),
    FAST_BACKUP,
  );
  const result: Actor = { manager: buildManager(), backup, storage, keys };
  if (options.enroll !== false) {
    result.credential = await completeBackupEnrollment(backup);
  }
  await result.manager.start();
  return result;

  function buildManager(): GroupManager {
    return new GroupManager({
      crypto,
      storage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: keys,
      userId,
    });
  }
}

describe("spec §10.5: every actor can reach a working state", () => {
  it("creator — holds nothing, bootstraps through the account layer", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);

    const state = await alice.manager.createGroup({ min_managers: 1 });
    const g = state.group_id;
    expect(state.epoch).toBe(0);
    // ...and can immediately act, because creating granted auth_sk[0].
    await expect(alice.manager.setPolicy(g, { min_managers: 1 })).resolves.toMatchObject({
      epoch: 1,
    });
  });

  it("invitee — holds nothing for this group, and its first fetch delivers the key", async () => {
    // The second such circle: signing the fetch would have
    // required the secret the fetch itself delivers.
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const bob = await actor("bob", relay);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: true,
    });

    const state = await bob.manager.syncGroup(g);
    expect(state.epoch).toBe(1);
    // Having synced, bob now holds auth_sk[1] and can write.
    await expect(bob.manager.setPolicy(g, { min_managers: 1 })).resolves.toMatchObject({
      epoch: 2,
    });
  });

  it("lagging member — stale key, still reaches current", async () => {
    // The first such circle: requiring the current key for reads makes
    // catching up impossible for anyone briefly offline.
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const bob = await actor("bob", relay);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: false,
    });
    await bob.manager.syncGroup(g);
    for (let i = 0; i < 3; i++) {
      await alice.manager.setPolicy(g, { min_managers: 1 });
    }

    expect(bob.manager.getState(g)?.epoch).toBe(1);
    expect((await bob.manager.syncGroup(g)).epoch).toBe(4);
  });

  it("restored device — credential only, recovers identity then group access", async () => {
    // The third such circle: the blob handle once derived from the
    // identity key, which lives inside the blob being fetched.
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.backup.refresh(alice.credential ?? "");

    // A blank device holding nothing but the credential.
    const fresh = new MemoryStore();
    const restorer = new BackupManager(
      crypto,
      fresh,
      new SyncManager(relay),
      FAST_BACKUP,
    );
    const identity = await restorer.restore("alice", alice.credential ?? "");
    expect(identity.userId).toBe("alice");

    const recovered = new GroupManager({
      crypto,
      storage: fresh,
      transport: relay,
      locks: new InProcessLockProvider(),
      deviceKeys: await km.deviceKeysFromIdentity(identity.identityPrivateKey),
      userId: "alice",
    });
    await recovered.start();
    expect((await recovered.syncGroup(g)).epoch).toBe(0);
  });
});

describe("spec §10.5: every actor without a capability is provably refused", () => {
  it("removed member — can still read, cannot write", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const bob = await actor("bob", relay);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: true,
    });
    await bob.manager.syncGroup(g);
    const bobsLastSecret = await bob.storage.getGroupSecret(g, 1);
    if (bobsLastSecret === undefined) throw new Error("fixture");

    await alice.manager.removeMember(g, "bob"); // epoch 2

    // Read: still permitted, which is what lets him fetch the removal
    // notice that explains why (spec §6.5, §9.3).
    const read = await authorizeRelayRequest(crypto, g, "getTransitions", 1, bobsLastSecret);
    await expect(relay.getTransitions(g, undefined, read)).resolves.toHaveLength(3);

    // Write: refused, and refused by the relay rather than by politeness.
    const write = await authorizeRelayRequest(crypto, g, "putRecord", 1, bobsLastSecret);
    await expect(
      relay.putRecord(
        g,
        { record_id: "r", epoch: 2, ciphertext: "x", nonce: "n", suite: "gv1" },
        write,
      ),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("outsider — never a member, holds nothing that works", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;

    // A key from nowhere is refused for both reads and writes.
    const foreign = crypto.randomBytes(32);
    for (const op of ["getTransitions", "putRecord"] as const) {
      const auth = await authorizeRelayRequest(crypto, g, op, 0, foreign);
      const call =
        op === "getTransitions"
          ? relay.getTransitions(g, undefined, auth)
          : relay.putRecord(
              g,
              { record_id: "r", epoch: 0, ciphertext: "x", nonce: "n", suite: "gv1" },
              auth,
            );
      await expect(call).rejects.toBeInstanceOf(TransportError);
    }

    // And an unsigned *write* is refused even though the account layer
    // vouches for unsigned reads: a caller that cannot sign cannot be a
    // member, so there is nothing for a write to bootstrap from.
    await expect(
      relay.putRecord(g, {
        record_id: "r",
        epoch: 0,
        ciphertext: "x",
        nonce: "n",
        suite: "gv1",
      }),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("wrong credential — cannot locate a backup, and cannot tell why", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    await alice.manager.createGroup({ min_managers: 1 });
    await alice.backup.refresh(alice.credential ?? "");

    const restorer = new BackupManager(
      crypto,
      new MemoryStore(),
      new SyncManager(relay),
      FAST_BACKUP,
    );
    // Deliberately indistinguishable from "no backup exists": the handle
    // derives from the credential, so a wrong one addresses nothing.
    // Reporting the difference would make the relay a guessing oracle.
    await expect(restorer.restore("alice", "not-the-credential")).rejects.toThrow();
  });
});

describe("spec §10.5: the facade satisfies the record rows too", () => {
  // The rows above were reached with `authorizeRelayRequest` called by
  // hand, which proves the *relay* enforces them and nothing about
  // whether the client can satisfy them. It could not: `GroupVault`
  // signed governance requests and left every record call unsigned, so
  // a conforming relay refused all of them while the whole suite stayed
  // green. A capability row needs an actor that reaches it through the
  // public API, or it is only half checked.
  it("reads and writes records through GroupVault against a strict relay", async () => {
    const relay = strictRelay();
    const vault = await GroupVault.open({
      transport: relay,
      userId: "alice",
      crypto,
      storage: new MemoryStore(),
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;

    await vault.putJsonRecord(g, "doc", { hello: "world" });
    expect(await vault.getJsonRecord(g, "doc")).toEqual({ hello: "world" });
    expect(await vault.listRecords(g)).toHaveLength(1);

    // Still works after a rotation, which moves the key every record
    // request must now be signed under.
    await vault.setPolicy(g, { min_managers: 1 });
    await vault.putJsonRecord(g, "doc-2", { after: "rotation" });
    expect(await vault.getJsonRecord(g, "doc-2")).toEqual({ after: "rotation" });
  });
});

describe("spec §10.5: the table's own invariants", () => {
  // The rule that turns a table row into a deadlock. Stated as a test so
  // that adding a gate without a holder fails here rather than in
  // whichever integration test happens to exercise that actor.
  it("no read operation requires the current epoch's key", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.setPolicy(g, { min_managers: 1 }); // epoch 1

    const epoch0 = await alice.storage.getGroupSecret(g, 0);
    if (epoch0 === undefined) throw new Error("fixture");

    for (const op of ["getTransitions", "getGroupState", "listRecords"] as const) {
      const stale = await authorizeRelayRequest(crypto, g, op, 0, epoch0);
      const call =
        op === "getTransitions"
          ? relay.getTransitions(g, undefined, stale)
          : op === "getGroupState"
            ? relay.getGroupState(g, stale)
            : relay.listRecords(g, undefined, stale);
      await expect(call).resolves.toBeDefined();
    }
  });

  it("every write operation requires the current epoch's key", async () => {
    const relay = strictRelay();
    const alice = await actor("alice", relay);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.setPolicy(g, { min_managers: 1 }); // epoch 1

    const epoch0 = await alice.storage.getGroupSecret(g, 0);
    if (epoch0 === undefined) throw new Error("fixture");

    const stale = await authorizeRelayRequest(crypto, g, "putRecord", 0, epoch0);
    await expect(
      relay.putRecord(
        g,
        { record_id: "r", epoch: 1, ciphertext: "x", nonce: "n", suite: "gv1" },
        stale,
      ),
    ).rejects.toBeInstanceOf(TransportError);
  });
});
