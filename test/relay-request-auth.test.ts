/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Relay request authorization — spec §10.1.
 *
 * The rule that matters is the asymmetry: **reads accept any epoch key
 * the group has ever published, writes require the current one.**
 *
 * Getting it backwards deadlocks the protocol. A member sitting at
 * epoch `e-1` holds only `auth_sk[e-1]`, so if reads demanded the
 * current key it could not fetch the very transition that would bring
 * it current — and that is every lagging or briefly-offline client, not
 * some edge case. The first test here is that deadlock, and it is the
 * reason this section of the spec changed.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { base64UrlToBytes } from "../src/core/bytes";
import { TransportError } from "../src/core/errors";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import {
  authorizeRelayRequest,
  isRelayWriteOp,
  RELAY_READ_OPS,
  RELAY_WRITE_OPS,
  verifyRelayRequest,
} from "../src/core/relay-auth";
import { BackupManager } from "../src/managers/backup-manager";
import { GroupManager } from "../src/managers/group-manager";
import { SyncManager } from "../src/managers/sync-manager";
import { completeBackupEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

/**
 * A MockTransport that enforces §10.1.
 *
 * `allowUnauthenticatedReads` stands in for the relay's account layer:
 * a client that holds no epoch key yet cannot sign, because signing
 * needs the secret the fetch would deliver. A signature that *is*
 * present is still verified strictly, which is what keeps the tests
 * below meaningful.
 */
function strictTransport(): MockTransport {
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

interface Client {
  manager: GroupManager;
  storage: MemoryStore;
  keys: DeviceKeys;
}

async function makeClient(userId: string, transport: MockTransport): Promise<Client> {
  const keys = await km.generateDeviceKeys();
  const storage = new MemoryStore();
  await storage.putIdentity({
    userId,
    identityPrivateKey: keys.identity.privateKey,
    backupEnrolled: false,
  });
  await completeBackupEnrollment(
    new BackupManager(crypto, storage, new SyncManager(transport), FAST_BACKUP),
  );
  const manager = new GroupManager({
    crypto,
    storage,
    transport,
    locks: new InProcessLockProvider(),
    deviceKeys: keys,
    userId,
  });
  await manager.start();
  return { manager, storage, keys };
}

let alice: Client;
let bob: Client;
let transport: MockTransport;

beforeAll(async () => {
  transport = strictTransport();
  alice = await makeClient("alice", transport);
  bob = await makeClient("bob", transport);
});

describe("the deadlock this rule exists to prevent (spec §10.1)", () => {
  it("a member several epochs behind can still catch up", async () => {
    const lag = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(lag, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: false,
    });
    await bob.manager.syncGroup(lag); // bob is at epoch 1

    // Alice moves the group on without bob. Bob now holds only
    // auth_sk[1] while the relay's current key is auth_pk[4].
    for (let i = 0; i < 3; i++) {
      await alice.manager.setPolicy(lag, { min_managers: 1 });
    }
    expect(alice.manager.getState(lag)?.epoch).toBe(4);
    expect(bob.manager.getState(lag)?.epoch).toBe(1);

    // The read is signed under bob's stale key and must be accepted.
    const caught = await bob.manager.syncGroup(lag);
    expect(caught.epoch).toBe(4);
  });
});

describe("read/write asymmetry (spec §10.1)", () => {
  it("accepts a read signed under any published epoch key", async () => {
    const reads = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.setPolicy(reads, { min_managers: 1 }); // epoch 1

    const epoch0Secret = await alice.storage.getGroupSecret(reads, 0);
    expect(epoch0Secret).toBeDefined();
    if (epoch0Secret === undefined) return;

    const stale = await authorizeRelayRequest(
      crypto,
      reads,
      "getTransitions",
      0,
      epoch0Secret,
    );
    await expect(transport.getTransitions(reads, undefined, stale)).resolves.toHaveLength(
      2,
    );
  });

  it("refuses a write signed under a superseded epoch key", async () => {
    const writes = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.setPolicy(writes, { min_managers: 1 }); // epoch 1

    const epoch0Secret = await alice.storage.getGroupSecret(writes, 0);
    if (epoch0Secret === undefined) throw new Error("fixture");

    const stale = await authorizeRelayRequest(
      crypto,
      writes,
      "putRecord",
      0,
      epoch0Secret,
    );
    await expect(
      transport.putRecord(
        writes,
        { record_id: "r", epoch: 1, ciphertext: "x", nonce: "n", suite: "gv1" },
        stale,
      ),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("refuses an unsigned write even during bootstrap", async () => {
    // Reads may bootstrap through the account layer; writes never can,
    // because a caller that cannot sign cannot be a member.
    const unsigned = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await expect(
      transport.putRecord(unsigned, {
        record_id: "r",
        epoch: 0,
        ciphertext: "x",
        nonce: "n",
        suite: "gv1",
      }),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("refuses any unsigned request when no account layer vouches", async () => {
    const sealed = new MockTransport({
      requireAuth: true,
      verifyAuth: () => Promise.resolve(true),
    });
    const sealed_relay = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const chain = await transport.getTransitions(sealed_relay, undefined, undefined);
    const genesis = chain[0];
    if (genesis === undefined) throw new Error("fixture");
    await sealed.createGroup(genesis);
    await expect(sealed.getTransitions(sealed_relay)).rejects.toBeInstanceOf(
      TransportError,
    );
  });

  it("refuses a signature made with a key outside the group", async () => {
    const outsider = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const forged = await authorizeRelayRequest(
      crypto,
      outsider,
      "getTransitions",
      0,
      crypto.randomBytes(32),
    );
    await expect(
      transport.getTransitions(outsider, undefined, forged),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("refuses a signature bound to a different operation", async () => {
    const crossop = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const secret = await alice.storage.getGroupSecret(crossop, 0);
    if (secret === undefined) throw new Error("fixture");

    // Signed for listRecords, presented as getTransitions.
    const wrongOp = await authorizeRelayRequest(
      crypto,
      crossop,
      "listRecords",
      0,
      secret,
    );
    await expect(
      transport.getTransitions(crossop, undefined, wrongOp),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("refuses a signature bound to a different group", async () => {
    const groupA = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const groupB = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const secret = await alice.storage.getGroupSecret(groupA, 0);
    if (secret === undefined) throw new Error("fixture");

    const wrongGroup = await authorizeRelayRequest(
      crypto,
      groupA,
      "getTransitions",
      0,
      secret,
    );
    await expect(
      transport.getTransitions(groupB, undefined, wrongGroup),
    ).rejects.toBeInstanceOf(TransportError);
  });
});

describe("revocation through rotation (spec §10.1)", () => {
  it("a removed member loses write access at the next epoch", async () => {
    const revoke = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(revoke, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: true,
    });
    await bob.manager.syncGroup(revoke);
    const bobsLastSecret = await bob.storage.getGroupSecret(revoke, 1);
    if (bobsLastSecret === undefined) throw new Error("fixture");

    await alice.manager.removeMember(revoke, "bob"); // epoch 2

    // Bob's newest key is epoch 1's; the relay now requires epoch 2 for
    // writes. No relay bookkeeping was needed to achieve this.
    const stale = await authorizeRelayRequest(
      crypto,
      revoke,
      "putRecord",
      1,
      bobsLastSecret,
    );
    await expect(
      transport.putRecord(
        revoke,
        { record_id: "r", epoch: 2, ciphertext: "x", nonce: "n", suite: "gv1" },
        stale,
      ),
    ).rejects.toBeInstanceOf(TransportError);

    // ...but he can still read, which is what lets him fetch the
    // removal notice that tells him why (spec §6.5, §9.3).
    const readable = await authorizeRelayRequest(
      crypto,
      revoke,
      "getTransitions",
      1,
      bobsLastSecret,
    );
    await expect(
      transport.getTransitions(revoke, undefined, readable),
    ).resolves.toHaveLength(3);
  });
});

describe("operation classification", () => {
  it("classifies every operation exactly once", () => {
    const reads = new Set<string>(RELAY_READ_OPS);
    const writes = new Set<string>(RELAY_WRITE_OPS);
    for (const op of writes) expect(reads.has(op)).toBe(false);
    for (const op of reads) expect(isRelayWriteOp(op)).toBe(false);
    for (const op of writes) expect(isRelayWriteOp(op)).toBe(true);
  });

  it("treats the state-changing operations as writes", () => {
    // If either of these ever drifts into the read set, a removed
    // member keeps the ability to change the group.
    expect(isRelayWriteOp("submitTransition")).toBe(true);
    expect(isRelayWriteOp("putRecord")).toBe(true);
  });
});
