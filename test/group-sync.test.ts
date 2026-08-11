/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * A manager client and a member client converge via
 * polling, and the adversarial backend suite (replay, fork, gap,
 * signature swap) is rejected with typed errors — never applied,
 * never silent.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { sealHistoryLink } from "../src/core/envelopes";
import {
  buildAddMember,
  buildGenesis,
  buildPromoteMember,
  buildSetPolicy,
  verifyTransition,
} from "../src/core/epoch-chain";
import {
  EnvelopeError,
  ChainMismatchError,
  ConflictError,
  EpochGapError,
  ForkDetectedError,
  HistoryIntegrityError,
  StaleEpochError,
  TransportError,
  UnauthorizedSignerError,
} from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { RecordCrypto } from "../src/core/record-crypto";
import type { WireTransition, MemberEntry } from "../src/core/types";
import { BackupManager } from "../src/managers/backup-manager";
import { GroupManager } from "../src/managers/group-manager";
import { SyncManager } from "../src/managers/sync-manager";
import type { Transport } from "../src/ports/transport";
import {
  completeBackupEnrollment,
  FAST_BACKUP,
  MemoryKeyUsageStore,
  SwitchableTransport,
} from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

function must<T>(value: T | undefined, what = "value"): T {
  if (value === undefined) throw new Error(`missing ${what}`);
  return value;
}

interface Client {
  userId: string;
  keys: DeviceKeys;
  devicePub: string;
  storage: MemoryStore;
  manager: GroupManager;
  forks: string[];
}

async function makeClient(
  userId: string,
  transport: Transport,
  existingKeys?: DeviceKeys,
): Promise<Client> {
  const keys = existingKeys ?? (await km.generateDeviceKeys());
  const storage = new MemoryStore();
  // Group operations are unreachable until backup enrollment (spec §9.6).
  await storage.putIdentity({
    userId,
    identityPrivateKey: keys.identity.privateKey,
    backupEnrolled: false,
  });
  await completeBackupEnrollment(
    new BackupManager(crypto, storage, new SyncManager(transport), FAST_BACKUP),
  );
  const forks: string[] = [];
  const manager = new GroupManager({
    crypto,
    storage,
    transport,
    locks: new InProcessLockProvider(),
    deviceKeys: keys,
    userId,
    onForkDetected: (groupId) => {
      forks.push(groupId);
    },
  });
  return { userId, keys, devicePub: km.devicePublicKey(keys), storage, manager, forks };
}

function memberEntry(client: Client, isManager = false): MemberEntry {
  return {
    user_id: client.userId,
    device_pubkeys: [client.devicePub],
    is_manager: isManager,
  };
}

describe("convergence via polling", () => {
  it("manager and member clients converge, including records and history", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const bob = await makeClient("bob", transport);
    const sync = new SyncManager(transport);
    const records = new RecordCrypto(crypto, new MemoryKeyUsageStore());

    // Alice creates the group and stores a record before Bob exists.
    const state0 = await alice.manager.createGroup({ min_managers: 1 });
    const g = state0.group_id;
    expect(state0.epoch).toBe(0);
    const secret0 = must(await alice.manager.getCurrentSecret(g), "epoch-0 secret");
    await sync.putRecord(
      g,
      await records.encryptJsonRecord(g, 0, secret0, "doc-0", { hello: "bob" }),
    );

    await alice.manager.addMember(g, memberEntry(bob));

    // Bob joins from nothing: full chain fetch, §9.1 verification,
    // envelope + history-chain secret recovery.
    const bobState = await bob.manager.syncGroup(g);
    expect(bobState).toEqual(alice.manager.getState(g));
    expect([...(await bob.storage.getGroupSecrets(g)).keys()].sort()).toEqual([0, 1]);

    // Bob decrypts the pre-join record through the whole stack.
    const fetched = await sync.getRecord(g, "doc-0");
    const recordSecret = must(await bob.storage.getGroupSecret(g, fetched.epoch));
    expect(await records.decryptJsonRecord(g, recordSecret, fetched)).toEqual({
      hello: "bob",
    });

    // Governance ping-pong across both clients.
    await alice.manager.promoteMember(g, "bob");
    await bob.manager.syncGroup(g);
    const afterDemote = await bob.manager.demoteMember(g, "alice");
    expect(afterDemote.epoch).toBe(3);

    const aliceView = await alice.manager.syncGroup(g);
    expect(aliceView).toEqual(bob.manager.getState(g));

    // Demoted alice can no longer act — refused at build time.
    await expect(
      alice.manager.setPolicy(g, { min_managers: 1 }),
    ).rejects.toBeInstanceOf(UnauthorizedSignerError);
  });

  // a removed member cannot open the removal
  // transition — its body is sealed to a secret they never receive — so
  // they do not advance to it at all. What they observe is loss of
  // access, not a verified removal (spec §6.5, §9.3). Stricter than
  // before: they also learn nothing about the remaining membership.
  it("a removed member stops advancing and receives no new secrets", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const bob = await makeClient("bob", transport);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, memberEntry(bob));
    await bob.manager.syncGroup(g);
    await alice.manager.removeMember(g, "bob");

    const bobState = await bob.manager.syncGroup(g);
    expect(bobState.epoch).toBe(1);
    expect(bobState.members.some((m) => m.user_id === "bob")).toBe(true);
    // Everything up to the removal stays verified; nothing after it is
    // readable, and no epoch-2 secret ever arrives.
    expect(await bob.storage.getGroupSecret(g, 1)).toBeDefined();
    expect(await bob.storage.getGroupSecret(g, 2)).toBeUndefined();
    expect(await bob.storage.getTransitions(g)).toHaveLength(2);
  });

  it("a restarted client reloads and re-verifies persisted state", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.setPolicy(g, { min_managers: 1 });

    const restarted = new GroupManager({
      crypto,
      storage: alice.storage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: alice.keys,
      userId: "alice",
    });
    const states = await restarted.start();
    expect(states.get(g)).toEqual(alice.manager.getState(g));
    expect(await restarted.getCurrentSecret(g)).toBeDefined();
  });

  it("syncing an unknown group fails with TransportError", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    await expect(alice.manager.syncGroup("missing")).rejects.toBeInstanceOf(
      TransportError,
    );
  });
});

describe("secret history integrity (spec §9.7)", () => {
  it("detects a manager that sealed the wrong secret into a history link", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const bob = await makeClient("bob", transport);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, memberEntry(bob));
    await bob.manager.syncGroup(g);
    // Bob now holds the epoch-0 and epoch-1 secrets.
    expect(await bob.storage.getGroupSecret(g, 0)).toBeDefined();

    // A manager builds a valid epoch-2 transition, but seals a bogus
    // value into the history link. Everything else verifies: the
    // signature is real, the chain links correctly. Only comparing
    // the link against what we already hold reveals it.
    const state = must(alice.manager.getState(g));
    const currentSecret = must(await alice.manager.getCurrentSecret(g));
    const built = await buildSetPolicy({
      crypto,
      state,
      signer: alice.keys,
      currentGroupSecret: currentSecret,
      policy: { min_managers: 1 },
    });
    // The link is an *outer* field, so forging it
    // needs no re-signing: the inner body is untouched and still
    // verifies perfectly. Only comparing the link against the secret we
    // already hold reveals it (spec §9.7).
    const forged: WireTransition = {
      ...built.wire,
      prev_secret_ciphertext: await sealHistoryLink(
        crypto,
        g,
        state.epoch + 1,
        built.groupSecret,
        crypto.randomBytes(32), // not the real epoch-1 secret
      ),
    };
    await new SyncManager(transport).submitTransition(g, forged);

    await expect(bob.manager.syncGroup(g)).rejects.toBeInstanceOf(
      HistoryIntegrityError,
    );
  });
});

describe("backend rejections surface as typed errors", () => {
  it("a losing concurrent submission → ConflictError (spec §10.4)", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;

    const staleState = must(alice.manager.getState(g));
    const staleSecret = must(await alice.manager.getCurrentSecret(g));
    await alice.manager.setPolicy(g, { min_managers: 1 }); // epoch 1 is taken

    const competing = await buildSetPolicy({
      crypto,
      state: staleState,
      signer: alice.keys,
      currentGroupSecret: staleSecret,
      policy: { min_managers: 1 },
    });
    await expect(
      new SyncManager(transport).submitTransition(g, competing.wire),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it("a stale record write → StaleEpochError (spec §9.3)", async () => {
    const transport = new MockTransport();
    const alice = await makeClient("alice", transport);
    const records = new RecordCrypto(crypto, new MemoryKeyUsageStore());

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    const secret0 = must(await alice.manager.getCurrentSecret(g));
    await alice.manager.setPolicy(g, { min_managers: 1 }); // now at epoch 1

    const staleRecord = await records.encryptJsonRecord(g, 0, secret0, "doc", {});
    await expect(
      new SyncManager(transport).putRecord(g, staleRecord),
    ).rejects.toBeInstanceOf(StaleEpochError);
  });
});

// ---------------------------------------------------------------------------
// Adversarial backend suite: replay, gap, signature swap, fork.
// ---------------------------------------------------------------------------

interface AdversarialFixture {
  transport: SwitchableTransport;
  chain: WireTransition[];
  states: GroupState[];
  altBranch: WireTransition[]; // equivocating branch from epoch 2
  /**
   * Bob's keys. The victim client must be a *member*: 
   * the bodies are sealed, so a stranger cannot verify the chain at
   * all — which is the point, but it would make these tests pass for
   * the wrong reason (nothing to reject, because nothing opens).
   */
  memberKeys: DeviceKeys;
  /** The fixture's group id — generated ids mean it is no longer a literal. */
  g: string;
}

/** Honest chain (epochs 0..2) plus a properly signed rival branch. */
async function adversarialFixture(): Promise<AdversarialFixture> {
  // Built from the core primitives rather than `GroupManager`, so the id
  // is a fixture value: `buildGenesis` still takes one, exactly as the
  // frozen vectors do. Only the client API generates ids (spec §6.5).
  const g = "group-sync-adversarial-fixture";
  const mock = new MockTransport();
  const transport = new SwitchableTransport(mock);
  const alice = await km.generateDeviceKeys();
  const bob = await km.generateDeviceKeys();

  const genesis = await buildGenesis({
    crypto,
    signer: alice,
    groupId: g,
    creatorUserId: "alice",
    policy: { min_managers: 1 },
  });
  const state0 = await verifyTransition(crypto, null, genesis.transition);
  await mock.createGroup(genesis.wire);

  const add = await buildAddMember({
    crypto,
    state: state0,
    signer: alice,
    currentGroupSecret: genesis.groupSecret,
    newMember: { user_id: "bob", device_pubkeys: [km.devicePublicKey(bob)], is_manager: false },
  });
  const state1 = await verifyTransition(crypto, state0, add.transition);
  await mock.submitTransition(g, add.wire);

  const promote = await buildPromoteMember({
    crypto,
    state: state1,
    signer: alice,
    currentGroupSecret: add.groupSecret,
    userId: "bob",
  });
  const state2 = await verifyTransition(crypto, state1, promote.transition);
  await mock.submitTransition(g, promote.wire);

  // Equivocation: alice signs a *different* epoch-2 transition and
  // builds on it — a fork only the hash chain can reveal.
  const rival2 = await buildSetPolicy({
    crypto,
    state: state1,
    signer: alice,
    currentGroupSecret: add.groupSecret,
    policy: { min_managers: 1 },
  });
  const rivalState2 = await verifyTransition(crypto, state1, rival2.transition);
  const rival3 = await buildSetPolicy({
    crypto,
    state: rivalState2,
    signer: alice,
    currentGroupSecret: rival2.groupSecret,
    policy: { min_managers: 1 },
  });

  return {
    g,
    transport,
    chain: [genesis.wire, add.wire, promote.wire],
    memberKeys: bob,
    states: [state0, state1, state2],
    altBranch: [rival2.wire, rival3.wire],
  };
}

describe("adversarial backend suite", () => {
  it("replayed transitions are rejected and never applied", async () => {
    const { transport, chain, memberKeys, g } = await adversarialFixture();
    const victim = await makeClient("bob", transport, memberKeys);
    await victim.manager.syncGroup(g); // honest sync to epoch 2

    transport.override = () => [must(chain[1])]; // serve epoch 1 again
    await expect(victim.manager.syncGroup(g)).rejects.toBeInstanceOf(EpochGapError);
    expect(victim.manager.getState(g)?.epoch).toBe(2);
    expect(await victim.storage.getTransitions(g)).toHaveLength(3);
  });

  it("epoch gaps are rejected", async () => {
    const { transport, chain, memberKeys, g } = await adversarialFixture();
    const victim = await makeClient("bob", transport, memberKeys);

    transport.override = () => [must(chain[0]), must(chain[2])]; // drop epoch 1
    await expect(victim.manager.syncGroup(g)).rejects.toBeInstanceOf(EpochGapError);
    // Nothing is applied at all: the gap is caught
    // while recovering secrets, before any body is opened, because the
    // §9.7 walk steps exactly one epoch at a time.
    expect(victim.manager.getState(g)).toBeUndefined();
    expect(await victim.storage.getTransitions(g)).toHaveLength(0);
  });

  // The signature is inside the sealed body, so a
  // relay can no longer reach it. Substituting a whole body is the
  // strongest equivalent it retains — and the AAD binding refuses it
  // before the inner signature is ever read (spec §6.5).
  it("swapped sealed bodies are rejected", async () => {
    const { transport, chain, memberKeys, g } = await adversarialFixture();
    const victim = await makeClient("bob", transport, memberKeys);

    const [t0, t1, t2] = chain;
    transport.override = () => [
      must(t0),
      { ...must(t1), sealed_body: must(t2).sealed_body },
    ];
    await expect(victim.manager.syncGroup(g)).rejects.toBeInstanceOf(EnvelopeError);
    expect(await victim.storage.getTransitions(g)).toHaveLength(1);
  });

  it("a forked history is detected, surfaced, and refused", async () => {
    const { transport, altBranch, memberKeys, g } = await adversarialFixture();
    const victim = await makeClient("bob", transport, memberKeys);
    await victim.manager.syncGroup(g); // honest chain, epoch 2

    // The backend now serves the continuation of the rival branch.
    transport.override = (_groupId, sinceEpoch) =>
      sinceEpoch === 2 ? [must(altBranch[1])] : [];
    const attempt = victim.manager.syncGroup(g);
    await expect(attempt).rejects.toBeInstanceOf(ForkDetectedError);
    await expect(attempt).rejects.toBeInstanceOf(ChainMismatchError); // hierarchy

    expect(victim.forks).toEqual([g]); // fork event fired
    expect(victim.manager.getState(g)?.epoch).toBe(2); // nothing applied
    expect(await victim.storage.getTransitions(g)).toHaveLength(3);
  });
});
