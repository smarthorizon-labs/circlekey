/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Startup reload + chain re-verification: the
 * transitions store is the source of truth, the groups cache is
 * repaired on disagreement, and corrupted local history fails loudly.
 */

import "fake-indexeddb/auto";

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { IndexedDbStore } from "../src/adapters/storage/indexeddb";
import { MemoryStore } from "../src/adapters/storage/memory";
import {
  buildAddMember,
  buildGenesis,
  buildPromoteMember,
  verifyTransition,
} from "../src/core/epoch-chain";
import { EnvelopeError, StorageError } from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager } from "../src/core/key-manager";
import type { WireTransition } from "../src/core/types";
import { persistVerifiedTransition, reloadVerifiedGroups } from "../src/managers/startup";
import type { StorageAdapter } from "../src/ports/storage";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

interface Fixture {
  chain: { wire: WireTransition; state: GroupState; secret: Uint8Array }[];
  finalState: GroupState;
}

let fixture: Fixture;

beforeAll(async () => {
  const alice = await km.generateDeviceKeys();
  const bob = await km.generateDeviceKeys();

  const chain: Fixture["chain"] = [];
  const genesis = await buildGenesis({
    crypto,
    signer: alice,
    groupId: "startup-group",
    creatorUserId: "alice",
    policy: { min_managers: 1 },
  });
  let state = await verifyTransition(crypto, null, genesis.transition);
  chain.push({ wire: genesis.wire, state, secret: genesis.groupSecret });

  const add = await buildAddMember({
    crypto,
    state,
    signer: alice,
    currentGroupSecret: genesis.groupSecret,
    newMember: { user_id: "bob", device_pubkeys: [km.devicePublicKey(bob)], is_manager: false },
  });
  state = await verifyTransition(crypto, state, add.transition);
  chain.push({ wire: add.wire, state, secret: add.groupSecret });

  const promote = await buildPromoteMember({
    crypto,
    state,
    signer: alice,
    currentGroupSecret: add.groupSecret,
    userId: "bob",
  });
  state = await verifyTransition(crypto, state, promote.transition);
  chain.push({ wire: promote.wire, state, secret: promote.groupSecret });

  fixture = { chain, finalState: state };
});

async function persistAll(storage: StorageAdapter): Promise<void> {
  for (const { wire, state, secret } of fixture.chain) {
    await persistVerifiedTransition(storage, wire, state, secret);
  }
}

describe("persistVerifiedTransition", () => {
  it("persists history, state cache, and the epoch secret", async () => {
    const storage = new MemoryStore();
    await persistAll(storage);

    expect(await storage.getTransitions("startup-group")).toHaveLength(3);
    expect(await storage.getGroupState("startup-group")).toEqual(fixture.finalState);
    expect([...(await storage.getGroupSecrets("startup-group")).keys()].sort()).toEqual([
      0, 1, 2,
    ]);
  });

  it("rejects a state that does not match the transition", async () => {
    const storage = new MemoryStore();
    const [genesis, add] = fixture.chain;
    if (genesis === undefined || add === undefined) throw new Error("fixture");
    await expect(
      persistVerifiedTransition(storage, genesis.wire, add.state, genesis.secret),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it("refuses double-persisting an epoch (append-only)", async () => {
    const storage = new MemoryStore();
    await persistAll(storage);
    const last = fixture.chain[2];
    if (last === undefined) throw new Error("fixture");
    await expect(
      persistVerifiedTransition(storage, last.wire, last.state, last.secret),
    ).rejects.toBeInstanceOf(StorageError);
  });
});

describe("reloadVerifiedGroups", () => {
  it("re-verifies stored chains and returns their states", async () => {
    const storage = new MemoryStore();
    await persistAll(storage);

    const states = await reloadVerifiedGroups(crypto, storage);
    expect(states.get("startup-group")).toEqual(fixture.finalState);
    expect(states.size).toBe(1);
  });

  it("repairs a corrupted groups cache from the transition log", async () => {
    const storage = new MemoryStore();
    await persistAll(storage);
    await storage.putGroupState({
      ...fixture.finalState,
      epoch: 99,
      last_transition_hash: "bogus",
    });

    const states = await reloadVerifiedGroups(crypto, storage);
    expect(states.get("startup-group")).toEqual(fixture.finalState);
    expect(await storage.getGroupState("startup-group")).toEqual(fixture.finalState);
  });

  it("fails loudly on tampered local history instead of trusting it", async () => {
    const storage = new MemoryStore();
    const [genesis, add] = fixture.chain;
    if (genesis === undefined || add === undefined) throw new Error("fixture");
    await storage.appendTransition(genesis.wire);
    await storage.putGroupSecret("startup-group", 0, genesis.secret);
    // Tampering with the sealed body is the modern equivalent of
    // flipping a signature byte: the body no longer authenticates, so
    // reload fails before it can even read the inner signature.
    const body = add.wire.sealed_body;
    await storage.appendTransition({
      ...add.wire,
      sealed_body: body.startsWith("A") ? `B${body.slice(1)}` : `A${body.slice(1)}`,
    });
    await storage.putGroupSecret("startup-group", 1, add.secret);

    await expect(reloadVerifiedGroups(crypto, storage)).rejects.toBeInstanceOf(
      EnvelopeError,
    );
  });

  it("works identically over IndexedDbStore", async () => {
    const storage = await IndexedDbStore.open({ name: "circlekey-startup-test" });
    await persistAll(storage);

    const states = await reloadVerifiedGroups(crypto, storage);
    expect(states.get("startup-group")).toEqual(fixture.finalState);
    storage.close();
  });
});
