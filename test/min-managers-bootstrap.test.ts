/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * `min_managers` can only ratchet up behind the managers that exist.
 *
 * A genesis names exactly one member (spec §9.1 genesis check 3), and the
 * genesis checklist deliberately omits the `min_managers` check that every
 * successor gets (check 5). So the protocol *permits* a genesis policy
 * demanding more managers than the group can possibly have — and the
 * result verifies at epoch 0, then refuses every governance operation
 * afterwards, because no single transition can climb from one manager to
 * three.
 *
 * These tests pin both halves: that the client refuses to create such a
 * group, and that the protocol behaviour which makes that refusal
 * necessary is what we think it is.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import {
  buildAddMember,
  buildGenesis,
  buildSetPolicy,
  verifyWireTransition,
} from "../src/core/epoch-chain";
import { PolicyViolationError } from "../src/core/errors";
import { KeyManager } from "../src/core/key-manager";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);
const GROUP_ID = "AAAAAAAAAAAAAAAAAAAAAA";

function vaultOptions(transport: Transport, userId: string) {
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

describe("min_managers at genesis", () => {
  it("refuses to create a group demanding more managers than it can have", async () => {
    const vault = await GroupVault.open(vaultOptions(new MockTransport(), "alice"));
    await completeEnrollment(vault);

    await expect(vault.createGroup({ min_managers: 2 })).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
    await expect(vault.createGroup({ min_managers: 3 })).rejects.toBeInstanceOf(
      PolicyViolationError,
    );

    // The message has to name the way out, because the failure a caller
    // would otherwise hit is several steps later and points at a symptom.
    await expect(vault.createGroup({ min_managers: 3 })).rejects.toThrow(
      /min_managers: 1.*raise the policy/s,
    );

    // The satisfiable case is untouched.
    const state = await vault.createGroup({ min_managers: 1 });
    expect(state.epoch).toBe(0);
    expect(state.policy.min_managers).toBe(1);
  });

  it("climbs by alternating promotion and policy raise", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(alice);
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, {
      userId: "bob",
      devicePubkey: bob.devicePublicKey(),
      isManager: true,
    });

    // Two managers now exist, so the bar may rise to meet them — but not
    // past them: `min_managers` may never exceed the manager count.
    await expect(alice.setPolicy(g, { min_managers: 3 })).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
    const raised = await alice.setPolicy(g, { min_managers: 2 });
    expect(raised.policy.min_managers).toBe(2);
  });

  it("is a client guarantee: the core primitive still follows the spec", async () => {
    // `buildGenesis` implements spec §9.1 exactly, and the genesis
    // checklist has no `min_managers` check — so this must still verify.
    // The guard above is a usability rule of the client API, enforced at
    // the same boundary as "an application may not supply a group_id".
    const alice = await km.generateDeviceKeys();
    const genesis = await buildGenesis({
      crypto,
      signer: alice,
      groupId: GROUP_ID,
      creatorUserId: "alice",
      policy: { min_managers: 3 },
    });
    const { state } = await verifyWireTransition(
      crypto,
      null,
      genesis.wire,
      genesis.groupSecret,
    );
    expect(state.epoch).toBe(0);
    expect(state.policy.min_managers).toBe(3);
  });

  it("shows why: such a group refuses every way of adding a manager", async () => {
    const alice = await km.generateDeviceKeys();
    const bob = await km.generateDeviceKeys();
    const genesis = await buildGenesis({
      crypto,
      signer: alice,
      groupId: GROUP_ID,
      creatorUserId: "alice",
      policy: { min_managers: 3 },
    });
    const { state } = await verifyWireTransition(
      crypto,
      null,
      genesis.wire,
      genesis.groupSecret,
    );

    // Adding Bob as a plain member leaves one manager; adding him *as* a
    // manager leaves two. Both are short of three, and there is no
    // transition that adds two managers at once.
    //
    // The refusal lands at *build* time — a manager cannot even
    // construct the transition, let alone get it accepted — so the
    // assertion covers building and verifying together rather than
    // presuming which step fails.
    const addBob = async (isManager: boolean) => {
      const add = await buildAddMember({
        crypto,
        state,
        signer: alice,
        currentGroupSecret: genesis.groupSecret,
        newMember: {
          user_id: "bob",
          device_pubkeys: [km.devicePublicKey(bob)],
          is_manager: isManager,
        },
      });
      return verifyWireTransition(
        crypto,
        state,
        add.wire,
        add.groupSecret,
        genesis.groupSecret,
      );
    };
    await expect(addBob(false)).rejects.toBeInstanceOf(PolicyViolationError);
    await expect(addBob(true)).rejects.toBeInstanceOf(PolicyViolationError);
  });

  it("leaves one way out: lowering the bar first", async () => {
    // Recoverable, but only by a move no one would guess from the error —
    // which is the whole reason the client refuses to create it.
    const alice = await km.generateDeviceKeys();
    const genesis = await buildGenesis({
      crypto,
      signer: alice,
      groupId: GROUP_ID,
      creatorUserId: "alice",
      policy: { min_managers: 3 },
    });
    const { state } = await verifyWireTransition(
      crypto,
      null,
      genesis.wire,
      genesis.groupSecret,
    );

    const lowered = await buildSetPolicy({
      crypto,
      state,
      signer: alice,
      currentGroupSecret: genesis.groupSecret,
      policy: { min_managers: 1 },
    });
    const { state: after } = await verifyWireTransition(
      crypto,
      state,
      lowered.wire,
      lowered.groupSecret,
      genesis.groupSecret,
    );
    expect(after.policy.min_managers).toBe(1);
  });
});
