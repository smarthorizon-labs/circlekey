/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * spec §9.1 checklist: every check has accept AND reject coverage
 * (the testing bar — proving we refuse bad input matters more
 * than proving we accept good input).
 */

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import type { UnsignedEpochTransition } from "../src/core/codec";
import { placeEnvelopes, sealEnvelope } from "../src/core/envelopes";
import { profileForPolicy } from "../src/core/profiles";
import {
  buildAddMember,
  buildDemoteMember,
  buildGenesis,
  buildPromoteMember,
  buildRemoveMember,
  buildSetPolicy,
  recoverSecretHistory,
  replayChain,
  signTransition,
  verifyTransition,
  type BuildResult,
} from "../src/core/epoch-chain";
import {
  BadSignatureError,
  ChainMismatchError,
  EpochGapError,
  MalformedTransitionError,
  PolicyViolationError,
  UnauthorizedSignerError,
} from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import type {
  EpochTransition,
  WireTransition,
  GroupPolicy,
  MemberEntry,
  SecretEnvelope,
  TransitionAction,
} from "../src/core/types";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);
const GROUP_ID = "test-group";

interface Actor {
  userId: string;
  keys: DeviceKeys;
  devicePub: string;
  identityPub: string;
}

async function makeActor(userId: string): Promise<Actor> {
  const keys = await km.generateDeviceKeys();
  return {
    userId,
    keys,
    devicePub: km.devicePublicKey(keys),
    identityPub: km.identityPublicKey(keys),
  };
}

function memberOf(actor: Actor, isManager: boolean): MemberEntry {
  return {
    user_id: actor.userId,
    device_pubkeys: [actor.devicePub],
    is_manager: isManager,
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Clone, mutate, and re-sign so only the check under test fails. */
async function resign(
  transition: EpochTransition,
  signer: Actor,
  mutate: (draft: EpochTransition) => void,
): Promise<EpochTransition> {
  const draft = clone(transition);
  mutate(draft);
  const unsigned: Record<string, unknown> = { ...draft };
  delete unsigned.signature;
  return signTransition(
    crypto,
    unsigned as unknown as UnsignedEpochTransition,
    signer.keys.identity.privateKey,
  );
}

/** Hand-craft a transition the builders would refuse to produce. */
async function craft(options: {
  state: GroupState;
  action: TransitionAction;
  members: MemberEntry[];
  signer: Actor;
  policy?: GroupPolicy;
  epoch?: number;
  prevHash?: string;
  envelopes?: SecretEnvelope[];
  /** Override the padded array length (spec §6.5 slot count). */
  slotCount?: number;
  /** Override the slot map, to forge a mismatch. */
  slots?: number[];
}): Promise<EpochTransition> {
  const epoch = options.epoch ?? options.state.epoch + 1;
  let real = options.envelopes;
  if (real === undefined) {
    const secret = crypto.randomBytes(32);
    real = [];
    for (const member of options.members) {
      for (const device of member.device_pubkeys) {
        real.push(await sealEnvelope(crypto, device, epoch, secret));
      }
    }
  }
  // spec §6.5: pad to the profile's slots, exactly as the real builder
  // does, so drafts are rejected for the reason under test rather than
  // for having the wrong array length.
  const slotCount =
    options.slotCount ?? profileForPolicy(options.policy ?? options.state.policy).envelopeSlots;
  const placed = placeEnvelopes(crypto, real, epoch, slotCount);
  const base = {
    group_id: options.state.group_id,
    epoch,
    prev_transition_hash: options.prevHash ?? options.state.last_transition_hash,
    action: options.action,
    members: options.members,
    envelope_slots: options.slots ?? placed.slots,
    signed_by: options.signer.identityPub,
  };
  const unsigned: UnsignedEpochTransition =
    options.policy === undefined ? base : { ...base, policy: options.policy };
  return signTransition(crypto, unsigned, options.signer.keys.identity.privateKey);
}

// Shared two-member fixture: alice (manager) + bob (regular), min_managers 1.
let alice: Actor;
let bob: Actor;
let carol: Actor;
let genesis: BuildResult;
let state0: GroupState;
let addBob: BuildResult;
let state1: GroupState;
let promoteBob: BuildResult; // built against state1, not applied

beforeAll(async () => {
  alice = await makeActor("alice");
  bob = await makeActor("bob");
  carol = await makeActor("carol");
  genesis = await buildGenesis({
    crypto,
    signer: alice.keys,
    groupId: GROUP_ID,
    creatorUserId: alice.userId,
    policy: { min_managers: 1 },
  });
  state0 = await verifyTransition(crypto, null, genesis.transition);
  addBob = await buildAddMember({
    crypto,
    state: state0,
    signer: alice.keys,
    currentGroupSecret: genesis.groupSecret,
    newMember: memberOf(bob, false),
  });
  state1 = await verifyTransition(crypto, state0, addBob.transition);
  promoteBob = await buildPromoteMember({
    crypto,
    state: state1,
    signer: alice.keys,
    currentGroupSecret: addBob.groupSecret,
    userId: bob.userId,
  });
});

describe("genesis verification (spec §9.1 genesis checklist)", () => {
  it("accepts a valid genesis and produces epoch-0 state", () => {
    expect(state0.epoch).toBe(0);
    expect(state0.group_id).toBe(GROUP_ID);
    expect(state0.members).toEqual([memberOf(alice, true)]);
    // Genesis materializes both optional fields, so verified state
    // carries them: they drive the padded sizes and check 11.
    expect(state0.policy).toEqual({
      min_managers: 1,
      capacity: "lite",
      removal_notice: "required",
    });
    expect(state0.last_transition_hash).toHaveLength(43);
  });

  it("rejects genesis with epoch != 0 (check 1)", async () => {
    const bad = await resign(genesis.transition, alice, (draft) => {
      draft.epoch = 1;
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      EpochGapError,
    );
  });

  it("rejects genesis whose prev hash is not the genesis marker (check 2)", async () => {
    const bad = await resign(genesis.transition, alice, (draft) => {
      draft.prev_transition_hash = "A".repeat(43);
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      ChainMismatchError,
    );
  });

  it("rejects genesis with more than one member (check 3)", async () => {
    const bad = await resign(genesis.transition, alice, (draft) => {
      draft.members.push(memberOf(bob, false));
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects genesis whose creator is not a manager (check 3)", async () => {
    const bad = await resign(genesis.transition, alice, (draft) => {
      const creator = draft.members[0];
      if (creator) creator.is_manager = false;
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects genesis without a policy", async () => {
    const bad = await resign(genesis.transition, alice, (draft) => {
      delete draft.policy;
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects genesis signed by a key that is not the creator's device", async () => {
    const bad = await resign(genesis.transition, bob, (draft) => {
      draft.signed_by = bob.identityPub;
    });
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects genesis with an invalid signature", async () => {
    const bad = clone(genesis.transition);
    bad.signature = `${"A".repeat(85)}A`;
    await expect(verifyTransition(crypto, null, bad)).rejects.toBeInstanceOf(
      BadSignatureError,
    );
  });

  it("rejects a non-create transition when no state exists", async () => {
    await expect(
      verifyTransition(crypto, null, addBob.transition),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });
});

describe("check 1 — epoch strictly current + 1", () => {
  it("accepts the exact successor epoch", async () => {
    const state2 = await verifyTransition(crypto, state1, promoteBob.transition);
    expect(state2.epoch).toBe(2);
  });

  it("rejects a replayed transition (same epoch)", async () => {
    await expect(
      verifyTransition(crypto, state1, addBob.transition),
    ).rejects.toBeInstanceOf(EpochGapError);
  });

  it("rejects an epoch gap", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      draft.epoch = 4;
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      EpochGapError,
    );
  });

  it("rejects a rollback to an older epoch", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      draft.epoch = 0;
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      EpochGapError,
    );
  });
});

describe("check 2 — hash-chain continuity", () => {
  it("rejects a transition referencing a different previous transition", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      draft.prev_transition_hash = "B".repeat(43);
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      ChainMismatchError,
    );
  });
});

describe("check 3 — signer was a manager before the transition", () => {
  it("rejects a transition signed by a regular member", async () => {
    const bad = await resign(promoteBob.transition, bob, (draft) => {
      draft.signed_by = bob.identityPub;
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects a transition signed by a non-member (fabricated by a backend)", async () => {
    const bad = await resign(promoteBob.transition, carol, (draft) => {
      draft.signed_by = carol.identityPub;
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects a demoted manager acting on stale authority", async () => {
    // alice promotes bob; bob demotes alice; alice then tries to act.
    const promoted = await verifyTransition(crypto, state1, promoteBob.transition);
    const demoteAlice = await buildDemoteMember({
      crypto,
      state: promoted,
      signer: bob.keys,
      currentGroupSecret: promoteBob.groupSecret,
      userId: alice.userId,
    });
    const afterDemote = await verifyTransition(crypto, promoted, demoteAlice.transition);
    const stale = await craft({
      state: afterDemote,
      action: "remove",
      members: [memberOf(alice, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, afterDemote, stale)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });
});

describe("check 4 — Ed25519 signature over the transition", () => {
  it("rejects a flipped signature", async () => {
    const bad = clone(promoteBob.transition);
    bad.signature = bad.signature.startsWith("A")
      ? `B${bad.signature.slice(1)}`
      : `A${bad.signature.slice(1)}`;
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      BadSignatureError,
    );
  });

  it("rejects content tampered after signing", async () => {
    const bad = clone(promoteBob.transition);
    const target = bad.members.find((member) => member.user_id === alice.userId);
    if (target) target.is_manager = false;
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      BadSignatureError,
    );
  });

  it("rejects malformed signature encodings", async () => {
    const short = clone(promoteBob.transition);
    short.signature = "AAAA";
    await expect(verifyTransition(crypto, state1, short)).rejects.toBeInstanceOf(
      BadSignatureError,
    );
    const garbage = clone(promoteBob.transition);
    garbage.signature = "!not-base64url!";
    await expect(verifyTransition(crypto, state1, garbage)).rejects.toBeInstanceOf(
      BadSignatureError,
    );
  });
});

describe("check 5 — min_managers holds after every individual transition", () => {
  it("rejects removing the sole manager (self-removal)", async () => {
    const bad = await craft({
      state: state1,
      action: "remove",
      members: [memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
  });

  it("rejects a set_policy raising min_managers above the manager count", async () => {
    const bad = await craft({
      state: state1,
      action: "set_policy",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
      policy: { min_managers: 2 },
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
  });

  it("rejects a demote that transiently violates min_managers (transfer rule, spec §8)", async () => {
    // Build a min_managers=2 group with alice+bob managers.
    const promoted = await verifyTransition(crypto, state1, promoteBob.transition);
    const raise = await buildSetPolicy({
      crypto,
      state: promoted,
      signer: alice.keys,
      currentGroupSecret: promoteBob.groupSecret,
      policy: { min_managers: 2 },
    });
    const strict = await verifyTransition(crypto, promoted, raise.transition);
    const bad = await craft({
      state: strict,
      action: "demote",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, strict, bad)).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
  });
});

describe("action semantics", () => {
  it("rejects an add that also changes a flag", async () => {
    const bad = await craft({
      state: state1,
      action: "add",
      members: [memberOf(alice, true), memberOf(bob, true), memberOf(carol, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects an add that adds nothing", async () => {
    const bad = await craft({
      state: state1,
      action: "add",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a remove that removes two members", async () => {
    const addCarol = await buildAddMember({
      crypto,
      state: state1,
      signer: alice.keys,
      currentGroupSecret: addBob.groupSecret,
      newMember: memberOf(carol, false),
    });
    const state2 = await verifyTransition(crypto, state1, addCarol.transition);
    const bad = await craft({
      state: state2,
      action: "remove",
      members: [memberOf(alice, true)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state2, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects promoting someone who is already a manager", async () => {
    const bad = await craft({
      state: state1,
      action: "promote",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a demote of a non-manager", async () => {
    const bad = await craft({
      state: state1,
      action: "demote",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a set_policy that also mutates the member set", async () => {
    const bad = await craft({
      state: state1,
      action: "set_policy",
      members: [memberOf(alice, true)],
      signer: alice,
      policy: { min_managers: 1 },
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a set_policy without a policy", async () => {
    const bad = await craft({
      state: state1,
      action: "set_policy",
      members: [memberOf(alice, true), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a policy on actions other than create/set_policy", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      draft.policy = { min_managers: 1 };
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a create after genesis", async () => {
    const bad = await craft({
      state: state1,
      action: "create",
      members: [memberOf(alice, true)],
      signer: alice,
      policy: { min_managers: 1 },
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a transition for a different group", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      draft.group_id = "another-group";
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects device-set changes to existing members (handled by the self-scoped device actions)", async () => {
    const bad = await resign(promoteBob.transition, alice, (draft) => {
      const entry = draft.members.find((member) => member.user_id === bob.userId);
      entry?.device_pubkeys.push(carol.devicePub);
    });
    await expect(verifyTransition(crypto, state1, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects duplicate users and duplicate devices", async () => {
    const dupUser = await craft({
      state: state1,
      action: "add",
      members: [memberOf(alice, true), memberOf(bob, false), memberOf(bob, false)],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, dupUser)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
    const carolWithBobsDevice: MemberEntry = {
      user_id: carol.userId,
      device_pubkeys: [bob.devicePub],
      is_manager: false,
    };
    const dupDevice = await craft({
      state: state1,
      action: "add",
      members: [memberOf(alice, true), memberOf(bob, false), carolWithBobsDevice],
      signer: alice,
    });
    await expect(verifyTransition(crypto, state1, dupDevice)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });
});

// The envelope-completeness and history-link checks moved to
// test/sealed-body.test.ts: both concern the *outer*
// WireTransition, which `verifyTransition` no longer sees. Mutating
// them needs no re-signing, since only the inner body is signed.

describe("build-side mirrors of the invariants", () => {
  it("refuses to build when the signer is not a manager", async () => {
    await expect(
      buildRemoveMember({
        crypto,
        state: state1,
        signer: bob.keys,
        currentGroupSecret: addBob.groupSecret,
        userId: alice.userId,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedSignerError);
  });

  it("refuses to build a policy-violating transition", async () => {
    const base = {
      crypto,
      state: state1,
      signer: alice.keys,
      currentGroupSecret: addBob.groupSecret,
    };
    await expect(
      buildRemoveMember({ ...base, userId: alice.userId }),
    ).rejects.toBeInstanceOf(PolicyViolationError);
    await expect(
      buildDemoteMember({ ...base, userId: alice.userId }),
    ).rejects.toBeInstanceOf(PolicyViolationError);
    await expect(
      buildSetPolicy({ ...base, policy: { min_managers: 2 } }),
    ).rejects.toBeInstanceOf(PolicyViolationError);
  });

  it("refuses invalid membership edits", async () => {
    const base = {
      crypto,
      state: state1,
      signer: alice.keys,
      currentGroupSecret: addBob.groupSecret,
    };
    await expect(
      buildAddMember({ ...base, newMember: memberOf(bob, false) }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
    await expect(
      buildRemoveMember({ ...base, userId: "nobody" }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
    await expect(
      buildPromoteMember({ ...base, userId: alice.userId }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
    await expect(
      buildDemoteMember({ ...base, userId: bob.userId }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });
});

describe("full chain round-trip", () => {
  it("verifies create → add → promote → set_policy ×2 → demote → remove and replays identically", async () => {
    const a = await makeActor("alice");
    const b = await makeActor("bob");
    const chain: EpochTransition[] = [];
    const wires: WireTransition[] = [];
    const secrets = new Map<number, Uint8Array>();

    const g = await buildGenesis({
      crypto,
      signer: a.keys,
      groupId: "round-trip-group",
      creatorUserId: a.userId,
      policy: { min_managers: 1 },
    });
    chain.push(g.transition);
    wires.push(g.wire);
    secrets.set(0, g.groupSecret);
    let state = await verifyTransition(crypto, null, g.transition);

    let currentSecret = g.groupSecret;
    const apply = async (result: BuildResult) => {
      state = await verifyTransition(crypto, state, result.transition);
      chain.push(result.transition);
      wires.push(result.wire);
      secrets.set(state.epoch, result.groupSecret);
      currentSecret = result.groupSecret;
    };

    await apply(
      await buildAddMember({
        crypto,
        state,
        signer: a.keys,
        currentGroupSecret: currentSecret,
        newMember: memberOf(b, false),
      }),
    );
    await apply(
      await buildPromoteMember({
        crypto,
        state,
        signer: a.keys,
        currentGroupSecret: currentSecret,
        userId: b.userId,
      }),
    );
    // bob, freshly promoted, exercises non-creator manager authority.
    await apply(
      await buildSetPolicy({
        crypto,
        state,
        signer: b.keys,
        currentGroupSecret: currentSecret,
        policy: { min_managers: 2 },
      }),
    );
    await apply(
      await buildSetPolicy({
        crypto,
        state,
        signer: a.keys,
        currentGroupSecret: currentSecret,
        policy: { min_managers: 1 },
      }),
    );
    await apply(
      await buildDemoteMember({
        crypto,
        state,
        signer: a.keys,
        currentGroupSecret: currentSecret,
        userId: b.userId,
      }),
    );
    await apply(
      await buildRemoveMember({
        crypto,
        state,
        signer: a.keys,
        currentGroupSecret: currentSecret,
        userId: b.userId,
      }),
    );

    expect(state.epoch).toBe(6);
    expect(state.members).toEqual([memberOf(a, true)]);
    expect(state.policy).toEqual({
      min_managers: 1,
      capacity: "lite",
      removal_notice: "required",
    });

    const replayed = await replayChain(crypto, chain);
    expect(replayed).toEqual(state);

    // spec §9.7: the newest secret alone recovers the whole history.
    const recovered = await recoverSecretHistory(crypto, wires, currentSecret);
    expect(recovered.size).toBe(7);
    for (const [epoch, secret] of secrets) {
      expect(recovered.get(epoch)).toEqual(secret);
    }
  });

  it("rejects replaying an empty chain", async () => {
    await expect(replayChain(crypto, [])).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });
});
