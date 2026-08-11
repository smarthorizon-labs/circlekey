/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Invariants over *random* sequences of valid operations, rather than
 * the fixed scripts the other suites walk. Property testing has
 * already earned its place in this repo — it found the `__proto__`
 * canonicalization defect — and this aims the same technique at the
 * security core: whatever order a group evolves in, the §9.1 chain
 * rules and the §8.1 governance invariant must survive.
 *
 * Each step picks uniformly among the operations that are *currently
 * applicable*, so the walk stays inside the protocol while still
 * reaching states no hand-written test enumerates.
 */

import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import {
  buildAddDevice,
  buildAddMember,
  buildDemoteMember,
  buildGenesis,
  buildPromoteMember,
  buildRemoveDevice,
  buildRemoveMember,
  buildSetPolicy,
  recoverSecretHistory,
  replayChain,
  replayWireChain,
  verifyTransition,
  type BuildResult,
} from "../src/core/epoch-chain";
import { managerCount, satisfiesPolicy, type GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import type { WireTransition } from "../src/core/types";
import { bytesToHex } from "./helpers";
import { CAPACITY_PROFILES } from "../src/core/profiles";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

/** Reused so the walk spends its time on the protocol, not keygen. */
interface Actor {
  userId: string;
  keys: DeviceKeys;
  devicePub: string;
}
let pool: Actor[] = [];
/** Spare device keys for add_device. */
let sparePubkeys: string[] = [];

beforeAll(async () => {
  pool = await Promise.all(
    ["alice", "bob", "carol", "dave"].map(async (userId) => {
      const keys = await km.generateDeviceKeys();
      return { userId, keys, devicePub: km.devicePublicKey(keys) };
    }),
  );
  sparePubkeys = await Promise.all(
    Array.from({ length: 4 }, async () =>
      km.devicePublicKey(await km.generateDeviceKeys()),
    ),
  );
});

interface Walk {
  state: GroupState;
  chain: WireTransition[];
  secrets: Map<number, Uint8Array>;
  current: Uint8Array;
}

/** An operation that is legal in the current state. */
type Step = (walk: Walk) => Promise<BuildResult>;

function applicableSteps(walk: Walk): Step[] {
  const { state } = walk;
  const steps: Step[] = [];
  const members = state.members;
  const signerFor = (userId: string): DeviceKeys | undefined =>
    pool.find((actor) => actor.userId === userId)?.keys;
  const managers = members.filter((m) => m.is_manager);
  const anyManager = managers[0];
  if (anyManager === undefined) return steps; // unreachable: policy ≥ 1
  const managerKeys = signerFor(anyManager.user_id);
  if (managerKeys === undefined) return steps;
  const common = { crypto, state, currentGroupSecret: walk.current };

  // add: any pooled user not yet in the group.
  const absent = pool.find(
    (actor) => !members.some((m) => m.user_id === actor.userId),
  );
  if (absent !== undefined) {
    steps.push(() =>
      buildAddMember({
        ...common,
        signer: managerKeys,
        newMember: {
          user_id: absent.userId,
          device_pubkeys: [absent.devicePub],
          is_manager: false,
        },
      }),
    );
  }

  // remove: any member whose departure keeps min_managers satisfied.
  for (const target of members) {
    const after = members.filter((m) => m.user_id !== target.user_id);
    if (after.length === 0 || !satisfiesPolicy(after, state.policy)) continue;
    steps.push(() =>
      buildRemoveMember({ ...common, signer: managerKeys, userId: target.user_id }),
    );
  }

  // promote / demote, subject to the same invariant.
  for (const target of members) {
    if (!target.is_manager) {
      steps.push(() =>
        buildPromoteMember({ ...common, signer: managerKeys, userId: target.user_id }),
      );
      continue;
    }
    const after = members.map((m) =>
      m.user_id === target.user_id ? { ...m, is_manager: false } : m,
    );
    if (satisfiesPolicy(after, state.policy)) {
      steps.push(() =>
        buildDemoteMember({ ...common, signer: managerKeys, userId: target.user_id }),
      );
    }
  }

  // set_policy: any value the current manager count already satisfies.
  for (const minManagers of [1, 2]) {
    if (managerCount(members) >= minManagers) {
      steps.push(() =>
        buildSetPolicy({
          ...common,
          signer: managerKeys,
          policy: { min_managers: minManagers },
        }),
      );
    }
  }

  // add_device / remove_device: self-scoped, so signed by the owner.
  const used = new Set(members.flatMap((m) => m.device_pubkeys));
  const spare = sparePubkeys.find((key) => !used.has(key));
  for (const target of members) {
    const ownerKeys = signerFor(target.user_id);
    if (ownerKeys === undefined) continue;
    if (spare !== undefined) {
      steps.push(() =>
        buildAddDevice({
          ...common,
          signer: ownerKeys,
          newDevicePubkey: spare,
        }),
      );
    }
    if (target.device_pubkeys.length > 1) {
      const removable = target.device_pubkeys[target.device_pubkeys.length - 1];
      if (removable !== undefined) {
        steps.push(() =>
          buildRemoveDevice({ ...common, signer: ownerKeys, devicePubkey: removable }),
        );
      }
    }
  }

  return steps;
}

describe("chain invariants over random operation sequences", () => {
  it("every reachable state satisfies the §9.1 and §8.1 rules", async () => {
    // Guards against the walk passing vacuously: a property that never
    // takes a step proves nothing, and would look identical here.
    const actionsSeen = new Set<string>();
    let longestWalk = 0;

    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.nat({ max: 999 }), { minLength: 3, maxLength: 7 }),
        async (choices) => {
          const creator = pool[0];
          if (creator === undefined) throw new Error("pool not initialised");

          const genesis = await buildGenesis({
            crypto,
            signer: creator.keys,
            groupId: "prop-group",
            creatorUserId: creator.userId,
            policy: { min_managers: 1 },
          });
          const walk: Walk = {
            state: await verifyTransition(crypto, null, genesis.transition),
            chain: [genesis.wire],
            secrets: new Map([[0, genesis.groupSecret]]),
            current: genesis.groupSecret,
          };

          for (const choice of choices) {
            const steps = applicableSteps(walk);
            if (steps.length === 0) break;
            const step = steps[choice % steps.length];
            if (step === undefined) break;

            const before = walk.state;
            const result = await step(walk);
            const next = await verifyTransition(crypto, before, result.transition);

            // §9.1 check 1: epochs advance by exactly one.
            expect(next.epoch).toBe(before.epoch + 1);
            // §9.1 check 2: the chain links to what we just accepted.
            expect(result.transition.prev_transition_hash).toBe(
              before.last_transition_hash,
            );
            // §8.1: the governance invariant holds after *every* step.
            expect(satisfiesPolicy(next.members, next.policy)).toBe(true);
            // A group can never lose its last member or a member their
            // last device.
            expect(next.members.length).toBeGreaterThan(0);
            for (const member of next.members) {
              expect(member.device_pubkeys.length).toBeGreaterThan(0);
            }
            // spec §6.5: envelopes are unaddressed, so completeness is
            // asserted through `envelope_slots` — one distinct slot per
            // current device, inside a fully padded array.
            const devices = next.members.flatMap((m) => m.device_pubkeys);
            expect(result.transition.envelope_slots).toHaveLength(devices.length);
            expect(new Set(result.transition.envelope_slots).size).toBe(devices.length);
            expect(result.wire.secret_envelopes).toHaveLength(
              CAPACITY_PROFILES.lite.envelopeSlots,
            );
            for (const slot of result.transition.envelope_slots) {
              expect(slot).toBeGreaterThanOrEqual(0);
              expect(slot).toBeLessThan(CAPACITY_PROFILES.lite.envelopeSlots);
            }

            actionsSeen.add(result.transition.action);
            walk.state = next;
            walk.chain.push(result.wire);
            walk.secrets.set(next.epoch, result.groupSecret);
            walk.current = result.groupSecret;
          }
          longestWalk = Math.max(longestWalk, walk.chain.length - 1);

          // Replaying the whole chain reproduces the incremental fold.
          expect((await replayWireChain(crypto, walk.chain, walk.secrets)).state).toEqual(
            walk.state,
          );

          // §9.7: the newest secret alone recovers every earlier one.
          const recovered = await recoverSecretHistory(
            crypto,
            walk.chain,
            walk.current,
          );
          expect(recovered.size).toBe(walk.secrets.size);
          for (const [epoch, secret] of walk.secrets) {
            expect(bytesToHex(recovered.get(epoch) ?? new Uint8Array())).toBe(
              bytesToHex(secret),
            );
          }
        },
      ),
      { numRuns: 12 },
    );

    // The walk must genuinely have explored, not short-circuited.
    expect(longestWalk).toBeGreaterThanOrEqual(3);
    expect(actionsSeen.size).toBeGreaterThanOrEqual(3);
    // Device actions share the verification path with governance ones,
    // so the walk is only meaningful if it reaches both kinds.
    expect(
      [...actionsSeen].some((action) => action.endsWith("_device")),
    ).toBe(true);
  }, 120_000);

  it("rejects any transition replayed out of its position", async () => {
    // Built once, then offered at the wrong point in the chain.
    const creator = pool[0];
    if (creator === undefined) throw new Error("pool not initialised");
    const genesis = await buildGenesis({
      crypto,
      signer: creator.keys,
      groupId: "prop-replay",
      creatorUserId: creator.userId,
      policy: { min_managers: 1 },
    });
    let state = await verifyTransition(crypto, null, genesis.transition);
    const chain = [genesis.transition];
    let secret = genesis.groupSecret;

    for (let i = 0; i < 3; i++) {
      const built = await buildSetPolicy({
        crypto,
        state,
        signer: creator.keys,
        currentGroupSecret: secret,
        policy: { min_managers: 1 },
      });
      state = await verifyTransition(crypto, state, built.transition);
      chain.push(built.transition);
      secret = built.groupSecret;
    }

    // Every earlier transition must be refused against the head.
    for (const stale of chain.slice(0, -1)) {
      await expect(verifyTransition(crypto, state, stale)).rejects.toThrow();
    }
    // And truncating the chain must not replay.
    await expect(replayChain(crypto, chain.slice(0, 2).concat(chain[3] ?? []))).rejects.toThrow();
  });
});
