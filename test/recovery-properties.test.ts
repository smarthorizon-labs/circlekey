/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Recovery invariants over random sequences of facade operations.
 *
 * `chain-properties.test.ts` aims the same technique at `core/` — it
 * walks `buildAddMember`/`verifyTransition` directly. That is one layer
 * too low to see the bug class this file exists for: the `refresh` ×
 * `restore` defect lived at the seam between the backup manager and the
 * catch-up walk, and a generator scoped to the chain contains only one
 * side of that seam.
 *
 * So this walks `GroupVault` itself, with the operations a host
 * actually calls, and asserts what a host actually depends on: that a
 * device holding a valid recovery credential gets its access back, from
 * whatever state the group happens to be in.
 *
 * Deliberately *not* asserted: `secretHeld(e) ⟹ transitionStored(e)`.
 * That was the assumption the catch-up walk made, and `restore()`
 * violates it by design — the blob carries secrets and no transitions.
 * Asserting it would pin the bug rather than the requirement. The
 * requirement is recoverability, which is what these properties state.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { SecretUnavailableError, TransportError } from "../src/core/errors";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment } from "./helpers";

const crypto = new WebCryptoProvider();

/**
 * Cheaper than the shared `FAST_BACKUP`: a generated walk enrolls a
 * device per added member and per linked device, so the KDF is paid
 * tens of times per run. Nothing is lost by it — the KDF is not what
 * these properties are about, and `backup.test.ts` exercises both at
 * their real spec §6.2 parameters.
 *
 * It is not, however, where the time goes. Measured under full-suite
 * parallelism, dropping Argon2id barely moved the total: the dominant
 * cost is the transitions themselves (45 sealed envelope slots and an
 * 8 KiB body per epoch), so run counts are what keep this suite inside
 * its timeout. See the note on `numRuns` below.
 */
const CHEAP_BACKUP = { kdf: "pbkdf2-sha256" as const, kdfIterations: 1 };

function options(transport: Transport, userId: string, storage = new MemoryStore()) {
  return {
    transport,
    userId,
    crypto,
    storage,
    locks: new InProcessLockProvider(),
    requestPersistentStorage: false,
    backup: CHEAP_BACKUP,
  };
}

const OPS = ["addMember", "removeMember", "setPolicy", "putRecord", "linkDevice"] as const;
type Op = (typeof OPS)[number];

interface World {
  transport: MockTransport;
  owner: GroupVault;
  groupId: string;
  /** Non-owner members currently in the group. */
  members: { userId: string; vault: GroupVault }[];
  /** Extra devices linked to the owner's identity. */
  devices: GroupVault[];
  records: string[];
  n: number;
}

/** Only operations valid in the current state, so the walk stays legal. */
function applicable(world: World): Op[] {
  const ops: Op[] = ["setPolicy", "putRecord"];
  if (world.members.length < 3) ops.push("addMember");
  if (world.members.length > 0) ops.push("removeMember");
  if (world.devices.length < 2) ops.push("linkDevice");
  return ops;
}

async function apply(world: World, op: Op): Promise<void> {
  const { owner, groupId } = world;
  world.n += 1;
  switch (op) {
    case "addMember": {
      const userId = `user-${String(world.n)}`;
      const vault = await GroupVault.open(options(world.transport, userId));
      await completeEnrollment(vault);
      await owner.addMember(groupId, {
        userId,
        devicePubkey: vault.devicePublicKey(),
        isManager: false,
      });
      await vault.syncGroup(groupId);
      world.members.push({ userId, vault });
      return;
    }
    case "removeMember": {
      const victim = world.members.shift();
      if (victim === undefined) return;
      await owner.removeMember(groupId, victim.userId);
      victim.vault.close();
      return;
    }
    case "setPolicy":
      await owner.setPolicy(groupId, { min_managers: 1 });
      return;
    case "putRecord": {
      const key = `record-${String(world.n)}`;
      await owner.putJsonRecord(groupId, key, { step: world.n });
      world.records.push(key);
      return;
    }
    case "linkDevice": {
      const device = await GroupVault.open(options(world.transport, "owner"));
      await owner.linkDevice(device.devicePublicKey());
      await completeEnrollment(device);
      await device.syncGroup(groupId);
      world.devices.push(device);
      return;
    }
  }
}

function closeAll(world: World): void {
  world.owner.close();
  for (const m of world.members) m.vault.close();
  for (const d of world.devices) d.close();
}

describe("recovery invariants over random facade operation sequences", () => {
  it("a member with a valid credential always recovers to the head", async () => {
    // A generated walk that never walks proves nothing and looks
    // identical in the output, so the exploration is asserted below.
    const opsSeen = new Set<Op>();
    let longestWalk = 0;
    let refreshedRuns = 0;

    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.nat({ max: 999 }), { minLength: 3, maxLength: 5 }),
        fc.nat({ max: 999 }),
        async (choices, refreshChoice) => {
          const transport = new MockTransport();
          const owner = await GroupVault.open(options(transport, "owner"));
          const credential = await completeEnrollment(owner);
          const { group_id: groupId } = await owner.createGroup({ min_managers: 1 });

          const world: World = {
            transport,
            owner,
            groupId,
            members: [],
            devices: [],
            records: [],
            n: 0,
          };

          // Refresh lands at a random point *inside* the walk, so the
          // blob's snapshot is stale by a varying number of epochs —
          // including zero, and including "never".
          const refreshAt = refreshChoice % (choices.length + 1);
          if (refreshAt < choices.length) refreshedRuns += 1;

          for (const [index, choice] of choices.entries()) {
            if (index === refreshAt) await owner.refreshBackup(credential);
            const options_ = applicable(world);
            const op = options_[choice % options_.length];
            if (op === undefined) continue;
            opsSeen.add(op);
            await apply(world, op);
          }
          longestWalk = Math.max(longestWalk, world.n);

          const head = owner.getGroupState(groupId);
          expect(head).toBeDefined();

          // The property: whatever happened above, this credential
          // still restores a device that reaches the head.
          const store = new MemoryStore();
          const restored = await GroupVault.restore({
            ...options(transport, "owner", store),
            credential,
          });

          expect(restored.devicePublicKey()).toBe(owner.devicePublicKey());

          const state = await restored.syncGroup(groupId);
          expect(state.epoch).toBe(head?.epoch);
          expect(state.members.map((m) => m.user_id).sort()).toEqual(
            head?.members.map((m) => m.user_id).sort(),
          );

          // Verified, not merely reachable: the whole chain is stored,
          // contiguous from genesis.
          const stored = await store.getTransitions(groupId);
          expect(stored.map((t) => t.epoch)).toEqual(
            Array.from({ length: state.epoch + 1 }, (_, i) => i),
          );

          // Every record written before the restore is readable again.
          for (const key of world.records) {
            expect(await restored.getJsonRecord(groupId, key)).toEqual({
              step: Number(key.split("-")[1]),
            });
          }

          restored.close();
          closeAll(world);
        },
      ),
      // Low deliberately. At 10 runs this test measured ~26s of a 30s
      // timeout under full-suite parallelism — a flake waiting for a
      // slower CI runner, and the config is explicit that approaching
      // the bound means fixing the test rather than raising it.
      //
      // Exploration does not suffer the way it would for a one-shot:
      // fast-check reseeds on every execution, so coverage accumulates
      // across CI runs instead of within one. A failure prints its
      // shrunk counterexample and seed, which reproduces it exactly.
      { numRuns: 5 },
    );

    // The walk must genuinely have explored.
    expect(longestWalk).toBeGreaterThanOrEqual(3);
    // Tied to the declared alphabet rather than a literal, so adding an
    // operation raises the bar instead of silently leaving it uncovered.
    expect(opsSeen.size).toBeGreaterThanOrEqual(OPS.length - 1);
    // The refresh × restore crossing is the point of this suite; a run
    // set that never refreshed would test only the trivial path.
    expect(refreshedRuns).toBeGreaterThan(0);
  });

  it("a removed member fails as a loss of access, never as a transport fault", async () => {
    // The mirror property. Recovery must not paper over genuine removal
    // — but the way it stops has to name the cause, because a host maps
    // error types to what it tells the user.
    let removedRuns = 0;

    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.nat({ max: 999 }), { minLength: 1, maxLength: 4 }),
        fc.boolean(),
        async (choices, refreshBeforeRemoval) => {
          const transport = new MockTransport();
          const owner = await GroupVault.open(options(transport, "owner"));
          await completeEnrollment(owner);
          const { group_id: groupId } = await owner.createGroup({ min_managers: 1 });

          const victim = await GroupVault.open(options(transport, "victim"));
          const credential = await completeEnrollment(victim);
          await owner.addMember(groupId, {
            userId: "victim",
            devicePubkey: victim.devicePublicKey(),
            isManager: false,
          });
          await victim.syncGroup(groupId);
          if (refreshBeforeRemoval) await victim.refreshBackup(credential);

          const world: World = {
            transport,
            owner,
            groupId,
            members: [],
            devices: [],
            records: [],
            n: 0,
          };
          for (const choice of choices) {
            const options_ = applicable(world);
            const op = options_[choice % options_.length];
            if (op === undefined) continue;
            await apply(world, op);
          }
          await owner.removeMember(groupId, "victim");
          removedRuns += 1;

          const restored = await GroupVault.restore({
            ...options(transport, "victim"),
            credential,
          });

          // Which of the two correct outcomes applies is determined,
          // not incidental — so assert the specific one. Accepting
          // either would let this property pass while recovery was
          // entirely broken, since a broken recovery raises exactly the
          // error the removed case legitimately raises.
          const headEpoch = owner.getGroupState(groupId)?.epoch ?? Infinity;
          if (refreshBeforeRemoval) {
            // The blob holds the epochs the victim could read, so it
            // recovers that history and stops short of its removal —
            // which it never sees, being sealed out of it (spec §9.3).
            const state = await restored.syncGroup(groupId);
            expect(state.members.map((m) => m.user_id)).toContain("victim");
            expect(state.epoch).toBeLessThan(headEpoch);
          } else {
            // The blob predates the group entirely: nothing opens at
            // the head and nothing is held, so there is no history to
            // recover. It must say so as a loss of access, not as a
            // `TransportError` — a host mapping error types to user
            // text would otherwise blame the network.
            const failure = await restored
              .syncGroup(groupId)
              .then(() => undefined)
              .catch((error: unknown) => error);
            expect(failure).toBeInstanceOf(SecretUnavailableError);
            expect(failure).not.toBeInstanceOf(TransportError);
          }

          restored.close();
          victim.close();
          closeAll(world);
        },
      ),
      { numRuns: 5 },
    );

    expect(removedRuns).toBeGreaterThan(0);
  });
});
