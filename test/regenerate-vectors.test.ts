/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Regenerates `test/vectors/chain-v1.json`.
 *
 * Not a test — a generator that borrows vitest's TypeScript pipeline so
 * it needs no new tooling or dependency (the dependency allowlist is
 * closed). It is inert unless explicitly asked for:
 *
 *     REGEN_VECTORS=1 npx vitest run test/regenerate-vectors.test.ts
 *
 * **Regenerating is a deliberate act.** The vectors are the
 * interoperability reference (spec §6.5); a diff in them says the wire
 * format moved, which is a protocol change, not a build artifact
 * refresh. Run this only when a phase's spec changes require it, and
 * call the diff out in review.
 *
 * The device identity seeds and the group_id are **reused** from the
 * existing file rather than generated fresh, so the diff stays confined
 * to what actually changed. `group_secrets` are captured from the
 * builders, which mint them randomly.
 *
 * Chain: create → add → promote → set_policy ×2 → demote → remove.
 */

import { writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, bytesToBase64Url } from "../src/core/bytes";
import {
  buildAddMember,
  buildDemoteMember,
  buildGenesis,
  buildPromoteMember,
  buildRemoveMember,
  buildSetPolicy,
  replayWireChain,
  verifyWireTransition,
  type BuildResult,
} from "../src/core/epoch-chain";
import type { GroupState } from "../src/core/group-state";
import { KeyManager } from "../src/core/key-manager";
import type { WireTransition } from "../src/core/types";
import existing from "./vectors/chain-v1.json";

const OUTPUT = new URL("./vectors/chain-v1.json", import.meta.url);
const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

describe("chain vector generation", () => {
  it.runIf(process.env.REGEN_VECTORS === "1")(
    "regenerates chain-v1.json from the committed seeds",
    async () => {
      const groupId = existing.group_id;
      const alice = await km.deviceKeysFromIdentity(
        base64UrlToBytes(existing.devices.alice.identity_private_key),
      );
      const bob = await km.deviceKeysFromIdentity(
        base64UrlToBytes(existing.devices.bob.identity_private_key),
      );

      const wires: WireTransition[] = [];
      const groupSecrets: Record<string, string> = {};
      let state: GroupState;
      let secret: Uint8Array;

      const record = async (
        built: BuildResult,
        prev: GroupState | null,
      ): Promise<GroupState> => {
        const { state: next } = await verifyWireTransition(
          crypto,
          prev,
          built.wire,
          built.groupSecret,
        );
        wires.push(built.wire);
        groupSecrets[String(next.epoch)] = bytesToBase64Url(built.groupSecret);
        secret = built.groupSecret;
        return next;
      };

      const genesis = await buildGenesis({
        crypto,
        signer: alice,
        groupId,
        creatorUserId: "alice",
        policy: { min_managers: 1 },
      });
      state = await record(genesis, null);

      state = await record(
        await buildAddMember({
          crypto,
          state,
          signer: alice,
          currentGroupSecret: secret,
          newMember: {
            user_id: "bob",
            device_pubkeys: [km.devicePublicKey(bob)],
            is_manager: false,
          },
        }),
        state,
      );

      state = await record(
        await buildPromoteMember({
          crypto,
          state,
          signer: alice,
          currentGroupSecret: secret,
          userId: "bob",
        }),
        state,
      );

      for (const minManagers of [2, 1]) {
        state = await record(
          await buildSetPolicy({
            crypto,
            state,
            signer: alice,
            currentGroupSecret: secret,
            policy: { min_managers: minManagers },
          }),
          state,
        );
      }

      state = await record(
        await buildDemoteMember({
          crypto,
          state,
          signer: alice,
          currentGroupSecret: secret,
          userId: "bob",
        }),
        state,
      );

      state = await record(
        await buildRemoveMember({
          crypto,
          state,
          signer: alice,
          currentGroupSecret: secret,
          userId: "bob",
        }),
        state,
      );

      // The artifact must be valid before it is written: a vector file
      // that does not replay is worse than none, because every future
      // failure gets blamed on the code.
      const secrets = new Map(
        wires.map((wire) => [
          wire.epoch,
          base64UrlToBytes(groupSecrets[String(wire.epoch)] ?? ""),
        ]),
      );
      expect((await replayWireChain(crypto, wires, secrets)).state).toEqual(state);

      writeFileSync(
        OUTPUT,
        `${JSON.stringify(
          {
            _comment: existing._comment,
            group_id: groupId,
            devices: existing.devices,
            group_secrets: groupSecrets,
            transitions: wires,
            final_state: state,
          },
          null,
          2,
        )}\n`,
        "utf-8",
      );
    },
  );
});
