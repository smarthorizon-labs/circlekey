/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Core-level end-to-end flow: encrypt a JSON payload as one device,
 * decrypt it as another, with the group secret travelling only inside
 * a sealed envelope, state accepted only through chain verification,
 * and records handled by the real `record-crypto` module.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { openAnyEnvelope } from "../src/core/envelopes";
import {
  buildAddMember,
  buildGenesis,
  buildRemoveMember,
  recoverSecretHistory,
  replayWireChain,
  verifyTransition,
} from "../src/core/epoch-chain";
import { CryptoError } from "../src/core/errors";
import { KeyManager } from "../src/core/key-manager";
import { RecordCrypto } from "../src/core/record-crypto";
import type { WireTransition } from "../src/core/types";
import { MemoryKeyUsageStore } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

describe("JSON payload round-trip across two devices", () => {
  it("encrypts as the manager and decrypts as a member added later", async () => {
    // Two independent devices, each with its own RecordCrypto + counter store.
    const aliceKeys = await km.generateDeviceKeys();
    const bobKeys = await km.generateDeviceKeys();
    const bobDevicePub = km.devicePublicKey(bobKeys);
    const aliceRecords = new RecordCrypto(crypto, new MemoryKeyUsageStore());
    const bobRecords = new RecordCrypto(crypto, new MemoryKeyUsageStore());

    // Alice creates the group and stores a record *before* Bob joins.
    const genesis = await buildGenesis({
      crypto,
      signer: aliceKeys,
      groupId: "toy-group",
      creatorUserId: "alice",
      policy: { min_managers: 1 },
    });
    let aliceState = await verifyTransition(crypto, null, genesis.transition);

    const preJoinPayload = { title: "Q3 report", body: "written before bob joined" };
    const preJoin = await aliceRecords.encryptJsonRecord(
      "toy-group", 0, genesis.groupSecret, "doc-0", preJoinPayload,
    );

    // Alice adds Bob.
    const add = await buildAddMember({
      crypto,
      state: aliceState,
      signer: aliceKeys,
      currentGroupSecret: genesis.groupSecret,
      newMember: { user_id: "bob", device_pubkeys: [bobDevicePub], is_manager: false },
    });
    aliceState = await verifyTransition(crypto, aliceState, add.transition);

    const currentPayload = { title: "meeting notes", attendees: ["alice", "bob"] };
    const current = await aliceRecords.encryptJsonRecord(
      "toy-group", 1, add.groupSecret, "doc-1", currentPayload,
    );

    // --- Bob's device: trusts nothing it hasn't verified itself. ---
    // Bob replays the wire chain: he opens his envelope for the newest
    // epoch, walks §9.7 back for the rest, then verifies forward.
    const chain: WireTransition[] = [genesis.wire, add.wire];
    const secrets = new Map([
      [0, genesis.groupSecret],
      [1, add.groupSecret],
    ]);
    const { state: bobState } = await replayWireChain(crypto, chain, secrets);
    expect(bobState).toEqual(aliceState);

    // The only secret material Bob receives is his sealed envelope,
    // which he finds by trial decryption (spec §6.5).
    const opened = await openAnyEnvelope(
      crypto,
      bobKeys.encryption,
      add.wire.secret_envelopes,
    );
    expect(opened).toBeDefined();
    if (opened === undefined) return;
    expect(opened.epoch).toBe(1);

    // Current record decrypts with the enveloped secret.
    expect(
      await bobRecords.decryptJsonRecord("toy-group", opened.groupSecret, current),
    ).toEqual(currentPayload);

    // Pre-join record decrypts via the §9.7 history chain.
    const history = await recoverSecretHistory(crypto, chain, opened.groupSecret);
    const epochZeroSecret = history.get(0);
    expect(epochZeroSecret).toBeDefined();
    if (epochZeroSecret === undefined) return;
    expect(
      await bobRecords.decryptJsonRecord("toy-group", epochZeroSecret, preJoin),
    ).toEqual(preJoinPayload);
  });

  it("keeps outsiders and removed members out", async () => {
    const aliceKeys = await km.generateDeviceKeys();
    const bobKeys = await km.generateDeviceKeys();
    const eveKeys = await km.generateDeviceKeys();
    const bobDevicePub = km.devicePublicKey(bobKeys);
    const records = new RecordCrypto(crypto, new MemoryKeyUsageStore());

    const genesis = await buildGenesis({
      crypto,
      signer: aliceKeys,
      groupId: "toy-group-2",
      creatorUserId: "alice",
      policy: { min_managers: 1 },
    });
    let state = await verifyTransition(crypto, null, genesis.transition);
    const add = await buildAddMember({
      crypto,
      state,
      signer: aliceKeys,
      currentGroupSecret: genesis.groupSecret,
      newMember: { user_id: "bob", device_pubkeys: [bobDevicePub], is_manager: false },
    });
    state = await verifyTransition(crypto, state, add.transition);

    // Eve (never a member) can open nothing in the array — not Bob's
    // envelope, not anyone's, and not a decoy.
    expect(
      await openAnyEnvelope(crypto, eveKeys.encryption, add.wire.secret_envelopes),
    ).toBeUndefined();

    // Alice removes Bob; the group rotates to a fresh secret.
    const remove = await buildRemoveMember({
      crypto,
      state,
      signer: aliceKeys,
      currentGroupSecret: add.groupSecret,
      userId: "bob",
    });
    await verifyTransition(crypto, state, remove.transition);

    // Nothing in the rotation opens for Bob (spec §9.3) — checked by
    // trial decryption across every slot, decoys included.
    expect(
      await openAnyEnvelope(crypto, bobKeys.encryption, remove.wire.secret_envelopes),
    ).toBeUndefined();

    // ...and a record written after the removal is out of Bob's reach:
    // every secret he holds fails authentication on the new record.
    const postRemoval = await records.encryptJsonRecord(
      "toy-group-2", 2, remove.groupSecret, "doc-2",
      { secret: "bob must not read this" },
    );
    await expect(
      records.decryptJsonRecord("toy-group-2", add.groupSecret, postRemoval),
    ).rejects.toBeInstanceOf(CryptoError);
  });
});
