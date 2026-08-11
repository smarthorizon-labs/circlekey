/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Frozen chain vectors (spec §9.1).
 *
 * `test/vectors/chain-v1.json` is FINAL: a fully signed, fully
 * enveloped seven-transition chain exercising all six actions. It
 * freezes signature input bytes, chain hashing, the device key model
 * (Ed25519 → X25519 binding), and the envelope format in one
 * artifact, and doubles as the interop reference for other
 * implementations. If this suite fails after a code change, the code
 * is wrong — fix the code, never the vectors.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, utf8String } from "../src/core/bytes";
import {
  openAnyEnvelope,
  openRemovalNotice,
  sealRemovalNotice,
} from "../src/core/envelopes";
import {
  openWireTransition,
  recoverSecretHistory,
  replayWireChain,
} from "../src/core/epoch-chain";
import {
  EnvelopeError,
  EpochGapError,
  MalformedTransitionError,
} from "../src/core/errors";
import { CAPACITY_PROFILES } from "../src/core/profiles";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import type { WireTransition } from "../src/core/types";
import { bytesToHex } from "./helpers";
import vectors from "./vectors/chain-v1.json";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

const wires = vectors.transitions as unknown as WireTransition[];
// The JSON import widens the policy enums to `string`.
const finalState = vectors.final_state as unknown as GroupState;
const groupSecrets: Record<string, string> = vectors.group_secrets;

async function deviceKeysOf(device: { identity_private_key: string }): Promise<DeviceKeys> {
  return km.deviceKeysFromIdentity(base64UrlToBytes(device.identity_private_key));
}

/**
 * Envelopes are unaddressed (spec §6.5), so "which envelope is mine"
 * is answered by trial decryption rather than by a recipient label.
 */
async function openFor(wire: WireTransition, keys: DeviceKeys) {
  return openAnyEnvelope(crypto, keys.encryption, wire.secret_envelopes);
}

/** Every committed secret, keyed by epoch — the input replay needs. */
const secrets = new Map(
  Object.entries(groupSecrets).map(([epoch, value]) => [
    Number(epoch),
    base64UrlToBytes(value),
  ]),
);

/** The inner body of a committed wire transition. */
async function innerOf(index: number) {
  const wire = wires[index];
  if (wire === undefined) throw new Error("vector shape");
  const secret = secrets.get(wire.epoch);
  if (secret === undefined) throw new Error("vector shape");
  return (await openWireTransition(crypto, wire, secret)).transition;
}

describe("chain-v1 vectors (FINAL)", () => {
  it("replays the full committed chain to the committed final state", async () => {
    const { state } = await replayWireChain(crypto, wires, secrets);
    expect(state).toEqual(finalState);
  });

  it("rebuilds the committed device keys from the committed seeds", async () => {
    const alice = await deviceKeysOf(vectors.devices.alice);
    expect(km.devicePublicKey(alice)).toBe(vectors.devices.alice.device_pubkey);
    expect(km.identityPublicKey(alice)).toBe(vectors.devices.alice.identity_public_key);
    const bob = await deviceKeysOf(vectors.devices.bob);
    expect(km.devicePublicKey(bob)).toBe(vectors.devices.bob.device_pubkey);
    expect(km.identityPublicKey(bob)).toBe(vectors.devices.bob.identity_public_key);
  });

  it("opens alice's envelope at every epoch to the committed group_secret", async () => {
    const alice = await deviceKeysOf(vectors.devices.alice);
    for (const transition of wires) {
      const opened = await openFor(transition, alice);
      expect(opened).toBeDefined();
      if (opened === undefined) continue;
      expect(opened.epoch).toBe(transition.epoch);
      expect(bytesToHex(opened.groupSecret)).toBe(
        bytesToHex(base64UrlToBytes(groupSecrets[String(transition.epoch)] ?? "")),
      );
    }
  });

  it("gives the added member the full secret history via the chain (spec §9.7)", async () => {
    const bob = await deviceKeysOf(vectors.devices.bob);
    const addTransition = wires[1];
    expect((await innerOf(1)).action).toBe("add");
    if (addTransition === undefined) return;

    // bob opens exactly one envelope — the current epoch. History
    // comes from walking the §9.7 chain, not from extra envelopes.
    const opened = await openFor(addTransition, bob);
    expect(opened).toBeDefined();
    if (opened === undefined) return;
    expect(opened.epoch).toBe(1);

    const recovered = await recoverSecretHistory(
      crypto,
      wires.slice(0, 2),
      opened.groupSecret,
    );
    expect(recovered.size).toBe(2);
    for (const epoch of [0, 1]) {
      expect(bytesToHex(recovered.get(epoch) ?? new Uint8Array(0))).toBe(
        bytesToHex(base64UrlToBytes(groupSecrets[String(epoch)] ?? "")),
      );
    }
  });

  it("recovers the entire history from the newest secret alone (spec §9.7)", async () => {
    const latest = base64UrlToBytes(groupSecrets["6"] ?? "");
    const recovered = await recoverSecretHistory(crypto, wires, latest);
    expect(recovered.size).toBe(7);
    for (let epoch = 0; epoch <= 6; epoch++) {
      expect(bytesToHex(recovered.get(epoch) ?? new Uint8Array(0))).toBe(
        bytesToHex(base64UrlToBytes(groupSecrets[String(epoch)] ?? "")),
      );
    }
  });

  it("stops enveloping to bob once removed (spec §9.3)", async () => {
    const removeTransition = wires[6];
    expect((await innerOf(6)).action).toBe("remove");
    if (removeTransition === undefined) return;
    expect(await openFor(removeTransition, await deviceKeysOf(vectors.devices.bob))).toBeUndefined();
  });

  // The signature now lives inside the sealed body, so the adversarial
  // equivalent is swapping the bodies themselves: each still opens for
  // whoever holds the epoch secret, and each still fails the AAD bound
  // to its position in the chain (spec §6.5).
  it("rejects the chain when two committed bodies are swapped (adversarial)", async () => {
    const tampered = wires.map((wire) => ({ ...wire }));
    const [t2, t3] = [tampered[2], tampered[3]];
    if (t2 === undefined || t3 === undefined) throw new Error("vector shape");
    const swap = t2.sealed_body;
    t2.sealed_body = t3.sealed_body;
    t3.sealed_body = swap;
    await expect(replayWireChain(crypto, tampered, secrets)).rejects.toBeInstanceOf(
      EnvelopeError,
    );
  });

  it("rejects the chain when a transition is dropped (adversarial)", async () => {
    const gapped = [...wires.slice(0, 3), ...wires.slice(4)];
    await expect(replayWireChain(crypto, gapped, secrets)).rejects.toBeInstanceOf(
      EpochGapError,
    );
  });
});

/**
 * The removal notice is part of the wire format (spec §6.5), so it is
 * part of the interop artifact too. `replayWireChain` above already runs
 * §9.1 check 11 over these vectors — it passes the previous epoch's
 * secret at every step — but a passing replay pins neither what the
 * notice *says* nor the property that makes it safe to carry. An
 * independent implementation checking itself against `chain-v1.json`
 * needs both spelled out.
 */
describe("chain-v1 vectors: the removal notice (spec §6.5)", () => {
  const NOTICE_SIZE = CAPACITY_PROFILES.lite.removalNoticeSize;
  const REMOVAL_EPOCH = 6;

  /** Open the notice on `wires[index]` with the epoch-before secret. */
  async function noticeAt(index: number): Promise<Uint8Array> {
    const wire = wires[index];
    if (wire?.removal_notice === undefined) throw new Error("vector shape");
    const previous = secrets.get(wire.epoch - 1);
    if (previous === undefined) throw new Error("vector shape");
    return openRemovalNotice(
      crypto,
      wire.group_id,
      wire.epoch,
      previous,
      wire.removal_notice,
      NOTICE_SIZE,
    );
  }

  it("names exactly the removed device, signed by the acting manager", async () => {
    expect((await innerOf(REMOVAL_EPOCH)).action).toBe("remove");
    const bytes = await noticeAt(REMOVAL_EPOCH);
    const notice = JSON.parse(utf8String(bytes)) as {
      group_id: string;
      epoch: number;
      removed_devices: string[];
      signed_by: string;
    };

    expect(notice.group_id).toBe(vectors.group_id);
    expect(notice.epoch).toBe(REMOVAL_EPOCH);
    expect(notice.removed_devices).toEqual([vectors.devices.bob.device_pubkey]);
    expect(notice.signed_by).toBe(vectors.devices.alice.identity_public_key);
    // What it deliberately does not carry: who remains (spec §9.3).
    expect(utf8String(bytes)).not.toContain(vectors.devices.alice.device_pubkey);
  });

  it("is readable by the member it removes, using the secret they still hold", async () => {
    // The whole point of sealing under `group_secret[e-1]`: bob never
    // receives epoch 6, and can still be told he was removed at it.
    const removal = wires[REMOVAL_EPOCH];
    if (removal === undefined) throw new Error("vector shape");
    expect(await openFor(removal, await deviceKeysOf(vectors.devices.bob))).toBeUndefined();
    await expect(noticeAt(REMOVAL_EPOCH)).resolves.not.toHaveLength(0);
  });

  it("seals an empty notice on every transition that removes nothing", async () => {
    for (let epoch = 1; epoch < wires.length; epoch++) {
      if (epoch === REMOVAL_EPOCH) continue;
      expect(await noticeAt(epoch)).toHaveLength(0);
    }
  });

  it("is the same size whether or not it says anything (spec §5.8)", () => {
    // The indistinguishability property, frozen in the artifact: a relay
    // that can see all seven blobs cannot tell which epoch removed
    // someone, nor whether the group suppresses notices at all.
    const sizes = new Set(
      wires.slice(1).map((wire) => (wire.removal_notice ?? "").length),
    );
    expect(sizes.size).toBe(1);
    expect(wires[0]?.removal_notice).toBeUndefined(); // genesis removes nothing
  });

  it("is bound to its own epoch and group by the AAD (adversarial)", async () => {
    const removal = wires[REMOVAL_EPOCH];
    const correct = secrets.get(REMOVAL_EPOCH - 1);
    if (removal?.removal_notice === undefined || correct === undefined) {
      throw new Error("vector shape");
    }
    // The *correct* key each time — only the AAD differs, so nothing
    // here can pass by accident of key derivation.
    for (const [groupId, epoch] of [
      [removal.group_id, REMOVAL_EPOCH - 1],
      ["some-other-group", REMOVAL_EPOCH],
    ] as const) {
      await expect(
        openRemovalNotice(
          crypto,
          groupId,
          epoch,
          correct,
          removal.removal_notice,
          NOTICE_SIZE,
        ),
      ).rejects.toBeInstanceOf(EnvelopeError);
    }
  });

  it("rejects the chain when the removal is stripped of its notice", async () => {
    // Proves check 11 genuinely runs over these vectors rather than
    // being skipped for want of a previous secret — without this, every
    // assertion above could hold while the replay ignored the field.
    //
    // The substitute is a *correctly* sealed empty notice for this exact
    // group and epoch, so it decrypts cleanly and only check 11 can
    // refuse it. Borrowing another epoch's blob would fail at the AAD
    // instead and prove nothing about the policy rule.
    const tampered = wires.map((wire) => ({ ...wire }));
    const removal = tampered[REMOVAL_EPOCH];
    const previous = secrets.get(REMOVAL_EPOCH - 1);
    if (removal === undefined || previous === undefined) throw new Error("vector shape");
    removal.removal_notice = await sealRemovalNotice(
      crypto,
      removal.group_id,
      removal.epoch,
      previous,
      new Uint8Array(0),
      NOTICE_SIZE,
    );

    await expect(replayWireChain(crypto, tampered, secrets)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });
});
