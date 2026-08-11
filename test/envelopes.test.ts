/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, bytesToBase64Url } from "../src/core/bytes";
import {
  envelopeEpoch,
  makeDecoyEnvelope,
  openAnyEnvelope,
  openEnvelope,
  openHistoryLink,
  placeEnvelopes,
  sealEnvelope,
  sealHistoryLink,
  validateHistoryLinkShape,
} from "../src/core/envelopes";
import { EnvelopeError } from "../src/core/errors";
import { KeyManager } from "../src/core/key-manager";
import type { SecretEnvelope } from "../src/core/types";
import { bytesToHex } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

async function fixture() {
  const recipient = await km.generateDeviceKeys();
  const secret = crypto.randomBytes(32);
  const envelope = await sealEnvelope(crypto, km.devicePublicKey(recipient), 7, secret);
  return { recipient, secret, envelope };
}

function mutateBlob(
  envelope: SecretEnvelope,
  mutate: (blob: Uint8Array) => void,
): SecretEnvelope {
  const blob = base64UrlToBytes(envelope);
  mutate(blob);
  return bytesToBase64Url(blob);
}

describe("secret envelopes (spec §9.1)", () => {
  it("round-trips a group_secret with its epoch", async () => {
    const { recipient, secret, envelope } = await fixture();
    expect(envelopeEpoch(envelope)).toBe(7);
    const opened = await openEnvelope(crypto, recipient.encryption, envelope);
    expect(opened.epoch).toBe(7);
    expect(bytesToHex(opened.groupSecret)).toBe(bytesToHex(secret));
  });

  it("supports large epochs in the header", async () => {
    const { recipient, secret } = await fixture();
    const envelope = await sealEnvelope(
      crypto,
      km.devicePublicKey(recipient),
      2 ** 40,
      secret,
    );
    expect(envelopeEpoch(envelope)).toBe(2 ** 40);
  });

  it("cannot be opened by a different device", async () => {
    const { envelope } = await fixture();
    const other = await km.generateDeviceKeys();
    await expect(openEnvelope(crypto, other.encryption, envelope)).rejects.toBeInstanceOf(
      EnvelopeError,
    );
  });

  it("fails authentication when the ciphertext is tampered", async () => {
    const { recipient, envelope } = await fixture();
    const tampered = mutateBlob(envelope, (blob) => {
      blob[blob.length - 1] = (blob[blob.length - 1] ?? 0) ^ 0x01;
    });
    await expect(
      openEnvelope(crypto, recipient.encryption, tampered),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("binds the epoch header via AAD — a relabelled epoch fails to open", async () => {
    const { recipient, envelope } = await fixture();
    const relabelled = mutateBlob(envelope, (blob) => {
      blob[8] = (blob[8] ?? 0) ^ 0x01; // low byte of the big-endian epoch
    });
    expect(envelopeEpoch(relabelled)).not.toBe(envelopeEpoch(envelope));
    await expect(
      openEnvelope(crypto, recipient.encryption, relabelled),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("rejects unknown suite versions (spec §6.3)", async () => {
    const { recipient, envelope } = await fixture();
    const wrongSuite = mutateBlob(envelope, (blob) => {
      blob[0] = 0x02;
    });
    expect(() => envelopeEpoch(wrongSuite)).toThrow(EnvelopeError);
    await expect(
      openEnvelope(crypto, recipient.encryption, wrongSuite),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("rejects truncated blobs", async () => {
    const { recipient, envelope } = await fixture();
    const truncated: SecretEnvelope = bytesToBase64Url(
      base64UrlToBytes(envelope).subarray(0, 40),
    );
    expect(() => envelopeEpoch(truncated)).toThrow(EnvelopeError);
    await expect(
      openEnvelope(crypto, recipient.encryption, truncated),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("refuses to seal invalid inputs", async () => {
    const { recipient } = await fixture();
    const device = km.devicePublicKey(recipient);
    await expect(
      sealEnvelope(crypto, device, 0, crypto.randomBytes(16)),
    ).rejects.toBeInstanceOf(EnvelopeError);
    await expect(
      sealEnvelope(crypto, device, -1, crypto.randomBytes(32)),
    ).rejects.toBeInstanceOf(EnvelopeError);
    await expect(
      sealEnvelope(crypto, device, 1.5, crypto.randomBytes(32)),
    ).rejects.toBeInstanceOf(EnvelopeError);
    await expect(
      sealEnvelope(crypto, "dG9vLXNob3J0", 0, crypto.randomBytes(32)),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });
});

describe("secret history chain links (spec §9.7)", () => {
  const GROUP = "history-group";
  const current = crypto.randomBytes(32);
  const prev = crypto.randomBytes(32);

  it("round-trips the previous secret under the current one", async () => {
    const link = await sealHistoryLink(crypto, GROUP, 3, current, prev);
    validateHistoryLinkShape(link);
    const opened = await openHistoryLink(crypto, GROUP, 3, current, link);
    expect(bytesToHex(opened)).toBe(bytesToHex(prev));
  });

  it("cannot be opened without the current secret", async () => {
    const link = await sealHistoryLink(crypto, GROUP, 3, current, prev);
    await expect(
      openHistoryLink(crypto, GROUP, 3, crypto.randomBytes(32), link),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("binds group_id and epoch via AAD", async () => {
    const link = await sealHistoryLink(crypto, GROUP, 3, current, prev);
    await expect(
      openHistoryLink(crypto, "other-group", 3, current, link),
    ).rejects.toBeInstanceOf(EnvelopeError);
    await expect(
      openHistoryLink(crypto, GROUP, 4, current, link),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("fails authentication when tampered", async () => {
    const link = await sealHistoryLink(crypto, GROUP, 3, current, prev);
    const blob = base64UrlToBytes(link);
    blob[blob.length - 1] = (blob[blob.length - 1] ?? 0) ^ 0x01;
    await expect(
      openHistoryLink(crypto, GROUP, 3, current, bytesToBase64Url(blob)),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("rejects malformed or foreign-suite blobs", async () => {
    expect(() => {
      validateHistoryLinkShape("AAAA");
    }).toThrow(EnvelopeError);
    expect(() => {
      validateHistoryLinkShape("!x!");
    }).toThrow(EnvelopeError);
    const link = await sealHistoryLink(crypto, GROUP, 3, current, prev);
    const blob = base64UrlToBytes(link);
    blob[0] = 0x02;
    expect(() => {
      validateHistoryLinkShape(bytesToBase64Url(blob));
    }).toThrow(EnvelopeError);
  });

  it("refuses to seal invalid inputs", async () => {
    await expect(
      sealHistoryLink(crypto, GROUP, 0, current, prev),
    ).rejects.toBeInstanceOf(EnvelopeError);
    await expect(
      sealHistoryLink(crypto, GROUP, 3, crypto.randomBytes(16), prev),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });
});

// ---------------------------------------------------------------------------
// Decoy padding and trial decryption (spec §6.5)
// ---------------------------------------------------------------------------

describe("decoy envelopes (spec §6.5)", () => {
  it("is byte-indistinguishable from a real envelope in every readable field", async () => {
    const { envelope } = await fixture();
    const decoy = makeDecoyEnvelope(crypto, 7);

    // Everything a relay can see without a private key must match:
    // length, suite version byte, and the epoch header. A decoy that
    // differs anywhere here is filterable, and filterable decoys pad
    // nothing.
    expect(base64UrlToBytes(decoy).length).toBe(base64UrlToBytes(envelope).length);
    expect(base64UrlToBytes(decoy)[0]).toBe(base64UrlToBytes(envelope)[0]);
    expect(envelopeEpoch(decoy)).toBe(envelopeEpoch(envelope));
  });

  it("opens for nobody", async () => {
    const recipient = await km.generateDeviceKeys();
    await expect(
      openEnvelope(crypto, recipient.encryption, makeDecoyEnvelope(crypto, 3)),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("is freshly generated every time — a repeated decoy is identifiable", () => {
    const decoys = new Set<string>();
    for (let i = 0; i < 50; i++) decoys.add(makeDecoyEnvelope(crypto, 4));
    expect(decoys.size).toBe(50);
  });

  it("refuses a nonsensical epoch", () => {
    expect(() => makeDecoyEnvelope(crypto, -1)).toThrow(EnvelopeError);
    expect(() => makeDecoyEnvelope(crypto, 1.5)).toThrow(EnvelopeError);
  });
});

describe("envelope placement and trial decryption (spec §6.5)", () => {
  it("fills every slot and reports where the real envelopes went", async () => {
    const { recipient, secret, envelope } = await fixture();
    const { envelopes, slots } = placeEnvelopes(crypto, [envelope], 7, 45);

    expect(envelopes).toHaveLength(45);
    expect(slots).toHaveLength(1);
    expect(envelopes[slots[0] ?? -1]).toBe(envelope);

    const opened = await openAnyEnvelope(crypto, recipient.encryption, envelopes);
    expect(opened?.slot).toBe(slots[0]);
    expect(opened && bytesToHex(opened.groupSecret)).toBe(bytesToHex(secret));
  });

  it("finds an envelope at any slot, including the last", async () => {
    const { recipient, envelope } = await fixture();
    for (const slot of [0, 22, 44]) {
      const envelopes = Array.from({ length: 45 }, (_, i) =>
        i === slot ? envelope : makeDecoyEnvelope(crypto, 7),
      );
      const opened = await openAnyEnvelope(crypto, recipient.encryption, envelopes);
      expect(opened?.slot).toBe(slot);
    }
  });

  it("opens nothing for a device that was not enveloped", async () => {
    const { envelope } = await fixture();
    const outsider = await km.generateDeviceKeys();
    const { envelopes } = placeEnvelopes(crypto, [envelope], 7, 45);

    expect(await openAnyEnvelope(crypto, outsider.encryption, envelopes)).toBeUndefined();
  });

  it("keeps scanning past a malformed entry rather than giving up", async () => {
    // A relay that corrupts slot 0 must not be able to hide a real
    // envelope sitting at slot 1.
    const { recipient, envelope } = await fixture();
    const envelopes = ["AAAA", envelope, ...Array.from({ length: 43 }, () =>
      makeDecoyEnvelope(crypto, 7),
    )];
    const opened = await openAnyEnvelope(crypto, recipient.encryption, envelopes);
    expect(opened?.slot).toBe(1);
  });

  it("refuses to place more envelopes than the profile has slots", async () => {
    const { envelope } = await fixture();
    expect(() => placeEnvelopes(crypto, [envelope, envelope], 7, 1)).toThrow(EnvelopeError);
  });

  it("gives every slot to the real envelopes when the group is full", async () => {
    const real = await Promise.all(
      Array.from({ length: 5 }, async () => (await fixture()).envelope),
    );
    const { envelopes, slots } = placeEnvelopes(crypto, real, 7, 5);
    expect(new Set(slots).size).toBe(5);
    expect(new Set(envelopes).size).toBe(5);
  });

  // spec §6.5: placement must be CSPRNG-chosen, not sequential.
  // Appending real envelopes and padding after them would put the
  // device count straight back on the wire as "the index of the first
  // decoy" — so this asserts the distribution, not just that some
  // placement happened. Verified to go red against an order-preserving
  // build (check a new test can actually fail).
  it("scatters real envelopes across the array rather than filling from the front", async () => {
    const { envelope } = await fixture();
    const observed: number[] = [];
    for (let run = 0; run < 200; run++) {
      observed.push(placeEnvelopes(crypto, [envelope], 7, 45).slots[0] ?? -1);
    }

    expect(new Set(observed).size).toBeGreaterThan(20);
    const mean = observed.reduce((a, b) => a + b, 0) / observed.length;
    expect(mean).toBeGreaterThan(12);
    expect(mean).toBeLessThan(32);
  });
});
