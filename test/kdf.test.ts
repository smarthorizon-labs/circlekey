/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { utf8Bytes } from "../src/core/bytes";
import {
  DERIVED_KEY_LENGTH,
  deriveKey,
  KDF_LABELS,
  kdfInfo,
  type HkdfSha256Fn,
} from "../src/core/kdf";
import { bytesToHex } from "./helpers";

describe("KDF labels (spec §7)", () => {
  it("freezes the closed label set — changing a label is a protocol break", () => {
    expect(KDF_LABELS).toEqual({
      recordKey: "groupvault/record-key/v1",
      metadataKey: "groupvault/metadata-key/v1",
      envelopeKey: "groupvault/envelope-key/v1",
      historyKey: "groupvault/history-key/v1",
      // spec §5.8, §6.5.
      transitionBody: "groupvault/transition-body/v1",
      relayAuth: "groupvault/relay-auth/v1",
      recordId: "groupvault/record-id/v1",
      removalNotice: "groupvault/removal-notice/v1",
      relayHandle: "groupvault/relay-handle/v1",
    });
  });

  it("keeps every label distinct — a collision would merge two domains", () => {
    const labels = Object.values(KDF_LABELS);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("builds info as label || context", () => {
    expect(kdfInfo(KDF_LABELS.recordKey, "rec-1")).toEqual(
      utf8Bytes("groupvault/record-key/v1rec-1"),
    );
    expect(kdfInfo(KDF_LABELS.metadataKey)).toEqual(
      utf8Bytes("groupvault/metadata-key/v1"),
    );
  });
});

describe("deriveKey", () => {
  it("calls HKDF with empty salt, the labeled info, and 32-byte length", async () => {
    const calls: { ikm: Uint8Array; salt: Uint8Array; info: Uint8Array; length: number }[] =
      [];
    const stub: HkdfSha256Fn = (ikm, salt, info, length) => {
      calls.push({ ikm, salt, info, length });
      return Promise.resolve(new Uint8Array(length));
    };
    const ikm = utf8Bytes("group-secret");
    await deriveKey(stub, ikm, KDF_LABELS.recordKey, "rec-1");

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.ikm).toBe(ikm);
    expect(call?.salt).toHaveLength(0);
    expect(call?.info).toEqual(kdfInfo(KDF_LABELS.recordKey, "rec-1"));
    expect(call?.length).toBe(DERIVED_KEY_LENGTH);
  });

  it("separates domains: different labels yield different keys from one secret", async () => {
    const provider = new WebCryptoProvider();
    const hkdf: HkdfSha256Fn = (ikm, salt, info, length) =>
      provider.hkdfSha256(ikm, salt, info, length);
    const groupSecret = utf8Bytes("a-32-byte-ish-group-secret-value");

    const recordKey = await deriveKey(hkdf, groupSecret, KDF_LABELS.recordKey, "rec-1");
    const otherRecordKey = await deriveKey(hkdf, groupSecret, KDF_LABELS.recordKey, "rec-2");
    const metadataKey = await deriveKey(hkdf, groupSecret, KDF_LABELS.metadataKey);
    const envelopeKey = await deriveKey(hkdf, groupSecret, KDF_LABELS.envelopeKey);

    const hexes = [recordKey, otherRecordKey, metadataKey, envelopeKey].map(bytesToHex);
    expect(new Set(hexes).size).toBe(4);
    expect(recordKey).toHaveLength(DERIVED_KEY_LENGTH);

    // Deterministic: same inputs, same key.
    const again = await deriveKey(hkdf, groupSecret, KDF_LABELS.recordKey, "rec-1");
    expect(bytesToHex(again)).toBe(bytesToHex(recordKey));
  });
});
