/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Blinded relay handles (spec §6.5).
 *
 * The handle replaces `user_id` at the relay boundary, so its whole
 * value lies in two opposing properties: stable enough that a user can
 * find their own backup blob, unlinkable enough that two relays
 * comparing notes learn nothing. Both are tested here, and the
 * unlinkability one is the reason this module exists at all.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, bytesToBase64Url } from "../src/core/bytes";
import { CryptoError } from "../src/core/errors";
import { deriveRelayHandle, HANDLE_LENGTH } from "../src/core/handles";

const crypto = new WebCryptoProvider();
const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
  crypto.hkdfSha256(ikm, salt, info, length);

const RELAY = "relay.circlekey.io";

describe("blinded relay handles (spec §6.5)", () => {
  it("is stable for one credential at one relay", async () => {
    const credential = bytesToBase64Url(crypto.randomBytes(16));
    const first = await deriveRelayHandle(hkdf, credential, RELAY);
    const second = await deriveRelayHandle(hkdf, credential, RELAY);

    expect(first).toBe(second);
    // Stability is what makes a backup findable across sessions and
    // devices restored from the same identity key (spec §9.6).
    expect(base64UrlToBytes(first).length).toBe(HANDLE_LENGTH);
  });

  it("is unlinkable across relays — the point of blinding", async () => {
    const credential = bytesToBase64Url(crypto.randomBytes(16));
    const atOne = await deriveRelayHandle(hkdf, credential, "relay-one.example");
    const atTwo = await deriveRelayHandle(hkdf, credential, "relay-two.example");

    expect(atOne).not.toBe(atTwo);
  });

  it("distinguishes relays whose ids differ by one character", async () => {
    const credential = bytesToBase64Url(crypto.randomBytes(16));
    expect(await deriveRelayHandle(hkdf, credential, "relay-a")).not.toBe(
      await deriveRelayHandle(hkdf, credential, "relay-b"),
    );
  });

  it("gives different credentials different handles at the same relay", async () => {
    const handles = new Set<string>();
    for (let i = 0; i < 25; i++) {
      handles.add(
        await deriveRelayHandle(hkdf, bytesToBase64Url(crypto.randomBytes(16)), RELAY),
      );
    }
    expect(handles.size).toBe(25);
  });

  it("does not embed the credential it derives from", async () => {
    const credential = bytesToBase64Url(crypto.randomBytes(16));
    const handle = await deriveRelayHandle(hkdf, credential, RELAY);
    const handleBytes = base64UrlToBytes(handle);

    // A handle is public by design; it must still not leak the
    // credential, which is the secret that unlocks the whole backup.
    expect(handle).not.toContain(credential);
    expect(credential).not.toContain(handle);
    expect(handleBytes.length).toBe(HANDLE_LENGTH);
  });

  it("refuses an empty relay id, which would make handles linkable", async () => {
    await expect(deriveRelayHandle(hkdf, "some-credential", "")).rejects.toBeInstanceOf(
      CryptoError,
    );
  });

  it("refuses to derive from an empty credential", async () => {
    await expect(deriveRelayHandle(hkdf, "", RELAY)).rejects.toBeInstanceOf(
      CryptoError,
    );
  });
});
