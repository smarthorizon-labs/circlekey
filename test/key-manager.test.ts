/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes } from "../src/core/bytes";
import { KeyManager } from "../src/core/key-manager";
import { bytesToHex, hexToBytes } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

describe("KeyManager device key model", () => {
  it("generates a full device key set with 32-byte keys", async () => {
    const keys = await km.generateDeviceKeys();
    expect(keys.identity.publicKey).toHaveLength(32);
    expect(keys.identity.privateKey).toHaveLength(32);
    expect(keys.encryption.publicKey).toHaveLength(32);
    expect(keys.encryption.privateKey).toHaveLength(32);
    expect(base64UrlToBytes(km.devicePublicKey(keys))).toEqual(keys.encryption.publicKey);
    expect(base64UrlToBytes(km.identityPublicKey(keys))).toEqual(keys.identity.publicKey);
  });

  it("derives the X25519 device key as the birational image of the identity key", async () => {
    const keys = await km.generateDeviceKeys();
    const converted = await crypto.ed25519ToX25519PublicKey(keys.identity.publicKey);
    expect(bytesToHex(converted)).toBe(bytesToHex(keys.encryption.publicKey));
  });

  it("rebuilds the same device keys from the identity private key (restore path)", async () => {
    const seed = hexToBytes("11".repeat(32));
    const first = await km.deviceKeysFromIdentity(seed);
    const second = await km.deviceKeysFromIdentity(seed);
    expect(km.devicePublicKey(first)).toBe(km.devicePublicKey(second));
    expect(km.identityPublicKey(first)).toBe(km.identityPublicKey(second));

    const generated = await km.generateDeviceKeys();
    const rebuilt = await km.deviceKeysFromIdentity(generated.identity.privateKey);
    expect(km.devicePublicKey(rebuilt)).toBe(km.devicePublicKey(generated));
  });

  it("produces converted keypairs that actually agree on X25519 shared secrets", async () => {
    const alice = await km.generateDeviceKeys();
    const bob = await km.generateDeviceKeys();
    const fromAlice = await crypto.x25519SharedSecret(
      alice.encryption.privateKey,
      bob.encryption.publicKey,
    );
    const fromBob = await crypto.x25519SharedSecret(
      bob.encryption.privateKey,
      alice.encryption.publicKey,
    );
    expect(bytesToHex(fromAlice)).toBe(bytesToHex(fromBob));
  });

  it("signs with the identity key such that the published pubkey verifies", async () => {
    const keys = await km.generateDeviceKeys();
    const message = new TextEncoder().encode("transition bytes");
    const signature = await crypto.ed25519Sign(keys.identity.privateKey, message);
    expect(await crypto.ed25519Verify(keys.identity.publicKey, message, signature)).toBe(
      true,
    );
  });
});
