/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Per-epoch relay authentication key (spec §6.5, §10.1).
 *
 * Every member derives the same keypair from the `group_secret` they
 * already hold, so a signed request proves "a current member" without
 * naming one. The properties worth testing are therefore: all members
 * agree, epochs do not, and a party without the secret can neither
 * derive nor forge.
 *
 * The revocation case at the end is the one that carries weight — it
 * is why this design needs no cooperation from the relay to cut off a
 * removed member.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { utf8Bytes } from "../src/core/bytes";
import { CryptoError } from "../src/core/errors";
import {
  deriveRelayAuthKeyPair,
  deriveRelayAuthPublicKey,
  signRelayRequest,
  verifyRelayRequest,
} from "../src/core/relay-auth";

const crypto = new WebCryptoProvider();
const REQUEST = utf8Bytes("PUT /groups/abc/transitions epoch=4");

describe("relay auth key derivation (spec §6.5)", () => {
  it("is deterministic — every member of an epoch derives the same key", async () => {
    const secret = crypto.randomBytes(32);
    const alice = await deriveRelayAuthKeyPair(crypto, secret);
    const bob = await deriveRelayAuthKeyPair(crypto, secret);

    expect(alice.publicKey).toEqual(bob.publicKey);
    expect(alice.privateKey).toEqual(bob.privateKey);
  });

  it("diverges across epochs, so each epoch has its own credential", async () => {
    const epoch3 = await deriveRelayAuthPublicKey(crypto, crypto.randomBytes(32));
    const epoch4 = await deriveRelayAuthPublicKey(crypto, crypto.randomBytes(32));

    expect(epoch3).not.toEqual(epoch4);
  });

  it("produces a 32-byte Ed25519 public key", async () => {
    const pub = await deriveRelayAuthPublicKey(crypto, crypto.randomBytes(32));
    expect(pub.length).toBe(32);
  });

  it("agrees with the public half of the full keypair", async () => {
    const secret = crypto.randomBytes(32);
    const pair = await deriveRelayAuthKeyPair(crypto, secret);
    expect(await deriveRelayAuthPublicKey(crypto, secret)).toEqual(pair.publicKey);
  });

  it("is not the group secret itself, nor any trivial function of it", async () => {
    const secret = crypto.randomBytes(32);
    const pair = await deriveRelayAuthKeyPair(crypto, secret);

    expect(pair.privateKey).not.toEqual(secret);
    expect(pair.publicKey).not.toEqual(secret);
  });

  it("refuses a group secret of the wrong length", async () => {
    await expect(deriveRelayAuthKeyPair(crypto, crypto.randomBytes(16))).rejects.toBeInstanceOf(
      CryptoError,
    );
  });
});

describe("relay request signing (spec §10.1)", () => {
  it("round-trips: a member signs, the relay verifies against auth_pubkey", async () => {
    const secret = crypto.randomBytes(32);
    const signature = await signRelayRequest(crypto, secret, REQUEST);
    const authPub = await deriveRelayAuthPublicKey(crypto, secret);

    expect(await verifyRelayRequest(crypto, authPub, REQUEST, signature)).toBe(true);
  });

  it("rejects a signature over different request bytes", async () => {
    const secret = crypto.randomBytes(32);
    const signature = await signRelayRequest(crypto, secret, REQUEST);
    const authPub = await deriveRelayAuthPublicKey(crypto, secret);

    const tampered = utf8Bytes("PUT /groups/abc/transitions epoch=5");
    expect(await verifyRelayRequest(crypto, authPub, tampered, signature)).toBe(false);
  });

  it("rejects a tampered signature", async () => {
    const secret = crypto.randomBytes(32);
    const signature = await signRelayRequest(crypto, secret, REQUEST);
    const authPub = await deriveRelayAuthPublicKey(crypto, secret);

    const tampered = Uint8Array.from(signature);
    tampered.set([(signature.at(0) ?? 0) ^ 0xff], 0);

    expect(await verifyRelayRequest(crypto, authPub, REQUEST, tampered)).toBe(false);
    // ...and the untampered one still verifies, so this is detecting the
    // edit rather than failing for an unrelated reason.
    expect(await verifyRelayRequest(crypto, authPub, REQUEST, signature)).toBe(true);
  });

  it("answers false rather than throwing — 'not authorized' is routine", async () => {
    const authPub = await deriveRelayAuthPublicKey(crypto, crypto.randomBytes(32));
    await expect(
      verifyRelayRequest(crypto, authPub, REQUEST, crypto.randomBytes(64)),
    ).resolves.toBe(false);
  });

  // spec §10.1: a removed member is excluded from epoch e+1's envelopes,
  // so it never obtains group_secret[e+1] and cannot derive auth_sk[e+1].
  // The relay is told nothing and needs to do nothing.
  it("cuts off a removed member at the next rotation, with no relay involvement", async () => {
    const secretBefore = crypto.randomBytes(32); // epoch e — removed member holds this
    const secretAfter = crypto.randomBytes(32); // epoch e+1 — it does not

    const staleSignature = await signRelayRequest(crypto, secretBefore, REQUEST);
    const currentAuthPub = await deriveRelayAuthPublicKey(crypto, secretAfter);

    expect(await verifyRelayRequest(crypto, currentAuthPub, REQUEST, staleSignature)).toBe(false);

    // And a current member still passes, so this is revocation and not
    // a blanket failure.
    const freshSignature = await signRelayRequest(crypto, secretAfter, REQUEST);
    expect(await verifyRelayRequest(crypto, currentAuthPub, REQUEST, freshSignature)).toBe(true);
  });
});
