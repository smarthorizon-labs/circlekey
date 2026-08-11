/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Known-answer tests for the default CryptoProvider adapter, pinned
 * to published RFC/NIST vectors so a
 * platform or library regression cannot silently change primitives.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { utf8Bytes } from "../src/core/bytes";
import { CryptoError } from "../src/core/errors";
import { bytesToHex, hexToBytes } from "./helpers";

const provider = new WebCryptoProvider();

describe("randomBytes", () => {
  it("returns the requested length and non-constant output", () => {
    const a = provider.randomBytes(32);
    const b = provider.randomBytes(32);
    expect(a).toHaveLength(32);
    expect(bytesToHex(a)).not.toBe("00".repeat(32));
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

describe("sha256", () => {
  it("matches the FIPS 180 'abc' vector", async () => {
    const digest = await provider.sha256(utf8Bytes("abc"));
    expect(bytesToHex(digest)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("hkdfSha256", () => {
  it("matches RFC 5869 test case 1", async () => {
    const okm = await provider.hkdfSha256(
      hexToBytes("0b".repeat(22)),
      hexToBytes("000102030405060708090a0b0c"),
      hexToBytes("f0f1f2f3f4f5f6f7f8f9"),
      42,
    );
    expect(bytesToHex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("accepts a zero-length salt (used by core/kdf.ts)", async () => {
    const okm = await provider.hkdfSha256(
      utf8Bytes("ikm"),
      new Uint8Array(0),
      utf8Bytes("info"),
      32,
    );
    expect(okm).toHaveLength(32);
  });
});

describe("pbkdf2Sha256 (spec §6.2 fallback KDF)", () => {
  it("matches the published PBKDF2-HMAC-SHA256 vectors", async () => {
    const one = await provider.pbkdf2Sha256(utf8Bytes("password"), utf8Bytes("salt"), 1, 32);
    expect(bytesToHex(one)).toBe(
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    );
    const two = await provider.pbkdf2Sha256(utf8Bytes("password"), utf8Bytes("salt"), 2, 32);
    expect(bytesToHex(two)).toBe(
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
    );
  });
});

describe("argon2id (spec §6.2 primary KDF)", () => {
  // Pinned regression vector: computed with these exact parameters and
  // frozen here. Not an RFC 9106 vector (that one exercises `secret`
  // and associated-data inputs this port does not expose) — its job is
  // to catch a silent change in the library or platform.
  it("matches the pinned low-cost vector", async () => {
    const derived = await provider.argon2id(
      utf8Bytes("password"),
      utf8Bytes("somesalt1234"),
      { memoryKiB: 64, iterations: 2, parallelism: 1 },
      32,
    );
    expect(bytesToHex(derived)).toBe(
      "67c01894a09d7fc6a511b960c05cea852672dd32a48c57bcf8063e48d50e8566",
    );
  });

  it("is deterministic and parameter-sensitive", async () => {
    const base = { memoryKiB: 64, iterations: 1, parallelism: 1 };
    const salt = utf8Bytes("salt-for-argon2");
    const a = await provider.argon2id(utf8Bytes("pw"), salt, base, 32);
    const again = await provider.argon2id(utf8Bytes("pw"), salt, base, 32);
    expect(bytesToHex(again)).toBe(bytesToHex(a));

    const variants = await Promise.all([
      provider.argon2id(utf8Bytes("pw2"), salt, base, 32),
      provider.argon2id(utf8Bytes("pw"), utf8Bytes("other-salt-xxxx"), base, 32),
      provider.argon2id(utf8Bytes("pw"), salt, { ...base, iterations: 2 }, 32),
      provider.argon2id(utf8Bytes("pw"), salt, { ...base, memoryKiB: 128 }, 32),
      provider.argon2id(utf8Bytes("pw"), salt, { ...base, parallelism: 2 }, 32),
    ]);
    const hexes = [a, ...variants].map(bytesToHex);
    expect(new Set(hexes).size).toBe(hexes.length); // all distinct
  });

  it("honors the requested output length", async () => {
    const derived = await provider.argon2id(
      utf8Bytes("pw"),
      utf8Bytes("salt-len-check"),
      { memoryKiB: 64, iterations: 1, parallelism: 1 },
      64,
    );
    expect(derived).toHaveLength(64);
  });

  it("rejects invalid cost parameters", async () => {
    const salt = utf8Bytes("salt-invalid-ck");
    for (const params of [
      { memoryKiB: 0, iterations: 1, parallelism: 1 },
      { memoryKiB: 64, iterations: 0, parallelism: 1 },
      { memoryKiB: 64, iterations: 1, parallelism: 0 },
      { memoryKiB: 1.5, iterations: 1, parallelism: 1 },
    ]) {
      await expect(
        provider.argon2id(utf8Bytes("pw"), salt, params, 32),
      ).rejects.toBeInstanceOf(CryptoError);
    }
  });
});

describe("AES-256-GCM", () => {
  const key = hexToBytes("22".repeat(32));
  const nonce = hexToBytes("33".repeat(12));

  it("matches the NIST empty-plaintext vector (tag-only output)", async () => {
    const out = await provider.aesGcmEncrypt(
      hexToBytes("00".repeat(32)),
      hexToBytes("00".repeat(12)),
      new Uint8Array(0),
    );
    expect(bytesToHex(out)).toBe("530f8afbc74536b9a963b4f1c4cb738b");
  });

  it("round-trips with associated data", async () => {
    const plaintext = utf8Bytes("attack at dawn");
    const aad = utf8Bytes("record-1");
    const ciphertext = await provider.aesGcmEncrypt(key, nonce, plaintext, aad);
    expect(ciphertext).toHaveLength(plaintext.length + 16);
    const decrypted = await provider.aesGcmDecrypt(key, nonce, ciphertext, aad);
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
  });

  it("throws CryptoError on any tampering", async () => {
    const plaintext = utf8Bytes("attack at dawn");
    const aad = utf8Bytes("record-1");
    const ciphertext = await provider.aesGcmEncrypt(key, nonce, plaintext, aad);

    const flipped = new Uint8Array(ciphertext);
    flipped[0] = (flipped[0] ?? 0) ^ 0x01;
    await expect(provider.aesGcmDecrypt(key, nonce, flipped, aad)).rejects.toBeInstanceOf(
      CryptoError,
    );
    await expect(
      provider.aesGcmDecrypt(key, nonce, ciphertext, utf8Bytes("record-2")),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      provider.aesGcmDecrypt(key, hexToBytes("44".repeat(12)), ciphertext, aad),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      provider.aesGcmDecrypt(hexToBytes("55".repeat(32)), nonce, ciphertext, aad),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("refuses non-256-bit keys", async () => {
    await expect(
      provider.aesGcmEncrypt(hexToBytes("22".repeat(16)), nonce, utf8Bytes("x")),
    ).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("Ed25519 (spec §6 identity signatures)", () => {
  // RFC 8032 §7.1 TEST 1.
  const secretKey = hexToBytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  );
  const publicKey = hexToBytes(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  );
  const signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

  it("matches RFC 8032 test 1", async () => {
    const produced = await provider.ed25519Sign(secretKey, new Uint8Array(0));
    expect(bytesToHex(produced)).toBe(signature);
    expect(
      await provider.ed25519Verify(publicKey, new Uint8Array(0), hexToBytes(signature)),
    ).toBe(true);
  });

  it("rejects a tampered message or malformed inputs without throwing", async () => {
    expect(
      await provider.ed25519Verify(publicKey, utf8Bytes("x"), hexToBytes(signature)),
    ).toBe(false);
    expect(
      await provider.ed25519Verify(new Uint8Array(3), new Uint8Array(0), hexToBytes(signature)),
    ).toBe(false);
  });

  it("round-trips with generated keypairs", async () => {
    const pair = await provider.generateEd25519KeyPair();
    const message = utf8Bytes("epoch transition bytes");
    const sig = await provider.ed25519Sign(pair.privateKey, message);
    expect(await provider.ed25519Verify(pair.publicKey, message, sig)).toBe(true);
    expect(await provider.ed25519Verify(pair.publicKey, utf8Bytes("forged"), sig)).toBe(false);
  });
});

describe("X25519 (spec §6 key agreement)", () => {
  it("matches RFC 7748 §5.2 vector 1", async () => {
    const shared = await provider.x25519SharedSecret(
      hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
      hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    );
    expect(bytesToHex(shared)).toBe(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    );
  });

  it("produces a symmetric shared secret between two generated keypairs", async () => {
    const alice = await provider.generateX25519KeyPair();
    const bob = await provider.generateX25519KeyPair();
    const fromAlice = await provider.x25519SharedSecret(alice.privateKey, bob.publicKey);
    const fromBob = await provider.x25519SharedSecret(bob.privateKey, alice.publicKey);
    expect(bytesToHex(fromAlice)).toBe(bytesToHex(fromBob));
    expect(fromAlice).toHaveLength(32);
  });
});
