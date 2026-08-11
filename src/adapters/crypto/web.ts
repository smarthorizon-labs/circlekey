/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Default browser `CryptoProvider`:
 *
 * - WebCrypto (`crypto.subtle`) for AES-256-GCM, HKDF-SHA256,
 *   SHA-256, PBKDF2 and CSPRNG bytes;
 * - `@noble/curves` (audited, allowlisted) for X25519/Ed25519, since
 *   browser WebCrypto curve support is still uneven.
 *
 * Also runs on Node ≥ 20, where WebCrypto is global — CI relies on
 * this. `crypto.subtle` only exists in secure contexts (HTTPS);
 * construction fails fast when it is missing.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";

import { CryptoError } from "../../core/errors";
import type {
  Argon2Params,
  CryptoProvider,
  KeyPair,
} from "../../ports/crypto-provider";

export class WebCryptoProvider implements CryptoProvider {
  private readonly webCrypto: Crypto;
  private readonly subtle: SubtleCrypto;

  constructor() {
    // DOM types declare these as always present; at runtime `subtle`
    // is missing outside secure contexts.
    const webCrypto = globalThis.crypto as Crypto | undefined;
    const subtle = webCrypto?.subtle;
    if (webCrypto === undefined || subtle === undefined) {
      throw new CryptoError(
        "WebCrypto (crypto.subtle) is unavailable — CircleKey requires a secure context (HTTPS) or Node >= 20",
      );
    }
    this.webCrypto = webCrypto;
    this.subtle = subtle;
  }

  randomBytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    this.webCrypto.getRandomValues(out); // spec §6.1: CSPRNG only
    return out;
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await this.subtle.digest("SHA-256", asView(data)));
  }

  async hkdfSha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): Promise<Uint8Array> {
    const key = await this.subtle.importKey("raw", asView(ikm), "HKDF", false, [
      "deriveBits",
    ]);
    const bits = await this.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: asView(salt), info: asView(info) },
      key,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  async aesGcmEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    const aesKey = await this.importAesKey(key, "encrypt");
    return new Uint8Array(
      await this.subtle.encrypt(aesGcmParams(nonce, aad), aesKey, asView(plaintext)),
    );
  }

  async aesGcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    const aesKey = await this.importAesKey(key, "decrypt");
    try {
      return new Uint8Array(
        await this.subtle.decrypt(aesGcmParams(nonce, aad), aesKey, asView(ciphertext)),
      );
    } catch {
      // WebCrypto reports tag mismatch as an opaque OperationError.
      throw new CryptoError("AES-GCM authentication failed");
    }
  }

  generateX25519KeyPair(): Promise<KeyPair> {
    const { secretKey, publicKey } = x25519.keygen();
    return Promise.resolve({ privateKey: secretKey, publicKey });
  }

  x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(x25519.getSharedSecret(privateKey, peerPublicKey));
  }

  generateEd25519KeyPair(): Promise<KeyPair> {
    const { secretKey, publicKey } = ed25519.keygen();
    return Promise.resolve({ privateKey: secretKey, publicKey });
  }

  ed25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.getPublicKey(privateKey));
  }

  ed25519ToX25519PublicKey(publicKey: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.utils.toMontgomery(publicKey));
  }

  ed25519ToX25519PrivateKey(privateKey: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.utils.toMontgomerySecret(privateKey));
  }

  ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(ed25519.sign(message, privateKey));
  }

  ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    try {
      return Promise.resolve(ed25519.verify(signature, message, publicKey));
    } catch {
      // Malformed keys/signatures are a verification failure, not a crash.
      return Promise.resolve(false);
    }
  }

  async pbkdf2Sha256(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number,
  ): Promise<Uint8Array> {
    const key = await this.subtle.importKey("raw", asView(password), "PBKDF2", false, [
      "deriveBits",
    ]);
    const bits = await this.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: asView(salt), iterations },
      key,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  /**
   * Argon2id via `hash-wasm` (spec §6.2 primary backup KDF).
   *
   * The module is imported dynamically so its embedded WASM payload
   * lands in a separate bundle chunk, fetched on the first backup
   * operation rather than on page load — most sessions never enroll
   * or restore.
   */
  async argon2id(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params,
    length: number,
  ): Promise<Uint8Array> {
    if (
      !Number.isSafeInteger(params.memoryKiB) ||
      !Number.isSafeInteger(params.iterations) ||
      !Number.isSafeInteger(params.parallelism) ||
      params.memoryKiB < 8 ||
      params.iterations < 1 ||
      params.parallelism < 1
    ) {
      throw new CryptoError("invalid Argon2id parameters");
    }
    const { argon2id } = await import("hash-wasm");
    return argon2id({
      password,
      salt,
      iterations: params.iterations,
      parallelism: params.parallelism,
      memorySize: params.memoryKiB,
      hashLength: length,
      outputType: "binary",
    });
  }

  private importAesKey(key: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
    if (key.length !== 32) {
      throw new CryptoError("AES-256-GCM requires a 32-byte key");
    }
    return this.subtle.importKey("raw", asView(key), "AES-GCM", false, [usage]);
  }
}

/**
 * WebCrypto's `BufferSource` requires views over a plain
 * `ArrayBuffer`; every array this adapter handles is one — we never
 * allocate on a `SharedArrayBuffer`.
 */
function asView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

function aesGcmParams(nonce: Uint8Array, aad?: Uint8Array): AesGcmParams {
  const params: AesGcmParams = { name: "AES-GCM", iv: asView(nonce) };
  if (aad !== undefined) {
    params.additionalData = asView(aad);
  }
  return params;
}
