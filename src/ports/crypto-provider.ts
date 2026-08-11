/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * CryptoProvider port: the narrow interface
 * through which every cryptographic primitive enters the library.
 * No module outside `adapters/` implements or hand-rolls a primitive.
 *
 * All byte parameters and results are raw `Uint8Array`s; base64url
 * conversion happens at the codec boundary.
 */

export interface KeyPair {
  publicKey: Uint8Array;
  /**
   * Secret material — never leaves the device except sealed inside
   * the encrypted backup blob (spec §5.1, §9.6).
   */
  privateKey: Uint8Array;
}

/** Argon2id cost parameters (spec §6.2). */
export interface Argon2Params {
  /** Memory cost in kibibytes. spec §6.2 minimum: 19456 (19 MiB). */
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export interface CryptoProvider {
  /** CSPRNG bytes (spec §6.1: never a non-cryptographic RNG). */
  randomBytes(length: number): Uint8Array;

  sha256(data: Uint8Array): Promise<Uint8Array>;

  hkdfSha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): Promise<Uint8Array>;

  /**
   * AES-256-GCM. Returns ciphertext with the 16-byte auth tag
   * appended. Nonce policy (96-bit, fresh, CSPRNG) is the caller's
   * obligation per spec §6.1 — enforced by `core/record-crypto.ts`.
   */
  aesGcmEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>;

  /** Throws `CryptoError` on authentication failure. */
  aesGcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>;

  generateX25519KeyPair(): Promise<KeyPair>;

  x25519SharedSecret(
    privateKey: Uint8Array,
    peerPublicKey: Uint8Array,
  ): Promise<Uint8Array>;

  generateEd25519KeyPair(): Promise<KeyPair>;

  /** Recompute the Ed25519 public key from a private key (restore path). */
  ed25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array>;

  /**
   * Birational (Edwards → Montgomery) conversion of an Ed25519 public
   * key to its X25519 counterpart. CircleKey's device key model: a
   * device holds one Ed25519 keypair, and
   * its X25519 encryption key is the deterministic image — this is
   * what binds `signed_by` to a member's device entry in spec §9.1
   * check 3 without trusting the backend.
   */
  ed25519ToX25519PublicKey(publicKey: Uint8Array): Promise<Uint8Array>;

  /** Private-key counterpart of {@link ed25519ToX25519PublicKey}. */
  ed25519ToX25519PrivateKey(privateKey: Uint8Array): Promise<Uint8Array>;

  ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>;

  ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;

  /** Backup KDF, fallback flavor (spec §6.2). */
  pbkdf2Sha256(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number,
  ): Promise<Uint8Array>;

  /**
   * Backup KDF, primary flavor (spec §6.2).
   *
   * **Optional by design.** spec §6.2 sanctions PBKDF2-HMAC-SHA256 as
   * the fallback "for environments without a practical Argon2id
   * implementation", so a provider may omit this method and
   * `BackupManager` will use PBKDF2 for new blobs. A provider that
   * omits it cannot *open* an existing Argon2id blob, however — the
   * KDF is dictated by the blob, not by local configuration.
   */
  argon2id?(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params,
    length: number,
  ): Promise<Uint8Array>;
}
