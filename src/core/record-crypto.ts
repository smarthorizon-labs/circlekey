/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Record and group-metadata encryption (spec §6.1, §7).
 *
 * Every plaintext is encrypted with AES-256-GCM under a key derived
 * from the epoch's `group_secret` with a domain-separated label
 * (spec §7): per-record keys bind the `record_id` as KDF context,
 * the metadata key has its own label. Derived keys exist only inside
 * the call that uses them and are never persisted (spec §12).
 *
 * Nonce policy (spec §6.1): 96-bit CSPRNG nonces, fresh per
 * operation, and a persisted per-`(group, epoch)` encryption counter
 * — incremented via the atomic `KeyUsageStore` port so concurrent
 * tabs cannot race it — with a hard refusal
 * once the configured bound is reached. Decryption never counts.
 *
 * Every ciphertext is tagged with the versioned suite identifier and
 * AAD-bound to its group, id, epoch, and suite (spec §6.3).
 */

import { base64UrlToBytes, bytesToBase64Url, utf8Bytes, wipe } from "./bytes";
import { canonicalBytes, type JsonValue } from "./codec";
import { CryptoError, KeyUsageExceededError } from "./errors";
import { deriveBytes, deriveKey, KDF_LABELS } from "./kdf";
import { pad, recordBucket, unpad } from "./padding";
import { SUITE_V1, type EncryptedRecord } from "./types";
import type { CryptoProvider } from "../ports/crypto-provider";
import type { KeyUsageStore } from "../ports/storage";

const NONCE_LENGTH = 12; // spec §6.1: 96-bit
const GROUP_SECRET_LENGTH = 32;
/** spec §6.5: 128-bit opaque record identifier. */
const RECORD_ID_LENGTH = 16;

/**
 * Default per-epoch encryption bound: 2^20 operations — well below
 * the ~2^32 nonce-collision guidance of spec §6.1, and far beyond
 * what a ≤15-member group produces within one epoch.
 */
export const DEFAULT_KEY_USAGE_LIMIT = 2 ** 20;

/** Encrypted group metadata (record titles etc., spec §7). */
export interface EncryptedMetadata {
  epoch: number;
  ciphertext: string;
  nonce: string;
  /** Crypto agility identifier (spec §6.3). */
  suite: string;
}

export interface RecordCryptoOptions {
  /** Override the spec §6.1 usage bound (must stay well below 2^32). */
  keyUsageLimit?: number;
  /** Clock injection for deterministic tests; returns ISO-8601. */
  now?: () => string;
}

const decoder = new TextDecoder();

export class RecordCrypto {
  private readonly limit: number;
  private readonly now: () => string;

  constructor(
    private readonly crypto: CryptoProvider,
    private readonly usage: KeyUsageStore,
    options: RecordCryptoOptions = {},
  ) {
    const limit = options.keyUsageLimit ?? DEFAULT_KEY_USAGE_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit >= 2 ** 32) {
      throw new CryptoError("keyUsageLimit must be an integer in [1, 2^32)");
    }
    this.limit = limit;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async encryptRecord(
    groupId: string,
    epoch: number,
    groupSecret: Uint8Array,
    recordId: string,
    plaintext: Uint8Array,
  ): Promise<EncryptedRecord> {
    const key = await this.recordKey(groupSecret, recordId);
    // spec §6.5: pad to a size bucket so ciphertext length reveals a
    // bucket rather than a byte count. Applied here rather than in
    // `seal` because metadata has its own (unbucketed) shape.
    const padded = pad(plaintext, recordBucket(plaintext.length));
    try {
      const sealed = await this.seal(
        groupId,
        epoch,
        key,
        padded,
        recordAad(groupId, recordId, epoch),
      );
      return {
        record_id: recordId,
        epoch,
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        suite: SUITE_V1,
      };
    } finally {
      // spec §12: derived keys must not outlive their use.
      wipe(key, padded);
    }
  }

  /** `groupSecret` must be the secret of `record.epoch`. */
  async decryptRecord(
    groupId: string,
    groupSecret: Uint8Array,
    record: EncryptedRecord,
  ): Promise<Uint8Array> {
    requireSuite(record.suite);
    const key = await this.recordKey(groupSecret, record.record_id);
    let padded: Uint8Array | undefined;
    try {
      padded = await this.open(
        key,
        record.nonce,
        record.ciphertext,
        recordAad(groupId, record.record_id, record.epoch),
      );
      // The bucket is whatever was sealed; `unpad` verifies the
      // declared length and that the padding really is zero (spec §6.5).
      return unpad(padded, padded.length);
    } finally {
      wipe(key, padded);
    }
  }

  /** Convenience wrapper: JSON payload in, `EncryptedRecord` out. */
  async encryptJsonRecord(
    groupId: string,
    epoch: number,
    groupSecret: Uint8Array,
    recordId: string,
    payload: JsonValue,
  ): Promise<EncryptedRecord> {
    return this.encryptRecord(
      groupId,
      epoch,
      groupSecret,
      recordId,
      utf8Bytes(JSON.stringify(payload)),
    );
  }

  async decryptJsonRecord(
    groupId: string,
    groupSecret: Uint8Array,
    record: EncryptedRecord,
  ): Promise<unknown> {
    const plaintext = await this.decryptRecord(groupId, groupSecret, record);
    return JSON.parse(decoder.decode(plaintext)) as unknown;
  }

  async encryptMetadata(
    groupId: string,
    epoch: number,
    groupSecret: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<EncryptedMetadata> {
    const key = await this.metadataKey(groupSecret);
    try {
      const sealed = await this.seal(
        groupId,
        epoch,
        key,
        plaintext,
        metadataAad(groupId, epoch),
      );
      return {
        epoch,
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        suite: SUITE_V1,
      };
    } finally {
      wipe(key);
    }
  }

  /** `groupSecret` must be the secret of `metadata.epoch`. */
  async decryptMetadata(
    groupId: string,
    groupSecret: Uint8Array,
    metadata: EncryptedMetadata,
  ): Promise<Uint8Array> {
    requireSuite(metadata.suite);
    const key = await this.metadataKey(groupSecret);
    try {
      return await this.open(
        key,
        metadata.nonce,
        metadata.ciphertext,
        metadataAad(groupId, metadata.epoch),
      );
    } finally {
      wipe(key);
    }
  }

  private async seal(
    groupId: string,
    epoch: number,
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<{ nonce: string; ciphertext: string }> {
    // spec §6.1: persisted counter, hard refusal at the bound. The
    // increment reserves the slot before any ciphertext exists, so a
    // crash mid-encrypt can only over-count — never under-count.
    const uses = await this.usage.incrementKeyUsage(groupId, epoch);
    if (uses > this.limit) {
      throw new KeyUsageExceededError(
        `key usage bound reached for group ${groupId} epoch ${String(epoch)} ` +
          `(${String(this.limit)} operations) — rotate the epoch before encrypting more`,
      );
    }
    const nonce = this.crypto.randomBytes(NONCE_LENGTH); // spec §6.1: CSPRNG, fresh
    const ciphertext = await this.crypto.aesGcmEncrypt(key, nonce, plaintext, aad);
    return { nonce: bytesToBase64Url(nonce), ciphertext: bytesToBase64Url(ciphertext) };
  }

  private async open(
    key: Uint8Array,
    nonceB64: string,
    ciphertextB64: string,
    aad: Uint8Array,
  ): Promise<Uint8Array> {
    const nonce = base64UrlToBytes(nonceB64);
    if (nonce.length !== NONCE_LENGTH) {
      throw new CryptoError("record nonce must be 12 bytes");
    }
    return this.crypto.aesGcmDecrypt(key, nonce, base64UrlToBytes(ciphertextB64), aad);
  }

  private recordKey(groupSecret: Uint8Array, recordId: string): Promise<Uint8Array> {
    return this.derive(groupSecret, recordId);
  }

  private metadataKey(groupSecret: Uint8Array): Promise<Uint8Array> {
    return this.derive(groupSecret);
  }

  /**
   * Callers own the returned key and MUST `wipe()` it once finished
   * (spec §12: derived keys must not outlive their immediate use).
   */
  private derive(groupSecret: Uint8Array, recordId?: string): Promise<Uint8Array> {
    if (groupSecret.length !== GROUP_SECRET_LENGTH) {
      throw new CryptoError("group_secret must be 32 bytes");
    }
    const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
      this.crypto.hkdfSha256(ikm, salt, info, length);
    // spec §7: distinct labels; record keys bind record_id as context.
    return recordId === undefined
      ? deriveKey(hkdf, groupSecret, KDF_LABELS.metadataKey)
      : deriveKey(hkdf, groupSecret, KDF_LABELS.recordKey, recordId);
  }
}

/**
 * Derive a `record_id` from an application key (spec §6.5).
 *
 *   record_id = base64url(HKDF(group_secret[0], "record-id/v1", app_key)[0..16])
 *
 * Deterministic for members, pseudorandom to the relay. This is what
 * lets an application keep addressing records by a meaningful key —
 * `"invoice-2026-Q1"` — while the relay only ever sees an opaque
 * identifier (spec §5.8 rule 2), instead of a filename that discloses
 * the content before any cryptography is involved.
 *
 * Anchored on the **genesis** secret, not the current epoch, so an
 * identifier stays stable across rotations; a record whose id changed
 * every epoch would be unfindable after the first membership change.
 * That makes it a long-lived value derived from a long-lived secret:
 * it is an identifier, not a secret, and MUST NOT be treated as one.
 */
export async function deriveRecordId(
  crypto: CryptoProvider,
  genesisGroupSecret: Uint8Array,
  appKey: string,
): Promise<string> {
  if (genesisGroupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new CryptoError("group_secret must be 32 bytes");
  }
  if (appKey.length === 0) {
    throw new CryptoError("record app key must not be empty");
  }
  const derived = await deriveBytes(
    (ikm, salt, info, length) => crypto.hkdfSha256(ikm, salt, info, length),
    genesisGroupSecret,
    KDF_LABELS.recordId,
    RECORD_ID_LENGTH,
    appKey,
  );
  try {
    return bytesToBase64Url(derived);
  } finally {
    wipe(derived);
  }
}

/** spec §6.3: unknown suites are rejected, never guessed at. */
function requireSuite(suite: string): void {
  if (suite !== SUITE_V1) {
    throw new CryptoError(`unsupported record suite: ${suite}`);
  }
}

/**
 * AAD binds each ciphertext to its group, id, epoch, and suite —
 * belt-and-braces on top of the KDF context, making cross-record or
 * cross-group ciphertext transplants fail authentication.
 */
function recordAad(groupId: string, recordId: string, epoch: number): Uint8Array {
  return canonicalBytes({
    group_id: groupId,
    record_id: recordId,
    epoch,
    suite: SUITE_V1,
  });
}

function metadataAad(groupId: string, epoch: number): Uint8Array {
  return canonicalBytes({
    group_id: groupId,
    context: "metadata",
    epoch,
    suite: SUITE_V1,
  });
}
