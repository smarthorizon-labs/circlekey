/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * BackupManager (spec §9.6): mandatory,
 * no-opt-out backup enrollment and restore.
 *
 * The recovery credential is system-generated (128 bits of entropy,
 * base64url) rather than a human passphrase — spec §9.6's default.
 *
 * KDF (spec §6.2): **Argon2id is primary**, used for every new blob
 * when the `CryptoProvider` implements it; PBKDF2-HMAC-SHA256 is the
 * sanctioned fallback for environments without a practical Argon2id.
 * The choice and its cost parameters travel *inside each blob*, and
 * restore always honors what the blob records — never local
 * configuration. That is what lets Argon2id arrive without migrating
 * anything: PBKDF2-era blobs keep opening on Argon2id-capable
 * clients, indefinitely.
 *
 * Blob content (implementation decision, opaque to the backend): the
 * device's Ed25519 identity private key plus a snapshot of cached
 * group secrets, AES-256-GCM-sealed with the user id bound as AAD;
 * the ciphertext field is `nonce(12) || ct+tag`, versioned by the
 * blob's `suite` field (spec §6.3). Thanks to the §9.7 secret history
 * chain, the identity key alone is enough to recover every group the
 * device still belongs to — restore, resync, open the head envelope,
 * walk history — so even a stale blob recovers current groups; the
 * snapshot only adds coverage for groups the user was removed from.
 */

import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  utf8Bytes,
  wipe,
} from "../core/bytes";
import { canonicalBytes } from "../core/codec";
import { deriveRelayHandle } from "../core/handles";
import {
  BackupError,
  CryptoError,
  StorageError,
  TransportError,
} from "../core/errors";
import { SUITE_V1, type EncryptedBackupBlob } from "../core/types";
import type { Argon2Params, CryptoProvider } from "../ports/crypto-provider";
import type { StorageAdapter, StoredIdentity } from "../ports/storage";
import type { SyncManager } from "./sync-manager";

const CREDENTIAL_LENGTH = 16; // 128 bits (spec §9.6)
const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

/** The KDFs a backup blob may declare (spec §6.2). */
export type BackupKdf = EncryptedBackupBlob["kdf"];

/** spec §6.2: PBKDF2-HMAC-SHA256 minimum iteration count. */
export const PBKDF2_ITERATIONS = 600_000;

/**
 * spec §6.2 Argon2id baseline: 19 MiB memory, 2 iterations,
 * parallelism 1 — the stated minimum, and the default here because it
 * is the variant that works on memory-constrained devices too.
 */
export const ARGON2ID_PARAMS: Argon2Params = {
  memoryKiB: 19_456,
  iterations: 2,
  parallelism: 1,
};

/**
 * spec §6.2's higher-memory alternative (46 MiB, 1 iteration), which
 * the spec says implementations SHOULD prefer *where more memory is
 * available*. Browsers expose no reliable way to determine that, so
 * hosts that know their deployment can opt in explicitly via
 * {@link BackupManagerOptions.argon2Params}.
 */
export const ARGON2ID_PARAMS_HIGH_MEMORY: Argon2Params = {
  memoryKiB: 47_104,
  iterations: 1,
  parallelism: 1,
};

/** What travels inside the sealed blob. */
interface BackupPayload {
  user_id: string;
  identity_private_key: string;
  /** group_id → (epoch → group_secret), all base64url. */
  secrets: Record<string, Record<string, string>>;
}

/**
 * Default relay identifier for handle blinding (spec §6.5).
 *
 * Any stable string works; what matters is that a *different* relay
 * gets a different one, so the same user is unlinkable across relays.
 * Hosts pointing at their own relay should set it explicitly.
 */
export const DEFAULT_RELAY_ID = "circlekey";

export interface BackupManagerOptions {
  /**
   * Identifier of the relay this device talks to, mixed into the
   * blinded backup handle (spec §6.5). Changing it makes existing
   * blobs unreachable, so it belongs in deployment config, not a
   * per-call argument.
   */
  relayId?: string;
  /**
   * KDF for **new** blobs. Defaults to `"argon2id"` when the
   * `CryptoProvider` implements it, else `"pbkdf2-sha256"` (spec
   * §6.2). Restore ignores this and honors the blob's own KDF.
   */
  kdf?: BackupKdf;
  /**
   * Argon2id cost override for new blobs. Defaults to
   * {@link ARGON2ID_PARAMS}; reduce only in tests, or raise via
   * {@link ARGON2ID_PARAMS_HIGH_MEMORY}.
   */
  argon2Params?: Argon2Params;
  /**
   * PBKDF2 iteration override for new blobs. The spec §6.2 minimum is
   * the default; lower values are for tests only.
   */
  kdfIterations?: number;
}

export class BackupManager {
  private readonly kdf: BackupKdf;
  private readonly relayId: string;
  private readonly iterations: number;
  private readonly argon2Params: Argon2Params;

  constructor(
    private readonly crypto: CryptoProvider,
    private readonly storage: StorageAdapter,
    private readonly sync: SyncManager,
    options: BackupManagerOptions = {},
  ) {
    this.relayId = options.relayId ?? DEFAULT_RELAY_ID;
    const iterations = options.kdfIterations ?? PBKDF2_ITERATIONS;
    if (!Number.isSafeInteger(iterations) || iterations < 1) {
      throw new BackupError("kdfIterations must be a positive integer");
    }
    this.iterations = iterations;
    this.argon2Params = options.argon2Params ?? ARGON2ID_PARAMS;

    const argon2Available = typeof crypto.argon2id === "function";
    if (options.kdf === "argon2id" && !argon2Available) {
      throw new BackupError(
        "kdf: \"argon2id\" requested but this CryptoProvider does not implement argon2id (spec §6.2)",
      );
    }
    // spec §6.2: Argon2id primary, PBKDF2 the sanctioned fallback.
    this.kdf = options.kdf ?? (argon2Available ? "argon2id" : "pbkdf2-sha256");
  }

  /** The KDF this instance will use for new blobs (spec §6.2). */
  get activeKdf(): BackupKdf {
    return this.kdf;
  }

  async isEnrolled(): Promise<boolean> {
    return (await this.storage.getIdentity())?.backupEnrolled ?? false;
  }

  /**
   * Phase one of enrollment (spec §9.6): generate the recovery
   * credential, seal the backup blob and upload it. The credential is
   * returned exactly once.
   *
   * This does **not** complete enrollment — group operations stay
   * blocked until {@link confirmEnrollment} is called with the same
   * credential, which is how "no skip for now" is enforced
   * structurally rather than by host convention.
   */
  async enroll(): Promise<string> {
    const identity = await this.requireIdentity();
    if (identity.backupEnrolled) {
      throw new BackupError("already enrolled — use refresh(credential) to update the blob");
    }
    const credential = bytesToBase64Url(this.crypto.randomBytes(CREDENTIAL_LENGTH));
    await this.upload(identity, credential);
    // Deliberately does NOT set `backupEnrolled`. spec §9.6 requires
    // the client to "block further progress until the user confirms
    // they've stored it. There is no 'skip for now.'" Opening the gate
    // here would enforce only that a blob exists — a host that
    // discarded the returned string would leave an enrolled device
    // whose backup nobody can open, which is the exact failure §9.6
    // exists to prevent. The gate opens in `confirmEnrollment()`.
    return credential;
  }

  /**
   * Record that the user has stored their recovery credential, which
   * is what actually completes enrollment and unblocks group
   * operations (spec §9.6).
   *
   * Call this only after the credential has been shown and the user
   * has confirmed they saved it. The credential is re-verified against
   * the stored blob first, so confirming a value that cannot actually
   * open the backup is impossible.
   */
  async confirmEnrollment(credential: string): Promise<void> {
    const identity = await this.requireIdentity();
    if (identity.backupEnrolled) return; // already complete; idempotent
    // Fail closed: a typo'd or fabricated confirmation must not open
    // the gate on an unrecoverable backup.
    await this.open(identity.userId, credential);
    await this.storage.putIdentity({ ...identity, backupEnrolled: true });
  }

  /**
   * Re-seal the current identity + secret snapshot under the existing
   * credential. The credential is verified against the stored blob
   * first, so a typo can never overwrite a good backup with an
   * unrecoverable one.
   */
  async refresh(credential: string): Promise<void> {
    const identity = await this.requireIdentity();
    if (!identity.backupEnrolled) {
      throw new BackupError("not enrolled yet — call enroll() first");
    }
    await this.open(identity.userId, credential); // fail closed on mismatch
    await this.upload(identity, credential);
  }

  /**
   * Restore onto a fresh device: fetch the blob, unseal it with the
   * recovery credential, persist the identity (already enrolled) and
   * any snapshotted secrets. Follow with `GroupManager.syncGroup` to
   * re-verify chains and recover the remaining secrets via the §9.7
   * history chain.
   */
  async restore(userId: string, credential: string): Promise<StoredIdentity> {
    const payload = await this.open(userId, credential);
    const identity: StoredIdentity = {
      userId: payload.user_id,
      identityPrivateKey: base64UrlToBytes(payload.identity_private_key),
      backupEnrolled: true,
    };
    await this.storage.putIdentity(identity);
    for (const [groupId, epochs] of Object.entries(payload.secrets)) {
      for (const [epochKey, secret] of Object.entries(epochs)) {
        await this.storage.putGroupSecret(
          groupId,
          Number(epochKey),
          base64UrlToBytes(secret),
        );
      }
    }
    return identity;
  }

  private async requireIdentity(): Promise<StoredIdentity> {
    const identity = await this.storage.getIdentity();
    if (identity === undefined) {
      throw new StorageError("no device identity to back up — create one first");
    }
    return identity;
  }

  private async upload(identity: StoredIdentity, credential: string): Promise<void> {
    const secrets: BackupPayload["secrets"] = {};
    for (const groupId of await this.storage.listGroupIds()) {
      const perGroup = await this.storage.getGroupSecrets(groupId);
      if (perGroup.size === 0) continue;
      secrets[groupId] = Object.fromEntries(
        [...perGroup.entries()].map(([epoch, secret]) => [
          String(epoch),
          bytesToBase64Url(secret),
        ]),
      );
    }
    const payload: BackupPayload = {
      user_id: identity.userId,
      identity_private_key: bytesToBase64Url(identity.identityPrivateKey),
      secrets,
    };

    const salt = this.crypto.randomBytes(SALT_LENGTH);
    // spec §6.2: record the KDF and its parameters with the blob so it
    // stays openable after any future parameter or primitive change.
    const kdfParams: EncryptedBackupBlob["kdf_params"] =
      this.kdf === "argon2id"
        ? {
            iterations: this.argon2Params.iterations,
            memory_kib: this.argon2Params.memoryKiB,
            parallelism: this.argon2Params.parallelism,
          }
        : { iterations: this.iterations };
    const key = await this.derive(this.kdf, kdfParams, credential, salt);
    const serialized = utf8Bytes(JSON.stringify(payload));
    const nonce = this.crypto.randomBytes(NONCE_LENGTH); // spec §6.1
    let ciphertext: Uint8Array;
    try {
      ciphertext = await this.crypto.aesGcmEncrypt(
        key,
        nonce,
        serialized,
        backupAad(identity.userId),
      );
    } finally {
      // The serialized payload holds the identity key and every cached
      // group secret in the clear.
      wipe(key, serialized);
    }
    const blob: EncryptedBackupBlob = {
      ciphertext: bytesToBase64Url(concatBytes(nonce, ciphertext)),
      salt: bytesToBase64Url(salt),
      kdf: this.kdf,
      kdf_params: kdfParams,
      suite: SUITE_V1,
    };
    // spec §6.5: addressed by a blinded handle, never by user identity.
    // The AAD still binds the *real* user id, so a blob cannot be
    // replayed onto another account even though the relay never learns
    // whose it is.
    await this.sync.putBackupBlob(await this.handleFor(credential), blob);
  }

  /**
   * The blinded handle this device's backup lives under (spec §6.5).
   *
   * Derived from the identity *private* key, so it is stable for the
   * user across sessions and restored devices, and unlinkable to the
   * same user at another relay.
   */
  private handleFor(credential: string): Promise<string> {
    return deriveRelayHandle(
      (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
        this.crypto.hkdfSha256(ikm, salt, info, length),
      credential,
      this.relayId,
    );
  }

  private async open(userId: string, credential: string): Promise<BackupPayload> {
    // A wrong credential derives a *different* handle, so the relay
    // answers "no such blob" rather than "bad credential". Both are
    // reported identically and deliberately: distinguishing them would
    // turn the relay into an oracle for guessing credentials, and the
    // caller's remedy is the same either way.
    let blob: EncryptedBackupBlob;
    try {
      blob = await this.sync.getBackupBlob(await this.handleFor(credential));
    } catch (error) {
      if (error instanceof TransportError) {
        throw new BackupError("invalid recovery credential or no backup stored");
      }
      throw error;
    }
    if (blob.suite !== SUITE_V1) {
      throw new BackupError(`unsupported backup suite: ${blob.suite}`);
    }
    // Widened deliberately: the blob comes from the backend, so the
    // declared union is a claim to verify, not a guarantee.
    const declaredKdf: string = blob.kdf;
    if (declaredKdf !== "pbkdf2-sha256" && declaredKdf !== "argon2id") {
      throw new BackupError(`unsupported backup KDF: ${declaredKdf}`);
    }
    const iterations = blob.kdf_params.iterations;
    if (!Number.isSafeInteger(iterations) || iterations < 1) {
      throw new BackupError("backup blob carries invalid KDF parameters");
    }

    let bytes: Uint8Array;
    let salt: Uint8Array;
    try {
      bytes = base64UrlToBytes(blob.ciphertext);
      salt = base64UrlToBytes(blob.salt);
    } catch {
      throw new BackupError("backup blob is not valid base64url");
    }
    if (bytes.length < NONCE_LENGTH + TAG_LENGTH) {
      throw new BackupError("backup blob is truncated");
    }

    // spec §6.2: derive with the KDF and parameters stored alongside
    // the blob — never with this instance's configuration.
    const key = await this.derive(blob.kdf, blob.kdf_params, credential, salt);
    let plaintext: Uint8Array;
    try {
      plaintext = await this.crypto.aesGcmDecrypt(
        key,
        bytes.subarray(0, NONCE_LENGTH),
        bytes.subarray(NONCE_LENGTH),
        backupAad(userId),
      );
    } catch (error) {
      if (error instanceof CryptoError) {
        throw new BackupError("invalid recovery credential or corrupted backup blob");
      }
      throw error;
    } finally {
      wipe(key);
    }
    try {
      return parsePayload(JSON.parse(new TextDecoder().decode(plaintext)));
    } finally {
      // The decrypted payload carries the identity key and cached
      // secrets; the parsed copy is what the caller keeps.
      wipe(plaintext);
    }
  }

  /**
   * Derive the backup key under an explicit KDF + parameter set
   * (spec §6.2). Both call sites pass the parameters that belong with
   * the blob being written or read, so this never consults instance
   * configuration.
   */
  private derive(
    kdf: BackupKdf,
    params: EncryptedBackupBlob["kdf_params"],
    credential: string,
    salt: Uint8Array,
  ): Promise<Uint8Array> {
    const password = utf8Bytes(credential);
    if (kdf === "pbkdf2-sha256") {
      return this.crypto.pbkdf2Sha256(password, salt, params.iterations, KEY_LENGTH);
    }
    const argon2id = this.crypto.argon2id?.bind(this.crypto);
    if (argon2id === undefined) {
      throw new BackupError(
        "this backup was sealed with Argon2id, but this device's CryptoProvider does not implement it (spec §6.2)",
      );
    }
    const memoryKiB = params.memory_kib;
    const parallelism = params.parallelism;
    if (
      !Number.isSafeInteger(memoryKiB) ||
      memoryKiB === undefined ||
      memoryKiB < 8 ||
      !Number.isSafeInteger(parallelism) ||
      parallelism === undefined ||
      parallelism < 1
    ) {
      throw new BackupError(
        "Argon2id backup blob is missing valid memory_kib / parallelism parameters",
      );
    }
    return argon2id(
      password,
      salt,
      { memoryKiB, iterations: params.iterations, parallelism },
      KEY_LENGTH,
    );
  }
}

function backupAad(userId: string): Uint8Array {
  return canonicalBytes({ context: "backup", suite: SUITE_V1, user_id: userId });
}

/** Hostile-input validation of the decrypted payload shape. */
function parsePayload(value: unknown): BackupPayload {
  if (typeof value !== "object" || value === null) {
    throw new BackupError("backup payload is not an object");
  }
  const record = value as Record<string, unknown>;
  const userId = record.user_id;
  const identityKey = record.identity_private_key;
  const secrets = record.secrets;
  if (typeof userId !== "string" || typeof identityKey !== "string") {
    throw new BackupError("backup payload is malformed");
  }
  if (base64UrlToBytes(identityKey).length !== 32) {
    throw new BackupError("backup payload carries a malformed identity key");
  }
  if (typeof secrets !== "object" || secrets === null) {
    throw new BackupError("backup payload is malformed");
  }
  for (const epochs of Object.values(secrets as Record<string, unknown>)) {
    if (typeof epochs !== "object" || epochs === null) {
      throw new BackupError("backup payload is malformed");
    }
    for (const [epochKey, secret] of Object.entries(epochs as Record<string, unknown>)) {
      if (
        !Number.isSafeInteger(Number(epochKey)) ||
        typeof secret !== "string" ||
        base64UrlToBytes(secret).length !== 32
      ) {
        throw new BackupError("backup payload carries a malformed group secret");
      }
    }
  }
  return {
    user_id: userId,
    identity_private_key: identityKey,
    secrets: secrets as BackupPayload["secrets"],
  };
}
