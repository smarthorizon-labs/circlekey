/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Secret envelopes: a `group_secret` sealed to one device's X25519
 * key (spec §2.2, §9.1). ECIES-style construction (an
 * implementation decision, frozen by the chain test vectors):
 *
 *   ephemeral X25519 → shared secret
 *   key  = HKDF-SHA256(shared, info = envelope label || eph_pub || recipient_pub)
 *   blob = version(1) || epoch(8, big-endian) || eph_pub(32) || nonce(12) || AES-256-GCM(ct||tag)
 *   AAD  = version || epoch || eph_pub || recipient_pub
 *
 * The version byte is the suite identifier required by spec §6.3
 * (0x01 = suite "gv1"). The epoch header is plaintext-readable so
 * chain verification can classify envelopes (current vs. historical,
 * spec §9.2/§9.7) without decrypting; it is bound by the AAD, so a
 * relabelled epoch fails authentication. The AAD's recipient key
 * prevents an envelope from being replayed against another device.
 */

import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  utf8Bytes,
  wipe,
} from "./bytes";
import { CryptoError, EnvelopeError } from "./errors";
import { deriveKey, KDF_LABELS } from "./kdf";
import { LENGTH_PREFIX_BYTES, pad, unpad } from "./padding";
import type { SecretEnvelope } from "./types";
import type { CryptoProvider, KeyPair } from "../ports/crypto-provider";

/** Suite "gv1" (spec §6.3). */
export const ENVELOPE_VERSION = 0x01;
export const GROUP_SECRET_LENGTH = 32;

const EPOCH_OFFSET = 1;
const EPHEMERAL_OFFSET = 9;
const NONCE_OFFSET = 41;
const CIPHERTEXT_OFFSET = 53;
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const MIN_BLOB_LENGTH = CIPHERTEXT_OFFSET + TAG_LENGTH;

/** Seal `groupSecret` for `epoch` to one device key. */
export async function sealEnvelope(
  crypto: CryptoProvider,
  recipientDevicePubkey: string,
  epoch: number,
  groupSecret: Uint8Array,
): Promise<SecretEnvelope> {
  if (groupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new EnvelopeError("group_secret must be 32 bytes");
  }
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new EnvelopeError("envelope epoch must be a non-negative integer");
  }
  const recipientPub = decodeDeviceKey(recipientDevicePubkey);

  const ephemeral = await crypto.generateX25519KeyPair();
  const shared = await crypto.x25519SharedSecret(ephemeral.privateKey, recipientPub);
  const key = await envelopeKey(crypto, shared, ephemeral.publicKey, recipientPub);
  try {
    const header = buildHeader(epoch, ephemeral.publicKey);
    const aad = concatBytes(header, recipientPub);
    const nonce = crypto.randomBytes(NONCE_LENGTH); // spec §6.1: CSPRNG, fresh
    const ciphertext = await crypto.aesGcmEncrypt(key, nonce, groupSecret, aad);

    return bytesToBase64Url(concatBytes(header, nonce, ciphertext));
  } finally {
    // The ephemeral private key is single-use by construction; the
    // shared secret and sealing key are done.
    wipe(ephemeral.privateKey, shared, key);
  }
}

/** Open an envelope addressed to this device's X25519 keypair. */
export async function openEnvelope(
  crypto: CryptoProvider,
  recipientEncryptionKeys: KeyPair,
  envelope: SecretEnvelope,
): Promise<{ epoch: number; groupSecret: Uint8Array }> {
  const blob = decodeBlob(envelope);
  const epoch = readEpoch(blob);
  const ephemeralPub = blob.subarray(EPHEMERAL_OFFSET, NONCE_OFFSET);
  const nonce = blob.subarray(NONCE_OFFSET, CIPHERTEXT_OFFSET);
  const ciphertext = blob.subarray(CIPHERTEXT_OFFSET);

  const shared = await crypto.x25519SharedSecret(
    recipientEncryptionKeys.privateKey,
    ephemeralPub,
  );
  const key = await envelopeKey(
    crypto,
    shared,
    ephemeralPub,
    recipientEncryptionKeys.publicKey,
  );
  const aad = concatBytes(
    blob.subarray(0, NONCE_OFFSET),
    recipientEncryptionKeys.publicKey,
  );

  let groupSecret: Uint8Array;
  try {
    groupSecret = await crypto.aesGcmDecrypt(key, nonce, ciphertext, aad);
  } catch (error) {
    if (error instanceof CryptoError) {
      throw new EnvelopeError("envelope authentication failed");
    }
    throw error;
  } finally {
    // `groupSecret` belongs to the caller and is deliberately not
    // wiped here; these two are ours.
    wipe(shared, key);
  }
  if (groupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new EnvelopeError("envelope payload is not a 32-byte group_secret");
  }
  return { epoch, groupSecret };
}

/**
 * Read the epoch header without decrypting — used by chain
 * verification to classify current vs. historical envelopes. The
 * value is authenticated only once the envelope is opened.
 */
export function envelopeEpoch(envelope: SecretEnvelope): number {
  return readEpoch(decodeBlob(envelope));
}

/**
 * A decoy envelope (spec §6.5): structurally identical to a real one,
 * openable by nobody.
 *
 * It must match a real envelope byte-for-byte in every field the relay
 * can read — same length, same version byte, the transition's true
 * epoch — with CSPRNG bytes standing in for the ephemeral key, nonce
 * and ciphertext. A decoy that differs anywhere observable (a zero
 * ephemeral key, a wrong version, a constant) is filterable, and once
 * decoys are filterable the padding conveys nothing.
 *
 * They must also be freshly generated per transition: repeating a decoy
 * across epochs identifies it by correlation.
 */
export function makeDecoyEnvelope(crypto: CryptoProvider, epoch: number): SecretEnvelope {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new EnvelopeError("envelope epoch must be a non-negative integer");
  }
  const header = buildHeader(epoch, crypto.randomBytes(32));
  return bytesToBase64Url(
    concatBytes(
      header,
      crypto.randomBytes(NONCE_LENGTH),
      crypto.randomBytes(GROUP_SECRET_LENGTH + TAG_LENGTH),
    ),
  );
}

/**
 * Trial-decrypt an envelope array with one device keypair (spec §6.5
 * check O1), returning the slot that opened.
 *
 * Envelopes are unaddressed, so finding your own means trying each in
 * turn: ~45 X25519 operations at the `lite` profile, a few milliseconds,
 * once per epoch. Returns `undefined` rather than throwing when nothing
 * opens — that is the ordinary "this device has no access at this
 * epoch" answer (spec §9.3), not an error, and a malformed blob among
 * the candidates must not mask a real envelope later in the array.
 */
export async function openAnyEnvelope(
  crypto: CryptoProvider,
  recipientEncryptionKeys: KeyPair,
  envelopes: readonly SecretEnvelope[],
): Promise<{ slot: number; epoch: number; groupSecret: Uint8Array } | undefined> {
  for (let slot = 0; slot < envelopes.length; slot++) {
    const envelope = envelopes[slot];
    if (envelope === undefined) continue;
    try {
      const opened = await openEnvelope(crypto, recipientEncryptionKeys, envelope);
      return { slot, ...opened };
    } catch (error) {
      if (error instanceof EnvelopeError) continue;
      throw error;
    }
  }
  return undefined;
}

/**
 * Place `real` envelopes at CSPRNG-chosen slots and fill the rest with
 * decoys (spec §6.5).
 *
 * Returns the padded array together with the slot each real envelope
 * landed in, which the caller records as `envelope_slots` so verifiers
 * can prove the mapping (spec §9.1 check 9).
 *
 * Placement must be random, not sequential: appending the real
 * envelopes and padding after them would put the device count back on
 * the wire as "the index of the first decoy".
 */
export function placeEnvelopes(
  crypto: CryptoProvider,
  real: readonly SecretEnvelope[],
  epoch: number,
  slotCount: number,
): { envelopes: SecretEnvelope[]; slots: number[] } {
  if (!Number.isSafeInteger(slotCount) || slotCount < 1) {
    throw new EnvelopeError("envelope slot count must be a positive integer");
  }
  if (real.length > slotCount) {
    throw new EnvelopeError(
      `${String(real.length)} envelopes exceed the profile's ${String(slotCount)} slots — ` +
        "the group has outgrown its capacity profile (spec §6.5)",
    );
  }
  const chosen = distinctRandomIndices(crypto, real.length, slotCount);
  const envelopes: SecretEnvelope[] = new Array<SecretEnvelope>(slotCount);
  for (const [index, slot] of chosen.entries()) {
    const item = real[index];
    if (item !== undefined) envelopes[slot] = item;
  }
  for (let slot = 0; slot < slotCount; slot++) {
    envelopes[slot] ??= makeDecoyEnvelope(crypto, epoch);
  }
  return { envelopes, slots: chosen };
}

/**
 * `count` distinct indices in `[0, range)`, uniformly chosen.
 *
 * Partial Fisher-Yates over a full index array: unbiased, and it cannot
 * loop on collisions the way rejection sampling into a set can when
 * `count` approaches `range` (a full group takes every slot).
 */
function distinctRandomIndices(
  crypto: CryptoProvider,
  count: number,
  range: number,
): number[] {
  const pool = Array.from({ length: range }, (_, i) => i);
  for (let i = 0; i < count; i++) {
    const j = i + randomBelow(crypto, range - i);
    const a = pool[i] ?? 0;
    const b = pool[j] ?? 0;
    pool[i] = b;
    pool[j] = a;
  }
  return pool.slice(0, count);
}

/**
 * Uniform integer in `[0, bound)` via rejection sampling — a plain
 * `% bound` would bias low indices, which over many transitions is a
 * distinguisher between real slots and decoy slots.
 */
function randomBelow(crypto: CryptoProvider, bound: number): number {
  if (bound <= 1) return 0;
  const limit = Math.floor(0x100000000 / bound) * bound;
  for (;;) {
    const bytes = crypto.randomBytes(4);
    const value =
      (bytes[0] ?? 0) * 0x1000000 +
      ((bytes[1] ?? 0) << 16) +
      ((bytes[2] ?? 0) << 8) +
      (bytes[3] ?? 0);
    if (value < limit) return value % bound;
  }
}

async function envelopeKey(
  crypto: CryptoProvider,
  shared: Uint8Array,
  ephemeralPub: Uint8Array,
  recipientPub: Uint8Array,
): Promise<Uint8Array> {
  const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
    crypto.hkdfSha256(ikm, salt, info, length);
  return deriveKey(
    hkdf,
    shared,
    KDF_LABELS.envelopeKey,
    concatBytes(ephemeralPub, recipientPub),
  );
}

// --- Secret history chain (spec §9.7) -------------------------------------
//
// `prev_secret_ciphertext` blob layout:
//   version(1) || nonce(12) || AES-256-GCM(group_secret[epoch-1])+tag
// with key = HKDF(group_secret[epoch], "groupvault/history-key/v1")
// and AAD = utf8(group_id) || epoch(8, big-endian).

const HISTORY_NONCE_OFFSET = 1;
const HISTORY_CIPHERTEXT_OFFSET = HISTORY_NONCE_OFFSET + NONCE_LENGTH;
const HISTORY_BLOB_LENGTH =
  HISTORY_CIPHERTEXT_OFFSET + GROUP_SECRET_LENGTH + TAG_LENGTH;

/** Seal `group_secret[epoch-1]` under `group_secret[epoch]` (spec §9.7). */
export async function sealHistoryLink(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  currentGroupSecret: Uint8Array,
  prevGroupSecret: Uint8Array,
): Promise<string> {
  if (
    currentGroupSecret.length !== GROUP_SECRET_LENGTH ||
    prevGroupSecret.length !== GROUP_SECRET_LENGTH
  ) {
    throw new EnvelopeError("group_secret must be 32 bytes");
  }
  if (!Number.isSafeInteger(epoch) || epoch < 1) {
    throw new EnvelopeError("history link epoch must be an integer >= 1");
  }
  const key = await historyKey(crypto, currentGroupSecret);
  try {
    const nonce = crypto.randomBytes(NONCE_LENGTH); // spec §6.1
    const ciphertext = await crypto.aesGcmEncrypt(
      key,
      nonce,
      prevGroupSecret,
      historyAad(groupId, epoch),
    );
    const blob = new Uint8Array(HISTORY_NONCE_OFFSET);
    blob[0] = ENVELOPE_VERSION;
    return bytesToBase64Url(concatBytes(blob, nonce, ciphertext));
  } finally {
    wipe(key);
  }
}

/** Recover `group_secret[epoch-1]` from a history link (spec §9.7). */
export async function openHistoryLink(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  currentGroupSecret: Uint8Array,
  link: string,
): Promise<Uint8Array> {
  const blob = decodeHistoryBlob(link);
  const nonce = blob.subarray(HISTORY_NONCE_OFFSET, HISTORY_CIPHERTEXT_OFFSET);
  const ciphertext = blob.subarray(HISTORY_CIPHERTEXT_OFFSET);
  const key = await historyKey(crypto, currentGroupSecret);
  try {
    return await crypto.aesGcmDecrypt(key, nonce, ciphertext, historyAad(groupId, epoch));
  } catch (error) {
    if (error instanceof CryptoError) {
      throw new EnvelopeError("history link authentication failed");
    }
    throw error;
  } finally {
    wipe(key);
  }
}

/**
 * Structural validation only (spec §9.1 check 6) — content can only be
 * verified by a client holding the previous secret (spec §9.7).
 */
export function validateHistoryLinkShape(link: string): void {
  decodeHistoryBlob(link);
}

// --- Sealed transition body (spec §6.5) ----------------------
//
// `sealed_body` blob layout:
//   version(1) || nonce(12) || AES-256-GCM(padded inner JCS)+tag
// with key = HKDF(group_secret[epoch], "groupvault/transition-body/v1"),
// AAD = utf8(group_id) || epoch(8, big-endian) — the same AAD shape as
// the history link, under a different label. The plaintext is padded to
// the capacity profile's fixed size (spec §5.8 rule 3) before sealing,
// so ciphertext length reveals the profile and nothing else.

const BODY_NONCE_OFFSET = 1;
const BODY_CIPHERTEXT_OFFSET = BODY_NONCE_OFFSET + NONCE_LENGTH;
/** version + nonce + at least the 4-byte length prefix + GCM tag. */
const MIN_BODY_BLOB_LENGTH = BODY_CIPHERTEXT_OFFSET + LENGTH_PREFIX_BYTES + TAG_LENGTH;

/**
 * Seal the canonical bytes of an inner transition (spec §6.5).
 *
 * `epoch` and `groupId` are the **outer** routing values; binding them
 * as AAD is what stops a relay relabelling a body onto a different
 * position or group. `bodySize` is the profile's fixed padded size —
 * a body that does not fit is the group outgrowing its profile, and
 * refusing here beats emitting an oversized blob every verifier will
 * reject.
 */
export async function sealTransitionBody(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  innerBytes: Uint8Array,
  bodySize: number,
): Promise<string> {
  if (groupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new EnvelopeError("group_secret must be 32 bytes");
  }
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new EnvelopeError("sealed body epoch must be a non-negative integer");
  }
  let padded: Uint8Array;
  try {
    padded = pad(innerBytes, bodySize);
  } catch (error) {
    void error;
    throw new EnvelopeError(
      `transition body does not fit its capacity profile (${String(innerBytes.length)} ` +
        `bytes into ${String(bodySize)}) — the group has outgrown the profile (spec §6.5)`,
    );
  }
  const key = await transitionBodyKey(crypto, groupSecret);
  try {
    const nonce = crypto.randomBytes(NONCE_LENGTH); // spec §6.1
    const ciphertext = await crypto.aesGcmEncrypt(
      key,
      nonce,
      padded,
      historyAad(groupId, epoch),
    );
    const version = new Uint8Array([ENVELOPE_VERSION]);
    return bytesToBase64Url(concatBytes(version, nonce, ciphertext));
  } finally {
    wipe(key, padded);
  }
}

/**
 * Open a sealed body (spec §9.1 checks O2 and O4).
 *
 * The padded size is inferred from the blob and **returned to the
 * caller**, who MUST compare it against the profile once the inner
 * policy is known — the profile is inside the body for a genesis, so
 * it cannot be checked before decrypting. Unpadding verifies the
 * declared length and that every padding byte is zero (spec §6.5);
 * authentication failure means "not produced by a holder of this
 * epoch's secret, or relabelled".
 *
 * Opening proves membership, never authorization (spec §9.1): the
 * caller MUST still run the full inner checklist on the result.
 */
export async function openTransitionBody(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  sealedBody: string,
): Promise<{ innerBytes: Uint8Array; paddedSize: number }> {
  let blob: Uint8Array;
  try {
    blob = base64UrlToBytes(sealedBody);
  } catch {
    throw new EnvelopeError("sealed body is not valid base64url");
  }
  if (blob.length < MIN_BODY_BLOB_LENGTH) {
    throw new EnvelopeError("sealed body blob is too short");
  }
  if (blob[0] !== ENVELOPE_VERSION) {
    throw new EnvelopeError(`unsupported sealed body suite: ${String(blob[0])}`);
  }
  const nonce = blob.subarray(BODY_NONCE_OFFSET, BODY_CIPHERTEXT_OFFSET);
  const ciphertext = blob.subarray(BODY_CIPHERTEXT_OFFSET);
  const paddedSize = ciphertext.length - TAG_LENGTH;

  const key = await transitionBodyKey(crypto, groupSecret);
  let padded: Uint8Array;
  try {
    padded = await crypto.aesGcmDecrypt(key, nonce, ciphertext, historyAad(groupId, epoch));
  } catch (error) {
    if (error instanceof CryptoError) {
      throw new EnvelopeError("sealed body authentication failed");
    }
    throw error;
  } finally {
    wipe(key);
  }
  try {
    // spec §6.5: verify the padding, never assume it — the padding
    // region is relay-influenced space (check O4).
    return { innerBytes: unpad(padded, paddedSize), paddedSize };
  } catch (error) {
    void error;
    throw new EnvelopeError("sealed body padding is invalid (spec §6.5)");
  } finally {
    wipe(padded);
  }
}

// --- Removal notice (spec §6.5) ------------------------------
//
// Layout mirrors the sealed body: version(1) || nonce(12) || AEAD.
// The key is derived from `group_secret[epoch-1]` — the *previous*
// epoch — so the notice reaches every remaining member and the members
// just removed, and nobody else.

/**
 * Seal a removal notice, or padding when nothing was removed.
 *
 * `previousGroupSecret` is `group_secret[epoch-1]`. Passing the current
 * epoch's secret would produce a blob readable by everyone *except* the
 * people it is addressed to, which is the one mistake this construction
 * exists to prevent — hence the parameter name.
 */
export async function sealRemovalNotice(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  previousGroupSecret: Uint8Array,
  noticeBytes: Uint8Array,
  noticeSize: number,
): Promise<string> {
  if (previousGroupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new EnvelopeError("group_secret must be 32 bytes");
  }
  if (!Number.isSafeInteger(epoch) || epoch < 1) {
    throw new EnvelopeError("removal notice epoch must be an integer >= 1");
  }
  let padded: Uint8Array;
  try {
    padded = pad(noticeBytes, noticeSize);
  } catch {
    throw new EnvelopeError(
      `removal notice does not fit its capacity profile (${String(noticeBytes.length)} ` +
        `bytes into ${String(noticeSize)}) — too many devices removed at once (spec §6.5)`,
    );
  }
  const key = await removalNoticeKey(crypto, previousGroupSecret);
  try {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const ciphertext = await crypto.aesGcmEncrypt(
      key,
      nonce,
      padded,
      historyAad(groupId, epoch),
    );
    return bytesToBase64Url(
      concatBytes(new Uint8Array([ENVELOPE_VERSION]), nonce, ciphertext),
    );
  } finally {
    wipe(key, padded);
  }
}

/**
 * Open a removal notice, returning its bytes — empty when the
 * transition removed nothing.
 *
 * Only a holder of `group_secret[epoch-1]` can do this. A device
 * catching up from a backup restore may not hold it; that is an
 * ordinary state, not a verification failure (spec §9.1 check 11), and
 * callers must distinguish "checked and passed" from "could not check".
 */
export async function openRemovalNotice(
  crypto: CryptoProvider,
  groupId: string,
  epoch: number,
  previousGroupSecret: Uint8Array,
  sealed: string,
  noticeSize: number,
): Promise<Uint8Array> {
  let blob: Uint8Array;
  try {
    blob = base64UrlToBytes(sealed);
  } catch {
    throw new EnvelopeError("removal notice is not valid base64url");
  }
  if (blob.length < BODY_CIPHERTEXT_OFFSET + LENGTH_PREFIX_BYTES + TAG_LENGTH) {
    throw new EnvelopeError("removal notice blob is too short");
  }
  if (blob[0] !== ENVELOPE_VERSION) {
    throw new EnvelopeError(`unsupported removal notice suite: ${String(blob[0])}`);
  }
  const nonce = blob.subarray(BODY_NONCE_OFFSET, BODY_CIPHERTEXT_OFFSET);
  const ciphertext = blob.subarray(BODY_CIPHERTEXT_OFFSET);
  if (ciphertext.length - TAG_LENGTH !== noticeSize) {
    throw new EnvelopeError(
      `removal notice is padded to ${String(ciphertext.length - TAG_LENGTH)} bytes, ` +
        `expected ${String(noticeSize)} for this capacity profile (spec §6.5)`,
    );
  }
  const key = await removalNoticeKey(crypto, previousGroupSecret);
  let padded: Uint8Array;
  try {
    padded = await crypto.aesGcmDecrypt(key, nonce, ciphertext, historyAad(groupId, epoch));
  } catch (error) {
    if (error instanceof CryptoError) {
      throw new EnvelopeError("removal notice authentication failed");
    }
    throw error;
  } finally {
    wipe(key);
  }
  try {
    return unpad(padded, noticeSize);
  } catch {
    throw new EnvelopeError("removal notice padding is invalid (spec §6.5)");
  } finally {
    wipe(padded);
  }
}

async function removalNoticeKey(
  crypto: CryptoProvider,
  previousGroupSecret: Uint8Array,
): Promise<Uint8Array> {
  const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
    crypto.hkdfSha256(ikm, salt, info, length);
  return deriveKey(hkdf, previousGroupSecret, KDF_LABELS.removalNotice);
}

async function transitionBodyKey(
  crypto: CryptoProvider,
  groupSecret: Uint8Array,
): Promise<Uint8Array> {
  const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
    crypto.hkdfSha256(ikm, salt, info, length);
  return deriveKey(hkdf, groupSecret, KDF_LABELS.transitionBody);
}

async function historyKey(
  crypto: CryptoProvider,
  currentGroupSecret: Uint8Array,
): Promise<Uint8Array> {
  const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) =>
    crypto.hkdfSha256(ikm, salt, info, length);
  return deriveKey(hkdf, currentGroupSecret, KDF_LABELS.historyKey);
}

function historyAad(groupId: string, epoch: number): Uint8Array {
  return concatBytes(utf8Bytes(groupId), epochBytes(epoch));
}

function decodeHistoryBlob(link: string): Uint8Array {
  let blob: Uint8Array;
  try {
    blob = base64UrlToBytes(link);
  } catch {
    throw new EnvelopeError("history link is not valid base64url");
  }
  if (blob.length !== HISTORY_BLOB_LENGTH) {
    throw new EnvelopeError("history link blob has the wrong length");
  }
  if (blob[0] !== ENVELOPE_VERSION) {
    throw new EnvelopeError(`unsupported history link suite: ${String(blob[0])}`);
  }
  return blob;
}

// ---------------------------------------------------------------------------

function epochBytes(epoch: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(epoch));
  return bytes;
}

function buildHeader(epoch: number, ephemeralPub: Uint8Array): Uint8Array {
  const header = new Uint8Array(EPHEMERAL_OFFSET + KEY_LENGTH);
  header[0] = ENVELOPE_VERSION;
  header.set(epochBytes(epoch), EPOCH_OFFSET);
  header.set(ephemeralPub, EPHEMERAL_OFFSET);
  return header;
}

function decodeBlob(ciphertext: string): Uint8Array {
  const blob = base64UrlToBytes(ciphertext);
  if (blob.length < MIN_BLOB_LENGTH) {
    throw new EnvelopeError("envelope blob is truncated");
  }
  if (blob[0] !== ENVELOPE_VERSION) {
    // spec §6.3: unknown suites are rejected, never guessed at.
    throw new EnvelopeError(`unsupported envelope suite: ${String(blob[0])}`);
  }
  return blob;
}

function readEpoch(blob: Uint8Array): number {
  const raw = new DataView(blob.buffer, blob.byteOffset).getBigUint64(EPOCH_OFFSET);
  const epoch = Number(raw);
  if (!Number.isSafeInteger(epoch)) {
    throw new EnvelopeError("envelope epoch out of range");
  }
  return epoch;
}

function decodeDeviceKey(devicePubkey: string): Uint8Array {
  const bytes = base64UrlToBytes(devicePubkey);
  if (bytes.length !== KEY_LENGTH) {
    throw new EnvelopeError("device pubkey must be 32 bytes");
  }
  return bytes;
}
