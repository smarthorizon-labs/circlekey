/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * HKDF-SHA256 key derivation with enforced domain separation (spec §7).
 *
 * The `info` labels form a closed set: callers pick a `KdfLabel`, so a
 * free-form or colliding label is unrepresentable in the type system
 * (a non-negotiable invariant). HKDF itself enters via a function parameter —
 * `core/` imports no crypto.
 */

import { concatBytes, utf8Bytes } from "./bytes";

export const KDF_LABELS = {
  /** spec §7: per-record encryption key; context = `record_id`. */
  recordKey: "groupvault/record-key/v1",
  /** spec §7: group metadata encryption key; no context. */
  metadataKey: "groupvault/metadata-key/v1",
  /**
   * ECIES-style envelope sealing key; used by
   * `core/envelopes.ts`.
   */
  envelopeKey: "groupvault/envelope-key/v1",
  /** spec §7/§9.7: secret history chain link key. */
  historyKey: "groupvault/history-key/v1",
  /** spec §6.5/§7: sealing key for the transition body. */
  transitionBody: "groupvault/transition-body/v1",
  /**
   * spec §6.5/§7/§10.1: seed for the per-epoch Ed25519 keypair members
   * use to authenticate relay requests. Derives signing material, not
   * an AES key — same closed set regardless, so a cross-context reuse
   * is unrepresentable rather than merely discouraged.
   */
  relayAuth: "groupvault/relay-auth/v1",
  /** spec §6.5/§7: stable pseudorandom `record_id`; context = app key. */
  recordId: "groupvault/record-id/v1",
  /**
   * spec §6.5: sealing key for the removal notice.
   *
   * Keyed on `group_secret[epoch-1]` — the *previous* epoch — because
   * the audience is every remaining member plus the members just
   * removed, and the removed never receive the current epoch's secret.
   * Sealing under the current one would deliver the notice to everyone
   * except its intended recipient.
   */
  removalNotice: "groupvault/removal-notice/v1",
  /**
   * spec §6.5: per-relay blinded user handle; context = relay id.
   * The only label whose IKM is a device identity key rather than a
   * `group_secret` — the handle must be stable for a user across all
   * their groups, so it cannot be group-scoped.
   */
  relayHandle: "groupvault/relay-handle/v1",
} as const;

export type KdfLabel = (typeof KDF_LABELS)[keyof typeof KDF_LABELS];

export type HkdfSha256Fn = (
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
) => Promise<Uint8Array>;

/** All derived symmetric keys are 256-bit (AES-256-GCM, spec §6). */
export const DERIVED_KEY_LENGTH = 32;

const EMPTY_SALT = new Uint8Array(0);

/**
 * spec §7: info = label || context (e.g. `record_id` appended raw).
 * String contexts are UTF-8 encoded; binary contexts (e.g. envelope
 * key transcripts) are appended as-is.
 */
export function kdfInfo(label: KdfLabel, context?: string | Uint8Array): Uint8Array {
  if (context === undefined) return utf8Bytes(label);
  const contextBytes = typeof context === "string" ? utf8Bytes(context) : context;
  return concatBytes(utf8Bytes(label), contextBytes);
}

/**
 * Derive a 32-byte key from `ikm` (typically a `group_secret`) under
 * the given label. Zero-length HKDF salt by design: domain separation
 * comes entirely from the closed `info` label set.
 */
export async function deriveKey(
  hkdf: HkdfSha256Fn,
  ikm: Uint8Array,
  label: KdfLabel,
  context?: string | Uint8Array,
): Promise<Uint8Array> {
  return deriveBytes(hkdf, ikm, label, DERIVED_KEY_LENGTH, context);
}

/**
 * Variable-length derivation, for the contexts that are not 256-bit
 * symmetric keys: 16-byte identifiers (`record_id`, relay handles) and
 * the 32-byte Ed25519 seed of spec §6.5.
 *
 * HKDF-Expand is prefix-consistent, so deriving 16 bytes here yields
 * exactly the first 16 bytes of a 32-byte derivation under the same
 * label — the two spellings in spec §6.5 describe one value.
 */
export async function deriveBytes(
  hkdf: HkdfSha256Fn,
  ikm: Uint8Array,
  label: KdfLabel,
  length: number,
  context?: string | Uint8Array,
): Promise<Uint8Array> {
  return hkdf(ikm, EMPTY_SALT, kdfInfo(label, context), length);
}
