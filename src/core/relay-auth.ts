/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Per-epoch relay authentication key (spec §6.5, §10.1).
 *
 *   seed              = HKDF(group_secret[epoch], "groupvault/relay-auth/v1", L = 32)
 *   (auth_sk, auth_pk) = Ed25519 keypair from seed
 *
 * `auth_pk` travels in the outer transition so the relay learns the
 * epoch's verification key; `auth_sk` never leaves member devices. Every
 * member derives the same pair from the secret they already hold, so a
 * signed request proves "a current member sent this" and nothing more —
 * the relay cannot tell which member, and holds only public keys, so it
 * cannot mint access it was not given.
 *
 * Revocation needs no relay cooperation: a removed member is excluded
 * from the next epoch's envelopes, never obtains `group_secret[e+1]`,
 * and so cannot derive `auth_sk[e+1]`.
 *
 * **What this is for.** Sealing the transition body (spec §6.5) removed
 * the relay's ability to pre-validate submissions, so without request
 * authentication anyone who learned a `group_id` could submit a
 * well-formed blob at epoch e+1, win the uniqueness race, and deny
 * service indefinitely. This closes that. It is an *availability*
 * control, not a confidentiality one — a relay that ignores it leaks
 * nothing, it merely becomes trivially deniable-of-service (spec §10.1).
 */

import { bytesToBase64Url, wipe } from "./bytes";
import { canonicalBytes } from "./codec";
import { CryptoError } from "./errors";
import { deriveBytes, DERIVED_KEY_LENGTH, KDF_LABELS } from "./kdf";
import type { CryptoProvider, KeyPair } from "../ports/crypto-provider";

export const GROUP_SECRET_LENGTH = 32;

/**
 * Derive the epoch's relay keypair.
 *
 * An Ed25519 private key *is* its 32-byte seed (RFC 8032 §5.1.5), so
 * the HKDF output is used directly and the public key recomputed from
 * it — no separate seed-expansion step.
 */
export async function deriveRelayAuthKeyPair(
  crypto: CryptoProvider,
  groupSecret: Uint8Array,
): Promise<KeyPair> {
  if (groupSecret.length !== GROUP_SECRET_LENGTH) {
    throw new CryptoError("group_secret must be 32 bytes to derive a relay auth key");
  }
  const privateKey = await deriveBytes(
    (ikm, salt, info, length) => crypto.hkdfSha256(ikm, salt, info, length),
    groupSecret,
    KDF_LABELS.relayAuth,
    DERIVED_KEY_LENGTH,
  );
  const publicKey = await crypto.ed25519PublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Derive only the public half — what a client checks a transition's
 * `auth_pubkey` against (spec §9.1 check 7), and what a relay stores.
 */
export async function deriveRelayAuthPublicKey(
  crypto: CryptoProvider,
  groupSecret: Uint8Array,
): Promise<Uint8Array> {
  const pair = await deriveRelayAuthKeyPair(crypto, groupSecret);
  wipe(pair.privateKey);
  return pair.publicKey;
}

/**
 * The operations a relay distinguishes for authorization (spec §10.1).
 *
 * Reads accept a signature under **any** epoch key the relay has ever
 * published for the group; writes require the current one. That
 * asymmetry is load-bearing: requiring the current key for reads would
 * deadlock a client sitting at `e-1`, which could not fetch the very
 * transition that would let it catch up.
 */
export const RELAY_READ_OPS = [
  "getTransitions",
  "getGroupState",
  "getRecord",
  "listRecords",
] as const;
export const RELAY_WRITE_OPS = ["submitTransition", "putRecord"] as const;

export type RelayReadOp = (typeof RELAY_READ_OPS)[number];
export type RelayWriteOp = (typeof RELAY_WRITE_OPS)[number];
export type RelayOp = RelayReadOp | RelayWriteOp;

export function isRelayWriteOp(op: string): op is RelayWriteOp {
  return (RELAY_WRITE_OPS as readonly string[]).includes(op);
}

/** What a client attaches to a relay request (spec §10.1). */
export interface RelayRequestAuth {
  /** Which epoch's key signed — tells the relay which key to try. */
  epoch: number;
  /** Ed25519 over {@link relayRequestBytes}, base64url. */
  signature: string;
}

/**
 * Canonical bytes a relay request is signed over.
 *
 * **CircleKey's binding, not the protocol's.** Spec §10.3 leaves the
 * encoding to the transport, so this is the reference choice, the way
 * the ECIES envelope construction started out. A different transport
 * may bind differently as long as the signature is made with the
 * epoch's `auth_sk`.
 *
 * Deliberately narrow: it binds the group, the operation and the epoch,
 * and nothing else. It carries **no nonce or timestamp**, so a captured
 * signature is replayable for the life of its epoch. That is tolerable
 * here because the relay is untrusted anyway and this is an
 * availability control (spec §10.1) — replaying a read reveals what the
 * relay already served, and a replayed write still faces the
 * `(group_id, epoch)` uniqueness constraint and the freshness gate. A
 * transport that wants anti-replay should bind to its channel (TLS
 * exporter, request nonce) rather than change this.
 */
export function relayRequestBytes(groupId: string, op: RelayOp, epoch: number): Uint8Array {
  return canonicalBytes({ epoch, group_id: groupId, op });
}

/**
 * Sign a relay request under the epoch's derived key.
 */
export async function signRelayRequest(
  crypto: CryptoProvider,
  groupSecret: Uint8Array,
  requestBytes: Uint8Array,
): Promise<Uint8Array> {
  const pair = await deriveRelayAuthKeyPair(crypto, groupSecret);
  try {
    return await crypto.ed25519Sign(pair.privateKey, requestBytes);
  } finally {
    wipe(pair.privateKey);
  }
}

/**
 * Verify a relay request against a published `auth_pubkey`.
 *
 * Returns a boolean rather than throwing: a failed verification is an
 * ordinary "not authorized" answer for a relay to give, not an
 * exceptional condition.
 */
export async function verifyRelayRequest(
  crypto: CryptoProvider,
  authPublicKey: Uint8Array,
  requestBytes: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  return crypto.ed25519Verify(authPublicKey, requestBytes, signature);
}

/**
 * Build the {@link RelayRequestAuth} a client attaches to one request.
 */
export async function authorizeRelayRequest(
  crypto: CryptoProvider,
  groupId: string,
  op: RelayOp,
  epoch: number,
  groupSecret: Uint8Array,
): Promise<RelayRequestAuth> {
  const signature = await signRelayRequest(
    crypto,
    groupSecret,
    relayRequestBytes(groupId, op, epoch),
  );
  return { epoch, signature: bytesToBase64Url(signature) };
}
