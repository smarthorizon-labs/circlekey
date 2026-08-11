/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Opaque identifiers that reach the relay (spec §6.5, §5.8 rule 2):
 * blinded backup handles, and group identifiers.
 *
 * The relay never receives a user identity. Backup blobs are addressed
 * by a handle derived from the recovery credential and the relay's own
 * identifier:
 *
 *   handle = base64url(HKDF(UTF-8(recovery_credential),
 *                           info = "groupvault/relay-handle/v1" || relay_id,
 *                           L = 16))
 *
 * Two properties matter, and they pull in opposite directions:
 *
 * - **Stable** for one user at one relay, across all their groups and
 *   sessions — otherwise they could not find their own backup blob.
 * - **Unlinkable** across relays. Binding `relay_id` into the info means
 *   two relays that compare notes see unrelated handles, so operating
 *   several of them buys no correlation.
 *
 * It is keyed on the **credential**, not the device identity key, for a
 * blunt reason: the one moment a device must find its blob is the
 * moment it has nothing else. A restoring device holds the credential
 * and nothing more — the identity key it would otherwise derive from is
 * *inside* the blob it is trying to fetch. Keying on a `group_secret`
 * fails for a different reason: it would rotate every epoch and differ
 * per group.
 *
 * A handle is an identifier, not a secret — it becomes visible to the
 * relay by design. What it must never be is *reversible* or
 * *guessable*, which is why it derives from key material rather than
 * from a hash of a user id (spec §5.8 rule 2: a hashed low-entropy
 * identifier is brute-forced instantly).
 */

import { bytesToBase64Url, utf8Bytes, wipe } from "./bytes";
import { CryptoError } from "./errors";
import { deriveBytes, KDF_LABELS, type HkdfSha256Fn } from "./kdf";

/** 128 bits, base64url-encoded to 22 characters (spec §6.5). */
export const HANDLE_LENGTH = 16;

/** Same width as a handle: 128 bits of CSPRNG output (spec §6.5). */
export const GROUP_ID_LENGTH = 16;

/**
 * A fresh group identifier (spec §6.5).
 *
 * `group_id` is plaintext on every request — it is how the relay routes
 * — so §5.8 rule 2 requires it to carry no application semantics, and
 * §12 forbids a client from accepting one supplied by the application.
 * A caller who could name a group would name it `acme-acquisition`, and
 * the most-repeated field in the protocol would leak the thing the rest
 * of the metadata-minimization design exists to hide.
 *
 * Unlike `record_id` this is generated, not derived. It has nothing to
 * derive *from*: the identifier must exist before the genesis
 * transition that establishes the group's first secret. Applications
 * keep their own label→id mapping locally, exactly as they would for
 * any opaque primary key.
 */
export function newGroupId(randomBytes: (length: number) => Uint8Array): string {
  const bytes = randomBytes(GROUP_ID_LENGTH);
  if (bytes.length !== GROUP_ID_LENGTH) {
    throw new CryptoError(
      `group id needs ${String(GROUP_ID_LENGTH)} random bytes, got ${String(bytes.length)}`,
    );
  }
  try {
    return bytesToBase64Url(bytes);
  } finally {
    wipe(bytes);
  }
}

export async function deriveRelayHandle(
  hkdf: HkdfSha256Fn,
  recoveryCredential: string,
  relayId: string,
): Promise<string> {
  if (recoveryCredential.length === 0) {
    throw new CryptoError("recovery credential is required to derive a relay handle");
  }
  if (relayId.length === 0) {
    throw new CryptoError(
      "relay id is required — an empty id would make handles linkable across relays",
    );
  }
  const derived = await deriveBytes(
    hkdf,
    utf8Bytes(recoveryCredential),
    KDF_LABELS.relayHandle,
    HANDLE_LENGTH,
    utf8Bytes(relayId),
  );
  try {
    return bytesToBase64Url(derived);
  } finally {
    wipe(derived);
  }
}
