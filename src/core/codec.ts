/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Canonical encoding and hashing.
 *
 * Everything that is signed or hash-chained goes through this module
 * and nothing else. The rules — frozen by `test/vectors/`, so any
 * behavioral change here is a suite-version bump, never an edit:
 *
 * - Encoding: RFC 8785 (JCS) over protocol JSON. UTF-8, keys sorted
 *   by UTF-16 code units, no whitespace, integers only. Binary values
 *   are base64url strings *before* canonicalization.
 * - Signature input: canonical form with `signature` omitted.
 * - Transition hash: SHA-256 over the canonical form of the complete
 *   transition, `signature` included — a signature swap is a fork.
 * - Genesis marker: SHA-256 of the UTF-8 bytes of `group_id`
 *   (spec §9.1, genesis check 2).
 *
 * Hashes are returned as base64url strings. SHA-256 itself enters via
 * a function parameter — `core/` imports no crypto.
 */

import { bytesToBase64Url, utf8Bytes } from "./bytes";
import { EncodingError } from "./errors";
import type { EpochTransition } from "./types";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type Sha256Fn = (data: Uint8Array) => Promise<Uint8Array>;

/**
 * RFC 8785 canonical JSON text of `value`.
 *
 * Stricter than RFC 8785 where the protocol allows it: numbers must
 * be safe integers (the protocol has no floats), objects must be
 * plain (no class instances silently serializing to `{}`), and
 * `undefined` property values are rejected rather than skipped —
 * omission must be explicit.
 */
export function canonicalize(value: unknown): string {
  const out: string[] = [];
  writeCanonical(value, out);
  return out.join("");
}

/** UTF-8 bytes of {@link canonicalize}. */
export function canonicalBytes(value: unknown): Uint8Array {
  return utf8Bytes(canonicalize(value));
}

/** An `EpochTransition` before its signature is attached. */
export type UnsignedEpochTransition = Omit<EpochTransition, "signature">;

/**
 * The exact bytes a manager signs and every client verifies:
 * canonical form of the transition with `signature` omitted
 * (`signed_by` stays in).
 */
export function transitionSigningBytes(
  transition: EpochTransition | UnsignedEpochTransition,
): Uint8Array {
  const unsigned: Record<string, unknown> = { ...transition };
  delete unsigned.signature;
  return canonicalBytes(unsigned);
}

/**
 * Chain hash of a complete transition, `signature` included, as a
 * base64url string — the value the next transition must reference in
 * `prev_transition_hash` (spec §5.4, §9.1 check 2).
 */
export async function hashTransition(
  sha256: Sha256Fn,
  transition: EpochTransition,
): Promise<string> {
  return bytesToBase64Url(await sha256(canonicalBytes(transition)));
}

/**
 * Deterministic `prev_transition_hash` for epoch 0:
 * base64url(SHA-256(UTF-8(group_id))). spec §9.1, genesis check 2.
 */
export async function genesisMarker(sha256: Sha256Fn, groupId: string): Promise<string> {
  return bytesToBase64Url(await sha256(utf8Bytes(groupId)));
}

function writeCanonical(value: unknown, out: string[]): void {
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "string":
      // JSON.stringify implements the ES string serialization RFC 8785
      // mandates (incl. control-character and lone-surrogate escapes).
      out.push(JSON.stringify(value));
      return;
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new EncodingError(
          `only safe integers are canonicalizable, got: ${String(value)}`,
        );
      }
      out.push(JSON.stringify(value)); // note: -0 serializes as "0"
      return;
    case "object":
      break;
    default:
      throw new EncodingError(`unsupported value type: ${typeof value}`);
  }
  if (Array.isArray(value)) {
    out.push("[");
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out.push(",");
      writeCanonical(value[i], out);
    }
    out.push("]");
    return;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new EncodingError("only plain objects are canonicalizable");
  }
  const record = value as Record<string, unknown>;
  // Default string sort compares UTF-16 code units — exactly the key
  // ordering RFC 8785 requires.
  const keys = Object.keys(record).sort();
  out.push("{");
  let first = true;
  for (const key of keys) {
    const propertyValue = record[key];
    if (propertyValue === undefined) {
      throw new EncodingError(
        `undefined property value for key ${JSON.stringify(key)} — omit the key instead`,
      );
    }
    if (!first) out.push(",");
    first = false;
    out.push(JSON.stringify(key), ":");
    writeCanonical(propertyValue, out);
  }
  out.push("}");
}
