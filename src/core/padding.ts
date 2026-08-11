/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Length-prefixed zero padding (spec §6.5).
 *
 *   padded = uint32_BE(len(plain)) || plain || zeros(size - 4 - len)
 *
 * Used for two things: sealed transition bodies, padded to their
 * capacity profile's fixed size, and record plaintexts, padded to a
 * geometric size bucket. In both cases the point is that ciphertext
 * length reveals a bucket rather than a byte count (spec §5.8 rule 3).
 *
 * `unpad` is a security boundary, not a formatting convenience. It runs
 * on attacker-influenced input and spec §6.5 requires it to verify the
 * padding rather than assume it: a decoder that trusts the declared
 * length reads out of bounds, and one that ignores the trailing bytes
 * gives a malicious relay a covert channel to members — the padding
 * region is space an attacker controls and nobody checks.
 */

import { EncodingError } from "./errors";

export const LENGTH_PREFIX_BYTES = 4;

/**
 * Record size buckets in bytes (spec §6.5). Geometric, so overhead is
 * bounded: worst case just under 4x for a payload that has only
 * overflowed a bucket, under 1% for large records. Above the largest
 * bucket, sizes round up to the next multiple of it.
 */
export const RECORD_BUCKETS: readonly number[] = [
  4 * 1024,
  16 * 1024,
  64 * 1024,
  256 * 1024,
  1024 * 1024,
  4 * 1024 * 1024,
];

/** The largest named bucket; sizes above it round to multiples of it. */
export const MAX_RECORD_BUCKET = 4 * 1024 * 1024;

/** Smallest bucket that fits `plainLength` plus its length prefix. */
export function recordBucket(plainLength: number): number {
  requireLength(plainLength);
  const needed = plainLength + LENGTH_PREFIX_BYTES;
  for (const bucket of RECORD_BUCKETS) {
    if (needed <= bucket) return bucket;
  }
  return Math.ceil(needed / MAX_RECORD_BUCKET) * MAX_RECORD_BUCKET;
}

/** Pad `plain` to exactly `size` bytes. */
export function pad(plain: Uint8Array, size: number): Uint8Array {
  requireSize(size);
  if (plain.length + LENGTH_PREFIX_BYTES > size) {
    throw new EncodingError(
      `cannot pad ${String(plain.length)} bytes into ${String(size)} (needs ${String(
        plain.length + LENGTH_PREFIX_BYTES,
      )})`,
    );
  }
  const out = new Uint8Array(size);
  writeUint32BE(out, 0, plain.length);
  out.set(plain, LENGTH_PREFIX_BYTES);
  return out;
}

/**
 * Recover the plaintext from a padded buffer, verifying every claim it
 * makes about itself.
 */
export function unpad(padded: Uint8Array, size: number): Uint8Array {
  requireSize(size);
  if (padded.length !== size) {
    throw new EncodingError(
      `padded buffer is ${String(padded.length)} bytes, expected exactly ${String(size)}`,
    );
  }
  const declared = readUint32BE(padded, 0);
  if (declared > size - LENGTH_PREFIX_BYTES) {
    throw new EncodingError(
      `declared length ${String(declared)} exceeds capacity ${String(
        size - LENGTH_PREFIX_BYTES,
      )}`,
    );
  }
  // spec §6.5: the padding region MUST be zero. Checking it closes the
  // covert channel; skipping it is invisible until someone uses it.
  for (let i = LENGTH_PREFIX_BYTES + declared; i < size; i++) {
    if (padded[i] !== 0) {
      throw new EncodingError(`non-zero padding byte at offset ${String(i)}`);
    }
  }
  return padded.slice(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + declared);
}

function requireSize(size: number): void {
  if (!Number.isSafeInteger(size) || size <= LENGTH_PREFIX_BYTES) {
    throw new EncodingError(`padding size must be an integer > ${String(LENGTH_PREFIX_BYTES)}`);
  }
}

function requireLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0xffffffff) {
    throw new EncodingError("padded length must fit an unsigned 32-bit integer");
  }
}

function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  requireLength(value);
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

// `?? 0` matches the idiom in core/bytes.ts. Callers bounds-check
// before reaching here, so the fallback is unreachable rather than
// load-bearing.
function readUint32BE(source: Uint8Array, offset: number): number {
  return (
    (source[offset] ?? 0) * 0x1000000 +
    ((source[offset + 1] ?? 0) << 16) +
    ((source[offset + 2] ?? 0) << 8) +
    (source[offset + 3] ?? 0)
  );
}
