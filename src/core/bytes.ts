/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Byte-level helpers shared across the protocol core.
 *
 * Binary values cross the wire and the codec as base64url strings
 * without padding. Implemented dependency-free:
 * `core/` imports no platform APIs beyond the universal TextEncoder.
 */

import { EncodingError } from "./errors";

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64URL_LOOKUP: Record<string, number> = {};
for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
  BASE64URL_LOOKUP[BASE64URL_ALPHABET.charAt(i)] = i;
}

const textEncoder = new TextEncoder();
// `fatal` so invalid UTF-8 raises instead of silently yielding U+FFFD:
// the sealed transition body is relay-supplied bytes, and a decoder
// that repairs them changes what gets parsed (spec §6.5).
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Bytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/** Decode UTF-8, rejecting malformed sequences (see above). */
export function utf8String(bytes: Uint8Array): string {
  try {
    return textDecoder.decode(bytes);
  } catch {
    throw new EncodingError("invalid UTF-8");
  }
}

/**
 * Overwrite a buffer that held key material.
 *
 * Best-effort by nature: JavaScript cannot reach copies the engine
 * may have made, `crypto.subtle` keeps its own copy of any imported
 * key, and strings are immutable so a credential cannot be wiped at
 * all. What this does buy is shrinking the window in which a heap
 * snapshot or crash dump contains a live key, which is worth having
 * even though it is not a guarantee — the client-compromise
 * exclusions in spec §13 still apply.
 *
 * Only ever call this on buffers the caller owns and is finished
 * with; never on a value being returned.
 */
export function wipe(...buffers: (Uint8Array | undefined)[]): void {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += BASE64URL_ALPHABET.charAt(b0 >> 2);
    out += BASE64URL_ALPHABET.charAt(((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    if (b1 === undefined) break;
    out += BASE64URL_ALPHABET.charAt(((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    if (b2 === undefined) break;
    out += BASE64URL_ALPHABET.charAt(b2 & 0x3f);
  }
  return out;
}

export function base64UrlToBytes(text: string): Uint8Array {
  const rem = text.length % 4;
  if (rem === 1) {
    throw new EncodingError("invalid base64url length");
  }
  const byteLength = Math.floor((text.length * 3) / 4);
  const out = new Uint8Array(byteLength);
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const value = BASE64URL_LOOKUP[char];
    if (value === undefined) {
      throw new EncodingError(`invalid base64url character: ${JSON.stringify(char)}`);
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex++] = (buffer >> bits) & 0xff;
    }
  }
  // Trailing bits must be zero padding, never dropped payload.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new EncodingError("invalid base64url trailing bits");
  }
  return out;
}
