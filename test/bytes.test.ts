/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * base64url is the encoding every binary protocol field travels in
 * (spec §6.5), so a defect here corrupts signatures, chain hashes,
 * envelopes and records at once. The decoder's rejection rules are
 * normative MUSTs, not defensive programming.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  utf8Bytes,
} from "../src/core/bytes";
import { EncodingError } from "../src/core/errors";
import { bytesToHex, hexToBytes } from "./helpers";

const BASE64URL = /^[A-Za-z0-9_-]*$/;

describe("base64url encoding (spec §6.5)", () => {
  it("matches RFC 4648 §5 test vectors, unpadded", () => {
    // The classic "f", "fo", "fooba"… ladder, which exercises every
    // remainder case (0, 1 and 2 bytes over a 3-byte group).
    const cases: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [plain, encoded] of cases) {
      expect(bytesToBase64Url(utf8Bytes(plain))).toBe(encoded);
      expect(base64UrlToBytes(encoded)).toEqual(utf8Bytes(plain));
    }
  });

  it("uses the URL-safe alphabet, never + / or padding", () => {
    // 0xFB 0xFF encodes to "+/" under standard base64.
    const tricky = hexToBytes("fbff00fbff");
    const encoded = bytesToBase64Url(tricky);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    expect(encoded).toMatch(BASE64URL);
    expect(bytesToHex(base64UrlToBytes(encoded))).toBe(bytesToHex(tricky));
  });

  it("encodes the 32- and 64-byte protocol sizes to the documented lengths", () => {
    // spec §6.5 quotes these: hashes/keys are 43 chars, signatures 86.
    expect(bytesToBase64Url(new Uint8Array(32))).toHaveLength(43);
    expect(bytesToBase64Url(new Uint8Array(64))).toHaveLength(86);
  });
});

describe("base64url properties", () => {
  it("round-trips arbitrary byte strings", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        expect(base64UrlToBytes(bytesToBase64Url(bytes))).toEqual(bytes);
      }),
    );
  });

  it("only ever emits alphabet characters, and never pads", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        const encoded = bytesToBase64Url(bytes);
        expect(encoded).toMatch(BASE64URL);
        expect(encoded.length).toBe(Math.ceil((bytes.length * 8) / 6));
      }),
    );
  });

  it("is deterministic", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 128 }), (bytes) => {
        expect(bytesToBase64Url(bytes)).toBe(bytesToBase64Url(bytes));
      }),
    );
  });
});

describe("base64url decoder rejections (spec §6.5 MUSTs)", () => {
  it("rejects characters outside the alphabet", () => {
    for (const bad of ["Zm9v+g", "Zm9v/g", "Zm9vYg==", "Zm 9v", "Zm9v!", "café"]) {
      expect(() => base64UrlToBytes(bad)).toThrow(EncodingError);
    }
  });

  it("rejects an impossible length (one leftover character)", () => {
    // A single trailing character cannot encode any whole byte.
    expect(() => base64UrlToBytes("A")).toThrow(EncodingError);
    expect(() => base64UrlToBytes("Zm9vA")).toThrow(EncodingError);
  });

  it("rejects non-zero trailing bits", () => {
    // "AA" decodes to 0x00 with four spare bits that MUST be zero;
    // "AB" sets one of them, so it is a second spelling of the same
    // byte — accepting it would make encodings non-canonical.
    expect(base64UrlToBytes("AA")).toEqual(new Uint8Array([0]));
    // 2 chars → 1 byte + 4 spare bits; 3 chars → 2 bytes + 2 spare.
    for (const bad of ["AB", "AC", "AP", "AAB"]) {
      expect(() => base64UrlToBytes(bad)).toThrow(EncodingError);
    }
    // A full 4-character group has no spare bits, so every combination
    // is canonical — including the all-ones one.
    expect(base64UrlToBytes("____")).toEqual(hexToBytes("ffffff"));
  });

  it("accepts every canonical encoding a round-trip can produce", () => {
    // The mirror of the rule above: nothing the encoder emits may be
    // rejected by the decoder's strictness.
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (bytes) => {
        expect(() => base64UrlToBytes(bytesToBase64Url(bytes))).not.toThrow();
      }),
    );
  });
});

describe("byte helpers", () => {
  it("concatenates in order, copying its inputs", () => {
    const a = hexToBytes("0102");
    const b = hexToBytes("0304");
    const joined = concatBytes(a, b, new Uint8Array(0));
    expect(bytesToHex(joined)).toBe("01020304");
    joined[0] = 0xff;
    expect(bytesToHex(a)).toBe("0102"); // inputs untouched
  });

  it("concatenation is associative and length-preserving", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 40 }),
        fc.uint8Array({ maxLength: 40 }),
        fc.uint8Array({ maxLength: 40 }),
        (a, b, c) => {
          const left = concatBytes(concatBytes(a, b), c);
          const right = concatBytes(a, concatBytes(b, c));
          expect(bytesToHex(left)).toBe(bytesToHex(right));
          expect(left.length).toBe(a.length + b.length + c.length);
        },
      ),
    );
  });

  it("encodes UTF-8, including astral characters", () => {
    expect(bytesToHex(utf8Bytes("é"))).toBe("c3a9");
    expect(bytesToHex(utf8Bytes("😀"))).toBe("f09f9880");
    expect(utf8Bytes("")).toHaveLength(0);
  });
});
