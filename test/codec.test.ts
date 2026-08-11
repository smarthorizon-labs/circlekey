/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { bytesToBase64Url, utf8Bytes } from "../src/core/bytes";
import {
  canonicalBytes,
  canonicalize,
  genesisMarker,
  hashTransition,
  transitionSigningBytes,
} from "../src/core/codec";
import { EncodingError } from "../src/core/errors";
import type { EpochTransition } from "../src/core/types";

const decoder = new TextDecoder();
const provider = new WebCryptoProvider();
const sha256 = (data: Uint8Array) => provider.sha256(data);

describe("canonicalize (RFC 8785 profile)", () => {
  it("sorts object keys by UTF-16 code units", () => {
    expect(canonicalize({ b: 2, a: 1, A: 0, Z: -3 })).toBe('{"A":0,"Z":-3,"a":1,"b":2}');
  });

  it("sorts numeric-looking keys as strings", () => {
    expect(canonicalize({ "10": "ten", "2": "two", "1": "one" })).toBe(
      '{"1":"one","10":"ten","2":"two"}',
    );
  });

  it("recurses into nested structures without whitespace", () => {
    expect(canonicalize({ z: [{ y: true, x: null }], a: { b: [1, 2, 3] } })).toBe(
      '{"a":{"b":[1,2,3]},"z":[{"x":null,"y":true}]}',
    );
  });

  it("serializes empty structures and primitives", () => {
    expect(canonicalize({ arr: [], obj: {} })).toBe('{"arr":[],"obj":{}}');
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize("")).toBe('""');
  });

  it("escapes strings per ES JSON.stringify rules", () => {
    expect(canonicalize("")).toBe('"\\u0007"');
    expect(canonicalize('a"b\\c\n')).toBe('"a\\"b\\\\c\\n"');
    // Non-ASCII stays literal (UTF-8 encoded at the byte layer).
    expect(canonicalize("héllo ✓")).toBe('"héllo ✓"');
  });

  it("serializes -0 as 0 and accepts the safe-integer bounds", () => {
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalize(Number.MIN_SAFE_INTEGER)).toBe("-9007199254740991");
  });

  it("accepts objects with a null prototype", () => {
    const nullProto: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    nullProto.a = 1;
    expect(canonicalize(nullProto)).toBe('{"a":1}');
  });

  it("rejects non-integer and unsafe numbers", () => {
    expect(() => canonicalize(1.5)).toThrow(EncodingError);
    expect(() => canonicalize(Number.NaN)).toThrow(EncodingError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(EncodingError);
    expect(() => canonicalize(2 ** 53)).toThrow(EncodingError);
  });

  it("rejects non-JSON values", () => {
    expect(() => canonicalize(undefined)).toThrow(EncodingError);
    expect(() => canonicalize(10n)).toThrow(EncodingError);
    expect(() => canonicalize(() => 0)).toThrow(EncodingError);
  });

  it("rejects class instances instead of silently serializing them", () => {
    expect(() => canonicalize(new Date(0))).toThrow(EncodingError);
    expect(() => canonicalize(new Map())).toThrow(EncodingError);
  });

  it("rejects undefined property values instead of skipping them", () => {
    expect(() => canonicalize({ a: undefined })).toThrow(EncodingError);
  });

  it("canonicalizes a literal \"__proto__\" key rather than dropping it", () => {
    // JSON.parse creates "__proto__" as a real own property, so hostile
    // backend JSON can carry one. It must be serialized like any other
    // key — silently dropping it would mean two parties hash and sign
    // different documents.
    const parsed: unknown = JSON.parse('{"b":1,"__proto__":2}');
    expect(canonicalize(parsed)).toBe('{"__proto__":2,"b":1}');
    // It must remain a plain object, never mutate the prototype chain.
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
  });
});

// Integer-only JSON arbitrary matching the protocol's canonical profile.
const { json: jsonArb } = fc.letrec((tie) => ({
  json: fc.oneof(
    { depthSize: "small" },
    fc.constant(null),
    fc.boolean(),
    fc.integer(),
    fc.constantFrom(Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0),
    fc.string(),
    fc.array(tie("json"), { maxLength: 5 }),
    fc.dictionary(fc.string(), tie("json"), { maxKeys: 5 }),
  ),
}));

function reorderKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reorderKeys);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).reverse()) {
      // `out[key] = …` would not create an own property for the key
      // "__proto__" — it would hit the prototype setter and the key
      // would vanish, making this helper (not the codec) lose data.
      // JSON.parse produces "__proto__" as a genuine own property, so
      // the codec must handle it and this helper must preserve it.
      Object.defineProperty(out, key, {
        value: reorderKeys(record[key]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return value;
}

describe("canonicalize properties", () => {
  it("is stable: canonicalize(parse(canonicalize(v))) === canonicalize(v)", () => {
    fc.assert(
      fc.property(jsonArb, (value) => {
        const once = canonicalize(value);
        expect(canonicalize(JSON.parse(once))).toBe(once);
      }),
    );
  });

  it("is independent of object key insertion order", () => {
    fc.assert(
      fc.property(jsonArb, (value) => {
        expect(canonicalize(reorderKeys(value))).toBe(canonicalize(value));
      }),
    );
  });

  it("round-trips through JSON.parse to a deeply equal value", () => {
    fc.assert(
      fc.property(jsonArb, (value) => {
        expect(JSON.parse(canonicalize(value))).toEqual(value);
      }),
    );
  });
});

const sampleTransition: EpochTransition = {
  group_id: "g-1",
  epoch: 0,
  prev_transition_hash: "marker",
  action: "create",
  members: [{ user_id: "alice", device_pubkeys: ["pkA"], is_manager: true }],
  envelope_slots: [0],
  policy: { min_managers: 1 },
  signed_by: "idA",
  signature: "sigA",
};

describe("transition signing bytes and hashing", () => {
  it("omits `signature` but keeps `signed_by` in the signing bytes", () => {
    const text = decoder.decode(transitionSigningBytes(sampleTransition));
    expect(text).toContain('"signed_by":"idA"');
    expect(text).not.toContain("signature");
    expect(text).toContain('"action":"create"');
  });

  it("produces identical signing bytes regardless of signature value", () => {
    const reSigned = { ...sampleTransition, signature: "completely-different" };
    expect(decoder.decode(transitionSigningBytes(reSigned))).toBe(
      decoder.decode(transitionSigningBytes(sampleTransition)),
    );
  });

  it("includes the signature in the chain hash — a signature swap is a fork", async () => {
    const reSigned = { ...sampleTransition, signature: "completely-different" };
    const originalHash = await hashTransition(sha256, sampleTransition);
    expect(await hashTransition(sha256, reSigned)).not.toBe(originalHash);
  });

  it("computes the genesis marker as base64url(SHA-256(utf8(group_id)))", async () => {
    const expected = bytesToBase64Url(await sha256(utf8Bytes("g-1")));
    expect(await genesisMarker(sha256, "g-1")).toBe(expected);
    expect(expected).toHaveLength(43); // 32 bytes, base64url, no padding
  });

  it("hashes the canonical bytes of the complete transition", async () => {
    const expected = bytesToBase64Url(await sha256(canonicalBytes(sampleTransition)));
    expect(await hashTransition(sha256, sampleTransition)).toBe(expected);
  });
});
