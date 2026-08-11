/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Length-prefixed padding (spec §6.5) and the record size buckets.
 *
 * The input space here is wide — any plaintext length against any
 * padded size — so most of this is property-based (the testing
 * bar). The hand-written cases cover the rejection paths, which matter
 * more than the round-trip: `unpad` runs on attacker-influenced input,
 * and the two ways to get it wrong (trusting the declared length,
 * ignoring the padding region) are both silent.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { EncodingError } from "../src/core/errors";
import {
  LENGTH_PREFIX_BYTES,
  MAX_RECORD_BUCKET,
  pad,
  RECORD_BUCKETS,
  recordBucket,
  unpad,
} from "../src/core/padding";
import { CAPACITY_PROFILES } from "../src/core/profiles";

const SIZE = 512;

describe("pad / unpad (spec §6.5)", () => {
  it("round-trips any payload that fits", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: SIZE - LENGTH_PREFIX_BYTES }), (plain) => {
        expect(unpad(pad(plain, SIZE), SIZE)).toEqual(plain);
      }),
    );
  });

  it("always produces exactly the requested size, whatever the payload", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: SIZE - LENGTH_PREFIX_BYTES }), (plain) => {
        expect(pad(plain, SIZE).length).toBe(SIZE);
      }),
    );
  });

  it("round-trips at both real profile sizes", () => {
    for (const profile of Object.values(CAPACITY_PROFILES)) {
      const plain = new Uint8Array(profile.sealedBodySize - LENGTH_PREFIX_BYTES).fill(7);
      expect(unpad(pad(plain, profile.sealedBodySize), profile.sealedBodySize)).toEqual(plain);
    }
  });

  it("handles the boundary payloads: empty and exactly full", () => {
    expect(unpad(pad(new Uint8Array(0), SIZE), SIZE)).toEqual(new Uint8Array(0));

    const full = new Uint8Array(SIZE - LENGTH_PREFIX_BYTES).fill(0xab);
    expect(unpad(pad(full, SIZE), SIZE)).toEqual(full);
  });

  it("zeroes the padding region rather than leaking prior contents", () => {
    const padded = pad(new Uint8Array([1, 2, 3]), SIZE);
    expect(padded.slice(LENGTH_PREFIX_BYTES + 3).every((b) => b === 0)).toBe(true);
  });

  it("refuses a payload one byte too large for its size", () => {
    const tooBig = new Uint8Array(SIZE - LENGTH_PREFIX_BYTES + 1);
    expect(() => pad(tooBig, SIZE)).toThrow(EncodingError);
  });

  it("rejects a declared length beyond the buffer — no out-of-bounds read", () => {
    const padded = pad(new Uint8Array([1, 2, 3]), SIZE);
    padded[0] = 0xff; // declare ~4 GiB
    expect(() => unpad(padded, SIZE)).toThrow(EncodingError);
  });

  it("rejects a declared length one byte past capacity", () => {
    const padded = pad(new Uint8Array(0), SIZE);
    // capacity is SIZE - 4; declare one more
    const over = SIZE - LENGTH_PREFIX_BYTES + 1;
    padded[2] = (over >>> 8) & 0xff;
    padded[3] = over & 0xff;
    expect(() => unpad(padded, SIZE)).toThrow(EncodingError);
  });

  // spec §6.5: the padding region is space an attacker controls. A
  // decoder that ignores it hands a malicious relay a covert channel to
  // members, and nothing else in the system would ever notice.
  it("rejects a non-zero padding byte anywhere in the region", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: SIZE - LENGTH_PREFIX_BYTES - 8 - 1 }), (offset) => {
        const padded = pad(new Uint8Array(8), SIZE);
        padded[LENGTH_PREFIX_BYTES + 8 + offset] = 0x01;
        expect(() => unpad(padded, SIZE)).toThrow(EncodingError);
      }),
    );
  });

  it("rejects a buffer that is not exactly the expected size", () => {
    const padded = pad(new Uint8Array([1]), SIZE);
    expect(() => unpad(padded.slice(0, SIZE - 1), SIZE)).toThrow(EncodingError);
    expect(() => unpad(new Uint8Array(SIZE + 1), SIZE)).toThrow(EncodingError);
  });

  it("rejects a nonsensical size", () => {
    expect(() => pad(new Uint8Array(0), 4)).toThrow(EncodingError);
    expect(() => pad(new Uint8Array(0), 1.5)).toThrow(EncodingError);
  });
});

describe("record size buckets (spec §6.5)", () => {
  it("always returns a bucket that fits the payload and its prefix", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 20 * 1024 * 1024 }), (length) => {
        expect(recordBucket(length)).toBeGreaterThanOrEqual(length + LENGTH_PREFIX_BYTES);
      }),
    );
  });

  it("is non-decreasing in payload length", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 8 * 1024 * 1024 }),
        fc.integer({ min: 0, max: 8 * 1024 * 1024 }),
        (a, b) => {
          const [small, large] = a <= b ? [a, b] : [b, a];
          expect(recordBucket(small)).toBeLessThanOrEqual(recordBucket(large));
        },
      ),
    );
  });

  it("collapses a wide range of sizes onto few distinct values", () => {
    // The whole point: many payload lengths must be indistinguishable.
    const observed = new Set<number>();
    for (let length = 0; length <= 4 * 1024 * 1024; length += 997) {
      observed.add(recordBucket(length));
    }
    expect(observed.size).toBeLessThanOrEqual(RECORD_BUCKETS.length);
  });

  it("picks the exact bucket at each boundary", () => {
    for (const bucket of RECORD_BUCKETS) {
      expect(recordBucket(bucket - LENGTH_PREFIX_BYTES)).toBe(bucket);
      const next = RECORD_BUCKETS.find((b) => b > bucket);
      if (next !== undefined) {
        expect(recordBucket(bucket - LENGTH_PREFIX_BYTES + 1)).toBe(next);
      }
    }
  });

  it("keeps MAX_RECORD_BUCKET in step with the ladder", () => {
    // The constant is written literally rather than derived, so this is
    // the only thing stopping the two drifting apart.
    expect(RECORD_BUCKETS[RECORD_BUCKETS.length - 1]).toBe(MAX_RECORD_BUCKET);
    expect(RECORD_BUCKETS.every((b, i) => i === 0 || b > (RECORD_BUCKETS[i - 1] ?? 0))).toBe(true);
  });

  it("rounds to multiples of the largest bucket above its range", () => {
    const max = MAX_RECORD_BUCKET;
    expect(recordBucket(max)).toBe(2 * max);
    expect(recordBucket(2 * max - LENGTH_PREFIX_BYTES)).toBe(2 * max);
    expect(recordBucket(2 * max)).toBe(3 * max);
  });

  it("pads a real payload into its bucket and back", () => {
    const plain = new Uint8Array(5000).fill(9);
    const bucket = recordBucket(plain.length);
    expect(bucket).toBe(16 * 1024);
    expect(unpad(pad(plain, bucket), bucket)).toEqual(plain);
  });
});
