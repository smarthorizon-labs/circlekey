/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Capacity profiles (spec §6.5, §8.1).
 *
 * These are constants, so the tests that matter are the ones that stop
 * them drifting: the padded sizes are wire format, and changing one
 * silently would make two implementations disagree about every
 * transition without either being obviously wrong.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { placeEnvelopes } from "../src/core/envelopes";
import { EnvelopeError, MalformedTransitionError } from "../src/core/errors";
import { LENGTH_PREFIX_BYTES } from "../src/core/padding";
import {
  CAPACITY_PROFILES,
  DEFAULT_CAPACITY,
  isCapacityName,
  profileFor,
  profileForPolicy,
} from "../src/core/profiles";

const crypto = new WebCryptoProvider();

describe("capacity profiles (spec §6.5)", () => {
  it("freezes the wire-format sizes — changing one is a protocol break", () => {
    expect(CAPACITY_PROFILES).toEqual({
      lite: {
        maxMembers: 15,
        envelopeSlots: 45,
        sealedBodySize: 8192,
        removalNoticeSize: 2048,
      },
      x: {
        maxMembers: 30,
        envelopeSlots: 90,
        sealedBodySize: 16384,
        removalNoticeSize: 4096,
      },
    });
  });

  it("caps `lite` at the spec §5.5 small-group assumption", () => {
    expect(CAPACITY_PROFILES.lite.maxMembers).toBe(15);
  });

  it("gives every member room for several devices", () => {
    // Envelope slots bound devices, not members (spec §6.5).
    for (const profile of Object.values(CAPACITY_PROFILES)) {
      expect(profile.envelopeSlots).toBeGreaterThanOrEqual(profile.maxMembers * 3);
    }
  });

  it("leaves the sealed body room for a full member set", () => {
    // A generous per-member upper bound: a user id, three 43-char
    // device keys, and JSON overhead.
    const perMember = 250;
    for (const profile of Object.values(CAPACITY_PROFILES)) {
      const needed = profile.maxMembers * perMember + LENGTH_PREFIX_BYTES + 512;
      expect(profile.sealedBodySize).toBeGreaterThan(needed);
    }
  });

  it("resolves by name", () => {
    expect(profileFor("lite")).toBe(CAPACITY_PROFILES.lite);
    expect(profileFor("x")).toBe(CAPACITY_PROFILES.x);
  });

  it("defaults to lite when a policy predates the field", () => {
    expect(profileFor(undefined)).toBe(CAPACITY_PROFILES[DEFAULT_CAPACITY]);
    expect(profileForPolicy({ min_managers: 1 })).toBe(CAPACITY_PROFILES.lite);
  });

  it("reads the capacity off a policy that declares one", () => {
    expect(profileForPolicy({ min_managers: 2, capacity: "x" })).toBe(CAPACITY_PROFILES.x);
  });

  // Guessing a profile would produce padded sizes that fail to verify
  // for reasons no error message would explain.
  it("rejects an unknown capacity rather than falling back", () => {
    expect(() => profileFor("xl" as never)).toThrow(MalformedTransitionError);
    expect(() => profileForPolicy({ min_managers: 1, capacity: "huge" as never })).toThrow(
      MalformedTransitionError,
    );
  });

  it("recognizes exactly the two defined names", () => {
    expect(isCapacityName("lite")).toBe(true);
    expect(isCapacityName("x")).toBe(true);
    for (const bad of ["", "LITE", "X", "large", null, undefined, 1]) {
      expect(isCapacityName(bad)).toBe(false);
    }
  });
});

/**
 * Spec §5.5 says an implementation SHOULD NOT be used for groups larger
 * than a few dozen members — the rekey and full-history costs stop being
 * negligible well before that. It names no number, and neither does this
 * suite: what satisfies the SHOULD is that a group is bounded *by
 * construction* rather than by advice a deployment can ignore.
 *
 * The bound is the profile's envelope slot count. A group that outgrows
 * it cannot produce a transition at all — building one fails loudly
 * instead of silently degrading, which is the behaviour that makes the
 * SHOULD structural.
 */
describe("a group cannot outgrow its capacity profile (spec §5.5, §6.5)", () => {
  const envelope = (n: number) => `envelope-${String(n)}`;

  it("refuses to place more envelopes than the profile has slots", () => {
    for (const name of ["lite", "x"] as const) {
      const { envelopeSlots } = CAPACITY_PROFILES[name];

      // Exactly at the bound is fine: every slot may legitimately hold a
      // real envelope, which is what a fully-populated group looks like.
      const full = Array.from({ length: envelopeSlots }, (_, i) => envelope(i));
      expect(
        placeEnvelopes(crypto, full, 1, envelopeSlots).envelopes,
      ).toHaveLength(envelopeSlots);

      // One past it has nowhere to go, and must fail rather than drop a
      // member's envelope — a silently skipped device would lose access
      // with no signal to anyone.
      expect(() =>
        placeEnvelopes(crypto, [...full, envelope(envelopeSlots)], 1, envelopeSlots),
      ).toThrow(EnvelopeError);
    }
  });

  it("bounds devices, not members — `maxMembers` is documentary", () => {
    // Worth stating plainly, because the two are easy to conflate. The
    // enforced ceiling counts *devices*: `lite` serves 45 and `x` 90, on
    // the assumption of roughly three devices per member. A profile's
    // `maxMembers` is the design intent behind that slot count, not a
    // second check — nothing reads it.
    for (const name of ["lite", "x"] as const) {
      const profile = CAPACITY_PROFILES[name];
      expect(profile.envelopeSlots).toBe(profile.maxMembers * 3);
    }
  });
});
