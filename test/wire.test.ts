/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Wire-shape rejection (spec §9.1, §10.2).
 *
 * The backend is untrusted, so malformed JSON must produce a typed
 * `MalformedTransitionError` — never a bare `TypeError` from inside
 * the verifier. Before this guard existed, `members: null` crashed
 * `validateMemberSet` with an untyped error.
 */

import { describe, expect, it } from "vitest";

import { MalformedTransitionError } from "../src/core/errors";
import {
  parseEpochTransition,
  parseEpochTransitions,
  parseWireTransition,
} from "../src/core/wire";

/** A structurally valid transition; individual cases break one field. */
function wellFormed(): Record<string, unknown> {
  return {
    group_id: "g",
    epoch: 1,
    prev_transition_hash: "h",
    action: "add",
    members: [{ user_id: "alice", device_pubkeys: ["devA"], is_manager: true }],
    secret_envelopes: ["ct"],
    envelope_slots: [0],
    prev_secret_ciphertext: "link",
    signed_by: "id",
    signature: "sig",
  };
}

/** A structurally valid outer transition (spec §6.5). */
function wellFormedWire(): Record<string, unknown> {
  return {
    group_id: "g",
    epoch: 1,
    sealed_body: "body",
    secret_envelopes: ["ct"],
    auth_pubkey: "auth",
  };
}

describe("parseEpochTransition", () => {
  it("accepts a well-formed transition and normalizes it", () => {
    const parsed = parseEpochTransition(wellFormed());
    expect(parsed.group_id).toBe("g");
    expect(parsed.members[0]?.is_manager).toBe(true);
  });

  it("drops unknown fields rather than carrying them through", () => {
    // Anything extra would otherwise reach canonicalization, hashing
    // and storage — a backend must not be able to smuggle fields in.
    const parsed = parseEpochTransition({ ...wellFormed(), injected: "surprise" });
    expect(Object.keys(parsed)).not.toContain("injected");
  });

  it("omits absent optional fields instead of setting them undefined", () => {
    // spec §6.5: canonical encoding rejects undefined values outright,
    // so an absent field must be absent, not present-and-undefined.
    const rest = wellFormed();
    delete rest.policy;
    delete rest.prev_secret_ciphertext;
    const parsed = parseEpochTransition(rest);
    expect("policy" in parsed).toBe(false);
    expect("prev_secret_ciphertext" in parsed).toBe(false);
  });

  it("rejects non-objects", () => {
    for (const bad of [null, undefined, 42, "transition", [], true]) {
      expect(() => parseEpochTransition(bad)).toThrow(MalformedTransitionError);
    }
  });

  it("rejects a malformed members array", () => {
    for (const members of [null, undefined, "alice", 3, {}]) {
      expect(() => parseEpochTransition({ ...wellFormed(), members })).toThrow(
        MalformedTransitionError,
      );
    }
    // Entries must be objects with the right field types.
    expect(() => parseEpochTransition({ ...wellFormed(), members: ["alice"] })).toThrow(
      MalformedTransitionError,
    );
    expect(() =>
      parseEpochTransition({
        ...wellFormed(),
        members: [{ user_id: "a", device_pubkeys: "devA", is_manager: true }],
      }),
    ).toThrow(MalformedTransitionError);
    expect(() =>
      parseEpochTransition({
        ...wellFormed(),
        members: [{ user_id: "a", device_pubkeys: [7], is_manager: true }],
      }),
    ).toThrow(MalformedTransitionError);
    expect(() =>
      parseEpochTransition({
        ...wellFormed(),
        members: [{ user_id: "a", device_pubkeys: [], is_manager: "yes" }],
      }),
    ).toThrow(MalformedTransitionError);
  });

  it("rejects a malformed secret_envelopes array (outer)", () => {
    for (const secret_envelopes of [null, undefined, {}, "x"]) {
      expect(() =>
        parseWireTransition({ ...wellFormedWire(), secret_envelopes }),
      ).toThrow(MalformedTransitionError);
    }
    expect(() =>
      parseWireTransition({ ...wellFormedWire(), secret_envelopes: [5] }),
    ).toThrow(MalformedTransitionError);
  });

  it("rejects epochs that are not non-negative safe integers", () => {
    for (const epoch of [-1, 1.5, "1", null, undefined, Number.NaN, 2 ** 53]) {
      expect(() => parseEpochTransition({ ...wellFormed(), epoch })).toThrow(
        MalformedTransitionError,
      );
    }
  });

  it("rejects non-string identity fields", () => {
    for (const field of [
      "group_id",
      "prev_transition_hash",
      "action",
      "signed_by",
      "signature",
    ]) {
      expect(() => parseEpochTransition({ ...wellFormed(), [field]: 7 })).toThrow(
        MalformedTransitionError,
      );
      expect(() =>
        parseEpochTransition({ ...wellFormed(), [field]: undefined }),
      ).toThrow(MalformedTransitionError);
    }
  });

  it("rejects a malformed policy when one is present", () => {
    for (const policy of ["min", 3, [], { min_managers: "2" }, { min_managers: 1.5 }]) {
      expect(() => parseEpochTransition({ ...wellFormed(), policy })).toThrow(
        MalformedTransitionError,
      );
    }
    expect(
      parseEpochTransition({ ...wellFormed(), policy: { min_managers: 2 } }).policy,
    ).toEqual({ min_managers: 2 });
  });

  // `secret_envelopes` and `prev_secret_ciphertext` moved to the outer
  // WireTransition, so they are validated there.
  it("rejects a non-string history link when one is present (outer)", () => {
    expect(() =>
      parseWireTransition({ ...wellFormedWire(), prev_secret_ciphertext: 5 }),
    ).toThrow(MalformedTransitionError);
  });

  it("accepts and normalizes a well-formed wire transition", () => {
    const parsed = parseWireTransition(wellFormedWire());
    expect(parsed.sealed_body).toBe("body");
    expect(parsed.auth_pubkey).toBe("auth");
    expect(Object.keys(parsed).sort()).toEqual([
      "auth_pubkey",
      "epoch",
      "group_id",
      "secret_envelopes",
      "sealed_body",
    ].sort());
  });

  it("rejects missing outer fields", () => {
    for (const field of ["group_id", "epoch", "sealed_body", "auth_pubkey"]) {
      const broken = Object.fromEntries(
        Object.entries(wellFormedWire()).filter(([key]) => key !== field),
      );
      expect(() => parseWireTransition(broken)).toThrow(MalformedTransitionError);
    }
  });
});

describe("parseEpochTransitions", () => {
  it("accepts an array and reports which entry failed", () => {
    expect(parseEpochTransitions([wellFormed(), wellFormed()])).toHaveLength(2);
    try {
      parseEpochTransitions([wellFormed(), { ...wellFormed(), members: null }]);
      throw new Error("expected a rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(MalformedTransitionError);
      expect((error as Error).message).toContain("transition[1]");
    }
  });

  it("rejects a non-array response", () => {
    for (const bad of [null, undefined, {}, "[]"]) {
      expect(() => parseEpochTransitions(bad)).toThrow(MalformedTransitionError);
    }
  });
});
