/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * The primitives behind the governance invariant. `satisfiesPolicy`
 * is what stands between the group and a `min_managers` breach (spec
 * §5.6, §8.1), and `cloneMembers` is what stops verified state from
 * aliasing untrusted input — both were only exercised indirectly.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  cloneMembers,
  findMember,
  managerCount,
  memberDevices,
  satisfiesPolicy,
} from "../src/core/group-state";
import type { MemberEntry } from "../src/core/types";

const member = (
  userId: string,
  isManager: boolean,
  devices: string[] = [`${userId}-dev`],
): MemberEntry => ({
  user_id: userId,
  device_pubkeys: devices,
  is_manager: isManager,
});

const membersArb = fc.array(
  fc.record({
    user_id: fc.string({ minLength: 1, maxLength: 6 }),
    is_manager: fc.boolean(),
  }),
  { maxLength: 8 },
);

describe("managerCount", () => {
  it("counts only managers", () => {
    expect(managerCount([])).toBe(0);
    expect(managerCount([member("a", false)])).toBe(0);
    expect(managerCount([member("a", true), member("b", false), member("c", true)])).toBe(
      2,
    );
  });

  it("equals the number of entries flagged is_manager", () => {
    fc.assert(
      fc.property(membersArb, (raw) => {
        const members = raw.map((entry, index) =>
          member(`${entry.user_id}-${String(index)}`, entry.is_manager),
        );
        expect(managerCount(members)).toBe(
          members.filter((entry) => entry.is_manager).length,
        );
      }),
    );
  });
});

describe("satisfiesPolicy (spec §5.6, §8.1)", () => {
  it("holds exactly at the boundary, and fails one below it", () => {
    const oneManager = [member("a", true), member("b", false)];
    expect(satisfiesPolicy(oneManager, { min_managers: 1 })).toBe(true);
    expect(satisfiesPolicy(oneManager, { min_managers: 2 })).toBe(false);

    const twoManagers = [member("a", true), member("b", true)];
    expect(satisfiesPolicy(twoManagers, { min_managers: 2 })).toBe(true);
    expect(satisfiesPolicy(twoManagers, { min_managers: 3 })).toBe(false);
  });

  it("rejects a manager-less group under any real policy", () => {
    const noManagers = [member("a", false), member("b", false)];
    expect(satisfiesPolicy(noManagers, { min_managers: 1 })).toBe(false);
    expect(satisfiesPolicy([], { min_managers: 1 })).toBe(false);
  });

  it("is exactly `managerCount >= min_managers`, never off by one", () => {
    fc.assert(
      fc.property(membersArb, fc.integer({ min: 1, max: 5 }), (raw, minManagers) => {
        const members = raw.map((entry, index) =>
          member(`${entry.user_id}-${String(index)}`, entry.is_manager),
        );
        expect(satisfiesPolicy(members, { min_managers: minManagers })).toBe(
          managerCount(members) >= minManagers,
        );
      }),
    );
  });
});

describe("findMember and memberDevices", () => {
  it("finds by exact user id only", () => {
    const members = [member("alice", true), member("bob", false)];
    expect(findMember(members, "bob")?.is_manager).toBe(false);
    expect(findMember(members, "Bob")).toBeUndefined(); // case-sensitive
    expect(findMember(members, "ali")).toBeUndefined(); // no prefix match
    expect(findMember([], "alice")).toBeUndefined();
  });

  it("flattens every device across members, in member order", () => {
    const members = [
      member("alice", true, ["a1", "a2"]),
      member("bob", false, ["b1"]),
    ];
    expect(memberDevices(members)).toEqual(["a1", "a2", "b1"]);
    expect(memberDevices([])).toEqual([]);
  });
});

describe("cloneMembers", () => {
  it("deep-copies so verified state never aliases its input", () => {
    const original = [member("alice", true, ["a1"])];
    const copy = cloneMembers(original);
    expect(copy).toEqual(original);

    // Mutating the clone must not reach the original…
    copy[0]?.device_pubkeys.push("injected");
    if (copy[0]) copy[0].is_manager = false;
    expect(original[0]?.device_pubkeys).toEqual(["a1"]);
    expect(original[0]?.is_manager).toBe(true);

    // …nor the reverse.
    original[0]?.device_pubkeys.push("late");
    expect(copy[0]?.device_pubkeys).toEqual(["a1", "injected"]);
  });

  it("preserves content for any member set", () => {
    fc.assert(
      fc.property(membersArb, (raw) => {
        const members = raw.map((entry, index) =>
          member(`${entry.user_id}-${String(index)}`, entry.is_manager),
        );
        const copy = cloneMembers(members);
        expect(copy).toEqual(members);
        expect(managerCount(copy)).toBe(managerCount(members));
      }),
    );
  });
});
