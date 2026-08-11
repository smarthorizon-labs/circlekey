/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * The version surface.
 *
 * `CIRCLEKEY_VERSION` duplicates `package.json`, so the only useful
 * assertion is that the two agree — hard-coding the literal in a third
 * place is what lets them drift apart silently, which for a security
 * library means a vulnerability report naming a version the code is
 * not. Bump `package.json` alone and this goes red.
 */

import { describe, expect, it } from "vitest";

import pkg from "../package.json";
import { CIRCLEKEY_VERSION, SUITE_V1, SUPPORTED_SUITES } from "../src/index";

describe("version surface", () => {
  it("reports the same version as package.json", () => {
    expect(CIRCLEKEY_VERSION).toBe(pkg.version);
  });

  it("declares the protocol suites this build speaks", () => {
    // Separate from the library version on purpose: spec §6.3 expects a
    // build to support several suites at once, so this list grows
    // rather than tracking `CIRCLEKEY_VERSION`.
    expect(SUPPORTED_SUITES).toContain(SUITE_V1);
    expect([...SUPPORTED_SUITES]).toEqual([...new Set(SUPPORTED_SUITES)]);
  });
});
