/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    /**
     * Raised from vitest's 5s default.
     *
     * Padding made every transition roughly an order of magnitude more
     * expensive: 45 sealed envelope slots plus an 8 KiB body seal, where
     * before there were one to three envelopes and no body. In isolation
     * the heaviest suites finish in ~2.5s, but under full-suite
     * parallelism they were brushing 5s and failing intermittently — a
     * flake that says nothing about correctness while hiding the
     * failures that do.
     *
     * This is headroom, not a licence to be slow. If a test starts
     * approaching this bound, find out why rather than raising it again.
     */
    testTimeout: 30_000,
  },
});
