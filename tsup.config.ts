/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "adapters/webcrypto": "src/adapters/crypto/web.ts",
    "adapters/indexeddb": "src/adapters/storage/indexeddb.ts",
    "adapters/locks": "src/adapters/locks.ts",
    "adapters/hints": "src/adapters/hints.ts",
    testing: "src/testing.ts",
  },
  format: ["esm"],
  target: "es2022",
  // tsup injects `baseUrl` into its dts build, which TypeScript 6
  // reports as deprecated (TS5101); silence only that, only here.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  sourcemap: true,
  clean: true,
});
