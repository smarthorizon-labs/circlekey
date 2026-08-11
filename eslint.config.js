/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "coverage/", "node_modules/"] },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/*.js"],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    // Excluded from tsconfig (see the note there), so the type-aware
    // rules cannot run on it. Like the manual browser suite, it trades
    // static checking for not dragging Node's globals into the project.
    ignores: ["test/regenerate-vectors.test.ts", "test/conformance-doc.test.ts"],
  },
  {
    // The vector generator runs in Node under vitest and is excluded
    // from tsconfig (see the note there), so its Node globals must be
    // declared here rather than coming from @types/node.
    files: ["test/regenerate-vectors.test.ts"],
    languageOptions: {
      globals: { process: "readonly" },
    },
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-call": "off",
    },
  },
  {
    // Code that runs in a page rather than in Node, so DOM and
    // browser-only globals are legitimate: the real-browser suite.
    files: ["test/browser/**/*.js"],
    languageOptions: {
      globals: {
        BroadcastChannel: "readonly",
        Element: "readonly",
        TextDecoder: "readonly",
        TextEncoder: "readonly",
        console: "readonly",
        document: "readonly",
        indexedDB: "readonly",
        navigator: "readonly",
        performance: "readonly",
        setTimeout: "readonly",
        structuredClone: "readonly",
        window: "readonly",
      },
    },
  },
);
