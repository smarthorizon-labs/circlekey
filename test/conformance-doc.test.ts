/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Guards `docs/conformance.md` against rot.
 *
 * That document's entire value is the claim "every client-observable
 * MUST maps to a named test". A citation to a test that no longer
 * exists silently converts the audit into a comfortable fiction, and
 * nothing else in the suite can notice — the tests still pass, the
 * document still reads correctly, and only the link between them is
 * broken.
 *
 * It had already happened: tests were renamed as behaviour
 * changed (a signature swap became a body swap; a removed member stops
 * advancing rather than keeping state) and moved the §9.7 history link
 * from the inner body to the outer wire. Four rows ended up citing
 * tests that had ceased to exist, and in the history-link case the
 * rejection tests had been lost outright while the verifier kept
 * enforcing the rules — an untested MUST that read as tested.
 *
 * So the mapping is now itself checked. Citations are the italic runs
 * that follow a `suite`: prefix, which is the convention the document
 * uses throughout; prose emphasis elsewhere in a row is ignored.
 */

import { readFileSync, readdirSync } from "node:fs";

import { describe, expect, it } from "vitest";

// URLs rather than `process.cwd()`: this package has no `@types/node`,
// and the paths are relative to this file anyway.
const TEST_DIR = new URL("./", import.meta.url);
const DOC = new URL("../docs/conformance.md", import.meta.url);

/** `it("…")` / `test('…')`, tolerating quotes of the other kind inside. */
const TEST_NAME = /\b(?:it|test)\(\s*(["'`])((?:\\.|(?!\1).)*)\1/g;

/**
 * A citation run: a backticked suite name, a colon, then one or more
 * italic test names separated by `;`. Prose emphasis that is not
 * introduced by a suite name is not a citation and is not checked.
 */
const CITATION_RUN = /`([a-z0-9-]+)`:\s*((?:\*[^*|]+\*(?:\s*;\s*)?)+)/g;

function normalize(value: string): string {
  // Source-level escapes (`\"` inside a double-quoted name) are not part
  // of the name a reader sees, nor of what the document cites.
  return value
    .replace(/\\(["'`\\])/g, "$1")
    .normalize("NFC")
    .replace(/’/g, "'")
    .trim();
}

function collectRealTestNames(): Set<string> {
  const names = new Set<string>();
  const walk = (dir: URL): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = new URL(entry.name, dir);
      if (entry.isDirectory()) {
        walk(new URL(`${entry.name}/`, dir));
      } else if (entry.name.endsWith(".test.ts") || entry.name.endsWith(".js")) {
        const source = readFileSync(path, "utf8");
        for (const match of source.matchAll(TEST_NAME)) {
          names.add(normalize(match[2] ?? ""));
        }
        // The browser suite is plain JS driven by its own runner, so
        // its cases are string literals rather than `it(...)` calls.
        if (entry.name.endsWith(".js")) {
          for (const match of source.matchAll(/["'`]([^"'`\n]{15,})["'`]/g)) {
            names.add(normalize(match[1] ?? ""));
          }
        }
      }
    }
  };
  walk(TEST_DIR);
  return names;
}

function collectCitations(): { suite: string; name: string }[] {
  const doc = readFileSync(DOC, "utf8");
  const cited: { suite: string; name: string }[] = [];
  for (const line of doc.split("\n")) {
    if (!line.startsWith("| ")) continue;
    for (const run of line.matchAll(CITATION_RUN)) {
      const suite = run[1] ?? "";
      for (const name of (run[2] ?? "").matchAll(/\*([^*|]+)\*/g)) {
        cited.push({ suite, name: normalize(name[1] ?? "") });
      }
    }
  }
  return cited;
}

describe("docs/conformance.md cites tests that exist", () => {
  const real = collectRealTestNames();
  const cited = collectCitations();

  it("finds citations to check, and test names to check them against", () => {
    // Without this, every assertion below passes vacuously the moment
    // either regex stops matching the file's conventions.
    expect(real.size).toBeGreaterThan(300);
    expect(cited.length).toBeGreaterThan(150);
  });

  it("resolves every cited test name to a real test", () => {
    const missing = cited
      // `vectors` names its cases from the vector file at runtime, so a
      // citation there is necessarily a template, not a literal.
      .filter((entry) => !entry.name.includes("${"))
      .filter((entry) => !real.has(entry.name))
      .map((entry) => `${entry.suite}: "${entry.name}"`);
    expect(missing, `conformance.md cites tests that do not exist:\n${missing.join("\n")}`).toEqual(
      [],
    );
  });

  it("keeps the requirement count in the summary honest", () => {
    const doc = readFileSync(DOC, "utf8");
    // Canonical rows are the 5-column table rows whose status cell is a
    // known marker; the summary must report exactly that many.
    const markers = new Set([
      "`TEST`",
      "`BACKEND`",
      "`DESIGN`",
      "`PROCESS`",
      "`N/A`",
      "**`GAP`**",
      "`TEST` / **`GAP`**",
    ]);
    let rows = 0;
    for (const line of doc.split("\n")) {
      if (!line.startsWith("| ")) continue;
      const cells = line
        .trim()
        .replace(/^\||\|$/g, "")
        .split("|")
        .map((cell: string) => cell.trim());
      if (cells.length === 5 && markers.has(cells[3] ?? "")) rows += 1;
    }
    expect(doc).toContain(`**${String(rows)} canonical requirement rows**`);
  });
});
