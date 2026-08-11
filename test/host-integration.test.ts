/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * The host-integration scenario runs green against
 * `MockTransport`. The same scenario, pointed at the host team's own
 * `Transport` adapter, is their acceptance test
 * (docs/backend-checklist.md).
 *
 * The reference backend here is deliberately the **strict** mock: the
 * scenario now probes spec §10.1 relay authorization directly, and a
 * relay that enforced nothing would otherwise sail through the very
 * checks that exist to catch it. The default `MockTransport` does not
 * require signatures — convenient for the rest of the suite, useless as
 * an acceptance reference.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { MockTransport } from "../src/adapters/transport/mock";
import { base64UrlToBytes } from "../src/core/bytes";
import { verifyRelayRequest } from "../src/core/relay-auth";
import { runHostIntegrationScenario } from "../src/testing";
import { FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();

/** A relay enforcing spec §10.1 the way a conforming backend must. */
function strictRelay(): MockTransport {
  return new MockTransport({
    requireAuth: true,
    // Models the account layer the spec requires a real relay to anchor
    // the bootstrap exemption in (§10.1). Presented signatures are
    // still verified strictly, and writes never bootstrap.
    allowUnauthenticatedReads: true,
    verifyAuth: (authPublicKey, requestBytes, signature) =>
      verifyRelayRequest(
        crypto,
        base64UrlToBytes(authPublicKey),
        requestBytes,
        base64UrlToBytes(signature),
      ),
  });
}

describe("host integration scenario", () => {
  it("passes end-to-end against the reference backend", async () => {
    const report = await runHostIntegrationScenario({
      makeTransport: () => strictRelay(),
      crypto,
      backup: FAST_BACKUP,
    });

    expect(report.checks).toContain(
      "backup gate blocks group ops pre-enrollment (spec §9.6)",
    );
    expect(report.checks).toContain(
      "pre-join record decrypted via the spec §9.7 history chain",
    );
    expect(report.checks).toContain("removed member cannot read post-removal data");
    expect(report.checks).toContain(
      "lost device restored from backup and recovered full access",
    );

    // The §10.1 read/write split, which is what a backend team is most
    // likely to collapse into a single rule.
    expect(report.checks).toContain(
      "read accepted with a stale epoch key (no catch-up deadlock, spec §10.1)",
    );
    expect(report.checks).toContain(
      "write refused when signed with a stale epoch key (spec §10.1)",
    );
    expect(report.checks).toContain(
      "write refused when signed with a key the group never published",
    );
    expect(report.checks).toContain(
      "unsigned write refused (writes never bootstrap, spec §10.5)",
    );
    expect(report.checks.length).toBeGreaterThanOrEqual(12);
  });

  it("fails a relay that does not enforce spec §10.1 at all", async () => {
    // The scenario's value as an acceptance test depends entirely on
    // this: a permissive relay must not be able to pass it. The default
    // mock ignores request signatures, which is exactly the backend a
    // team ships when they read §10.1 as optional.
    await expect(
      runHostIntegrationScenario({
        makeTransport: () => new MockTransport(),
        crypto,
        backup: FAST_BACKUP,
      }),
    ).rejects.toThrow(/write refused when signed with a stale epoch key/);
  });

  it("can run repeatedly against the same persistent backend", async () => {
    const transport = strictRelay();
    const options = {
      makeTransport: () => transport,
      crypto,
      backup: FAST_BACKUP,
    };
    const first = await runHostIntegrationScenario(options);
    const second = await runHostIntegrationScenario(options);
    expect(first.groupId).not.toBe(second.groupId);
  });
});
