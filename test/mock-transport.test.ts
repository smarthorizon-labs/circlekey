/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * MockTransport is the executable reference of the backend's spec §10
 * obligations — these tests document exactly what a host backend must
 * implement (epoch uniqueness, freshness gate, opaque storage).
 */

import { describe, expect, it } from "vitest";

import { MockTransport } from "../src/adapters/transport/mock";
import { TransportError } from "../src/core/errors";
import type { EncryptedRecord, WireTransition } from "../src/core/types";
import { wireStub } from "./helpers";

function transitionStub(groupId: string, epoch: number): WireTransition {
  return wireStub(groupId, epoch);
}

function recordStub(recordId: string, epoch: number): EncryptedRecord {
  return {
    record_id: recordId,
    epoch,
    ciphertext: "opaque",
    nonce: "nonce",
    suite: "gv1",
  };
}

async function groupAtEpoch(transport: MockTransport, groupId: string, epoch: number) {
  await transport.createGroup(transitionStub(groupId, 0));
  for (let e = 1; e <= epoch; e++) {
    await transport.submitTransition(groupId, transitionStub(groupId, e));
  }
}

describe("MockTransport: group lifecycle", () => {
  it("creates groups from genesis transitions only, exactly once", async () => {
    const transport = new MockTransport();
    await expect(transport.createGroup(transitionStub("g", 0))).resolves.toEqual({
      group_id: "g",
    });
    await expect(transport.createGroup(transitionStub("g", 0))).rejects.toBeInstanceOf(
      TransportError,
    );
    await expect(transport.createGroup(transitionStub("g2", 1))).rejects.toBeInstanceOf(
      TransportError,
    );
  });

  it("rejects operations on unknown groups", async () => {
    const transport = new MockTransport();
    await expect(transport.getTransitions("nope")).rejects.toBeInstanceOf(TransportError);
    await expect(
      transport.submitTransition("nope", transitionStub("nope", 1)),
    ).rejects.toBeInstanceOf(TransportError);
    await expect(transport.getRecord("nope", "r")).rejects.toBeInstanceOf(TransportError);
  });
});

describe("MockTransport: (group_id, epoch) uniqueness (spec §10.4)", () => {
  it("accepts the first submission per epoch and returns conflict to losers", async () => {
    const transport = new MockTransport();
    await groupAtEpoch(transport, "g", 0);

    await expect(transport.submitTransition("g", transitionStub("g", 1))).resolves.toEqual(
      { accepted: true },
    );
    // Same epoch again — first writer won.
    await expect(
      transport.submitTransition("g", { ...transitionStub("g", 1), sealed_body: "other" }),
    ).resolves.toEqual({ accepted: false, reason: "conflict" });
    // Older epoch — also lost.
    await expect(
      transport.submitTransition("g", transitionStub("g", 0)),
    ).resolves.toEqual({ accepted: false, reason: "conflict" });
    // Gapped epoch — malformed submission, not a race.
    await expect(
      transport.submitTransition("g", transitionStub("g", 5)),
    ).rejects.toBeInstanceOf(TransportError);
    // Mismatched group id.
    await expect(
      transport.submitTransition("g", transitionStub("other", 2)),
    ).rejects.toBeInstanceOf(TransportError);
  });
});

describe("MockTransport: transition serving", () => {
  it("serves transitions since an epoch, ascending, as copies", async () => {
    const transport = new MockTransport();
    await groupAtEpoch(transport, "g", 3);

    const all = await transport.getTransitions("g");
    expect(all.map((t) => t.epoch)).toEqual([0, 1, 2, 3]);
    const since = await transport.getTransitions("g", 1);
    expect(since.map((t) => t.epoch)).toEqual([2, 3]);

    const first = all[0];
    if (first) first.sealed_body = "mutated";
    expect((await transport.getTransitions("g"))[0]?.sealed_body).toBe("sealed-0");
  });

  // spec §10.2/§10.3: the snapshot is a routing hint and nothing more.
  // Membership, policy and the chain hash were all removed from
  // C — the first two because §5.7 forbade trusting them anyway, the
  // third because the chain now hashes sealed inner bodies the relay
  // cannot read. Asserting their *absence* is the point.
  it("exposes a routing snapshot carrying only the current epoch", async () => {
    const transport = new MockTransport();
    await groupAtEpoch(transport, "g", 2);

    const snapshot = await transport.getGroupState("g");
    expect(snapshot).toEqual({ group_id: "g", current_epoch: 2 });
    expect(Object.keys(snapshot).sort()).toEqual(["current_epoch", "group_id"]);
  });
});

describe("MockTransport: record freshness gate (spec §9.3)", () => {
  it("rejects writes tagged with a superseded epoch", async () => {
    const transport = new MockTransport();
    await groupAtEpoch(transport, "g", 2);

    await expect(transport.putRecord("g", recordStub("r1", 2))).resolves.toEqual({
      accepted: true,
    });
    await expect(transport.putRecord("g", recordStub("r2", 1))).resolves.toEqual({
      accepted: false,
      reason: "stale_epoch",
    });
    await expect(transport.putRecord("g", recordStub("r3", 7))).rejects.toBeInstanceOf(
      TransportError,
    );

    expect((await transport.getRecord("g", "r1")).epoch).toBe(2);
    await expect(transport.getRecord("g", "r2")).rejects.toBeInstanceOf(TransportError);
    expect((await transport.listRecords("g")).records).toHaveLength(1);
  });
});

describe("MockTransport: backup blobs", () => {

  it("stores backup blobs opaquely per user", async () => {
    const transport = new MockTransport();
    const blob = {
      ciphertext: "opaque",
      salt: "salt",
      kdf: "pbkdf2-sha256" as const,
      kdf_params: { iterations: 600_000 },
      suite: "gv1",
    };
    await transport.putBackupBlob("alice", blob);
    expect(await transport.getBackupBlob("alice")).toEqual(blob);
    await expect(transport.getBackupBlob("bob")).rejects.toBeInstanceOf(TransportError);
  });
});
