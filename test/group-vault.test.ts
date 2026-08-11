/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * GroupVault facade: precondition enforcement, record
 * round-trips, event wiring, and restore — through the public API
 * that hosts actually consume.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { base64UrlToBytes } from "../src/core/bytes";
import {
  BackupError,
  BackupRequiredError,
  CryptoError,
  ForkDetectedError,
  InsecureContextError,
  StorageError,
  TransportError,
} from "../src/core/errors";
import type { Transport } from "../src/ports/transport";
import {
  completeEnrollment,
  FAST_BACKUP,
  SplitTransport,
  SwitchableTransport,
} from "./helpers";

const crypto = new WebCryptoProvider();

function vaultOptions(transport: Transport, userId: string, storage = new MemoryStore()) {
  return {
    transport,
    userId,
    crypto,
    storage,
    locks: new InProcessLockProvider(),
    requestPersistentStorage: false,
    backup: FAST_BACKUP,
  };
}

describe("GroupVault facade", () => {
  it("onboards, enforces the backup gate, and round-trips records", async () => {
    const transport = new MockTransport();
    const vault = await GroupVault.open(vaultOptions(transport, "alice"));

    expect(vault.userId).toBe("alice");
    expect(vault.persistentStorage).toBeUndefined(); // request skipped
    expect(await vault.isBackupEnrolled()).toBe(false);
    await expect(
      vault.createGroup({ min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);

    const credential = await completeEnrollment(vault);
    expect(credential.length).toBeGreaterThanOrEqual(22);

    const state = await vault.createGroup({ min_managers: 1 });
    const g = state.group_id;
    expect(state.epoch).toBe(0);
    expect(vault.getGroupState(g)?.epoch).toBe(0);

    await vault.putJsonRecord(g, "doc-1", { title: "Q3", n: 3 });
    expect(await vault.getJsonRecord(g, "doc-1")).toEqual({ title: "Q3", n: 3 });

    const plaintext = new TextEncoder().encode("raw bytes payload");
    await vault.putRecordBytes(g, "doc-2", plaintext);
    expect(await vault.getRecordBytes(g, "doc-2")).toEqual(plaintext);

    // Listings carry derived identifiers, never the application's keys
    // (spec §5.8 rule 2) — a host matches them by deriving its own.
    const listed = await vault.listRecords(g);
    expect(listed.map((record) => record.record_id).sort()).toEqual(
      (
        await Promise.all(["doc-1", "doc-2"].map((key) => vault.recordIdFor(g, key)))
      ).sort(),
    );
    expect(listed.map((record) => record.record_id)).not.toContain("doc-1");
  });

  it("generates an opaque group id rather than accepting one (spec §6.5, §12)", async () => {
    // `group_id` is plaintext on every single request, so it is the most
    // repeated identifier in the protocol. §12 forbids a client from
    // taking one from the application: a caller who could name a group
    // would name it something meaningful, and hand the relay exactly the
    // kind of label the metadata-minimization design exists to remove.
    const transport = new MockTransport();
    const vault = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(vault);

    const first = await vault.createGroup({ min_managers: 1 });
    const second = await vault.createGroup({ min_managers: 1 });

    // 128 bits, base64url, no padding (spec §6.5).
    expect(first.group_id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(base64UrlToBytes(first.group_id)).toHaveLength(16);
    // Fresh per group — a fixed or derived id would collide or correlate.
    expect(second.group_id).not.toBe(first.group_id);

    // And the API gives an application no way to supply one: the arity
    // is the enforcement. A stray extra argument is a type error, and at
    // runtime it is ignored rather than honoured.
    expect(vault.createGroup.bind(vault)).toHaveLength(1);
    const sneaked = await (
      vault.createGroup as unknown as (
        policy: unknown,
        groupId?: string,
      ) => Promise<{ group_id: string }>
    )({ min_managers: 1 }, "acme-acquisition-2026");
    expect(sneaked.group_id).not.toContain("acme");
  });

  it("derives record identifiers, stably across rotations (spec §5.8 rule 2)", async () => {
    // The facade must actually *use* `deriveRecordId`. The primitive
    // shipped with its own tests and then went uncalled for two
    // phases, so the property that matters here is the wiring.
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(alice);
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    const h = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.putJsonRecord(g, "invoice-2026-Q1", { total: 42 });

    const before = await alice.recordIdFor(g, "invoice-2026-Q1");
    expect(before).not.toContain("invoice");

    // Anchored on the genesis secret, so a membership change — which
    // rotates the group key — must not move the identifier. An id that
    // changed per epoch would strand every record already stored.
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await alice.removeMember(g, "bob");
    expect(alice.getGroupState(g)?.epoch).toBe(2);
    expect(await alice.recordIdFor(g, "invoice-2026-Q1")).toBe(before);
    expect(await alice.getJsonRecord(g, "invoice-2026-Q1")).toEqual({ total: 42 });

    // Scoped per group: the same key in another group is unlinkable, so
    // a relay cannot correlate two groups by their filenames.
    expect(await alice.recordIdFor(h, "invoice-2026-Q1")).not.toBe(before);

    // And a member derives the same id as the writer.
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await bob.syncGroup(g);
    expect(await bob.recordIdFor(g, "invoice-2026-Q1")).toBe(before);
    expect(await bob.getJsonRecord(g, "invoice-2026-Q1")).toEqual({ total: 42 });
  });

  it("two vaults converge through the facade, including pre-join history", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    const bob = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(alice);
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.putJsonRecord(g, "doc-pre", { hello: "bob" });
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });

    const bobState = await bob.syncGroup(g);
    expect(bobState).toEqual(alice.getGroupState(g));
    expect(await bob.getJsonRecord(g, "doc-pre")).toEqual({ hello: "bob" });
  });

  it("refuses to open a storage that belongs to another account", async () => {
    const transport = new MockTransport();
    const storage = new MemoryStore();
    await GroupVault.open(vaultOptions(transport, "alice", storage));
    await expect(
      GroupVault.open(vaultOptions(transport, "mallory", storage)),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it("restores a lost device from the recovery credential", async () => {
    const transport = new MockTransport();
    const vault = await GroupVault.open(vaultOptions(transport, "alice"));
    const credential = await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;
    await vault.putJsonRecord(g, "doc", { keep: "safe" });

    await expect(
      GroupVault.restore({
        ...vaultOptions(transport, "alice"),
        credential: "not-the-credential",
      }),
    ).rejects.toBeInstanceOf(BackupError);

    const restored = await GroupVault.restore({
      ...vaultOptions(transport, "alice"),
      credential,
    });
    expect(restored.devicePublicKey()).toBe(vault.devicePublicKey());
    await restored.syncGroup(g);
    expect(await restored.getJsonRecord(g, "doc")).toEqual({ keep: "safe" });
  });

  it("surfaces forks through the forkDetected event", async () => {
    const transport = new SwitchableTransport(new MockTransport());
    const vault = await GroupVault.open(vaultOptions(transport, "alice"));
    const credential = await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;
    await vault.setPolicy(g, { min_managers: 1 }); // epoch 1

    const forks: string[] = [];
    vault.on("forkDetected", (groupId, error) => {
      forks.push(groupId);
      expect(error).toBeInstanceOf(ForkDetectedError);
    });

    // a fork cannot be *fabricated*: bodies are
    // sealed, so a forged successor fails to open long before check 2
    // could fire, and the test would prove nothing. A rival branch has
    // to be built by someone holding the epoch secret — a member.
    //
    // A second instance of the same identity (restore, spec §9.6) on a
    // separate relay gives exactly that: it replays the same history,
    // then advances independently. Two honest branches, one of which
    // our vault never adopted.
    const rivalRelay = new MockTransport();
    const shared = await transport.getTransitions(g);
    const [w0, w1] = shared;
    if (w0 === undefined || w1 === undefined) throw new Error("missing history");
    await rivalRelay.createGroup(w0);
    await rivalRelay.submitTransition(g, w1);

    // Restore reads the backup blob, which lives on the honest relay;
    // the rival relay only carries the group history.
    const twin = await GroupVault.restore({
      ...vaultOptions(new SplitTransport(rivalRelay, transport), "alice"),
      credential,
    });
    await twin.syncGroup(g);
    // The rival's epoch 2 must differ from ours in *body content*, not
    // merely in the fresh secret the rekey draws. `prev_transition_hash`
    // commits to the signed body alone, and two independently built
    // transitions with the same action, members and policy produce the
    // same bytes — Ed25519 signing is deterministic, so the only
    // variation left is `envelope_slots`, which in this one-member group
    // is a single CSPRNG-chosen index in [0, 45). It collided roughly
    // once in 45 runs, the two epoch 2s hashed alike, check 2 saw a
    // valid successor, and the divergence surfaced downstream as an
    // EnvelopeError from check 11 instead. Differing by policy makes the
    // branches distinguishable by hash every time.
    await twin.setPolicy(g, { min_managers: 1, removal_notice: "suppressed" });
    const rivalEpoch2Hash = twin.getGroupState(g)?.last_transition_hash;
    await twin.setPolicy(g, { min_managers: 1 }); // rival epoch 3
    const rivalChain = await rivalRelay.getTransitions(g);
    const rivalEpoch3 = rivalChain[3];
    if (rivalEpoch3 === undefined) throw new Error("missing rival epoch 3");

    // Our vault advances to its own epoch 2 on the honest relay.
    await vault.setPolicy(g, { min_managers: 1 });
    expect(vault.getGroupState(g)?.epoch).toBe(2);
    // Pin the premise above: if the two epoch 2s ever hash alike again,
    // the fork is invisible to check 2 and this test asserts nothing.
    expect(vault.getGroupState(g)?.last_transition_hash).not.toBe(rivalEpoch2Hash);

    // The relay now serves the rival's epoch 3, whose prev-hash commits
    // to an epoch 2 we never verified (spec §9.1 check 2).
    transport.override = (_groupId, sinceEpoch) =>
      sinceEpoch === 2 ? [rivalEpoch3] : [];

    await expect(vault.syncGroup(g)).rejects.toBeInstanceOf(ForkDetectedError);
    expect(forks).toEqual([g]);
  });

  // spec §9.3 step 3: the client's own freshness obligation, which the
  // spec states is not delegable to the backend. The backend gate
  // (step 4, exercised in test/group-sync.test.ts) is defense in depth
  // and no client guarantee may depend on it — so the assertion here is
  // that the write lands on the *first* attempt, which is the observable
  // §9.3 step 3 names. Without the pre-encrypt sync the facade still
  // succeeds, but only after emitting a stale record and being refused;
  // against a backend with no gate, that record would have stuck.
  it("syncs before encrypting, so a rotated epoch never yields a stale write", async () => {
    const transport = new MockTransport();
    const puts: number[] = [];
    // Object.create, not spread: MockTransport's methods live on its
    // prototype and a spread copy would lose them.
    const counting: Transport = Object.create(transport) as Transport;
    counting.putRecord = async (groupId, record) => {
      puts.push(record.epoch);
      return transport.putRecord(groupId, record);
    };

    const alice = await GroupVault.open(vaultOptions(counting, "alice"));
    const bob = await GroupVault.open(vaultOptions(counting, "bob"));
    await completeEnrollment(alice);
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await bob.syncGroup(g);
    expect(bob.getGroupState(g)?.epoch).toBe(1);

    // Alice rotates the epoch; bob is never told and never polls.
    const rotated = await alice.promoteMember(g, "bob");
    expect(rotated.epoch).toBe(2);
    expect(bob.getGroupState(g)?.epoch).toBe(1); // still stale locally

    await bob.putJsonRecord(g, "doc-fresh", { written: "after rotation" });

    // Exactly one write, tagged with the post-rotation epoch: bob
    // resynced before encrypting rather than after being refused.
    expect(puts).toEqual([2]);
    expect(await alice.getJsonRecord(g, "doc-fresh")).toEqual({
      written: "after rotation",
    });
  });

  it("serves reads from the offline cache when the backend is unreachable", async () => {
    const transport = new MockTransport();
    const offline = new SwitchableTransport(transport);
    const storage = new MemoryStore();
    const vault = await GroupVault.open(vaultOptions(offline, "alice", storage));
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;
    await vault.putJsonRecord(g, "doc", { cached: true });

    const cachedFor: string[] = [];
    vault.on("servedFromCache", (groupId, recordId) => {
      cachedFor.push(`${groupId}/${recordId}`);
    });

    // The backend goes away entirely.
    offline.failReads = new TransportError("network down");

    expect(await vault.getJsonRecord(g, "doc")).toEqual({ cached: true });
    expect(cachedFor).toEqual([`${g}/doc`]);
    expect((await vault.listRecords(g)).map((r) => r.record_id)).toEqual([
      await vault.recordIdFor(g, "doc"),
    ]);

    // A record never cached still fails — there is nothing to serve.
    await expect(vault.getJsonRecord(g, "never-read")).rejects.toBeInstanceOf(
      TransportError,
    );
  });

  it("does not mask a decryption failure with cached data", async () => {
    // Only TransportError may trigger the fallback: papering over a
    // verification failure with older data would hide a real problem.
    const transport = new MockTransport();
    const storage = new MemoryStore();
    const vault = await GroupVault.open(vaultOptions(transport, "alice", storage));
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;
    const record = await vault.putJsonRecord(g, "doc", { real: true });

    // Corrupt the stored ciphertext on the backend *and* in the cache.
    const tampered = {
      ...record,
      ciphertext: record.ciphertext.startsWith("A")
        ? `B${record.ciphertext.slice(1)}`
        : `A${record.ciphertext.slice(1)}`,
    };
    await transport.putRecord(g, tampered);
    await storage.putCachedRecord(g, tampered);

    await expect(vault.getJsonRecord(g, "doc")).rejects.toBeInstanceOf(CryptoError);
  });

  it("fails fast with InsecureContextError when WebCrypto is missing", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    if (descriptor?.configurable !== true) {
      return; // cannot simulate in this runtime
    }
    try {
      Object.defineProperty(globalThis, "crypto", {
        value: undefined,
        configurable: true,
      });
      await expect(
        GroupVault.open({
          transport: new MockTransport(),
          userId: "alice",
          storage: new MemoryStore(),
          locks: new InProcessLockProvider(),
          requestPersistentStorage: false,
        }),
      ).rejects.toBeInstanceOf(InsecureContextError);
    } finally {
      Object.defineProperty(globalThis, "crypto", descriptor);
    }
  });
});
