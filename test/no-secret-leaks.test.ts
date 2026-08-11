/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * spec §12, first requirement: "The backend MUST NOT ever receive
 * plaintext, private keys, or group secrets."
 *
 * It is the load-bearing claim of the whole design — §1.2's promise
 * that the backend cannot read data reduces to it — and until this
 * file existed it rested entirely on inspection. Every other suite
 * checks something narrower (envelopes are addressed correctly,
 * ciphertext decrypts, a removed member is cut off).
 *
 * The approach: run a full lifecycle through a Transport that records
 * every argument crossing it, then search the serialized traffic for
 * material that must never appear. Secrets are searched for in both
 * raw and base64url form, since either would be a leak.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { base64UrlToBytes, bytesToBase64Url, utf8String } from "../src/core/bytes";
import { KeyManager } from "../src/core/key-manager";
import type {
  EncryptedBackupBlob,
  EncryptedRecord,
  WireTransition,
} from "../src/core/types";
import type { Transport } from "../src/ports/transport";
import { completeEnrollment, FAST_BACKUP } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

/** Records everything handed to the backend, verbatim. */
class RecordingTransport implements Transport {
  readonly sent: unknown[] = [];

  constructor(private readonly inner: MockTransport) {}

  private capture<T>(value: T): T {
    this.sent.push(value);
    return value;
  }

  createGroup(genesis: WireTransition) {
    return this.inner.createGroup(this.capture(genesis));
  }
  submitTransition(groupId: string, transition: WireTransition) {
    return this.inner.submitTransition(groupId, this.capture(transition));
  }
  putRecord(groupId: string, record: EncryptedRecord) {
    return this.inner.putRecord(groupId, this.capture(record));
  }
  putBackupBlob(handle: string, blob: EncryptedBackupBlob) {
    // The handle itself is metadata: capture it so a test can prove no
    // user id is hiding in it (spec §6.5).
    return this.inner.putBackupBlob(this.capture(handle), this.capture(blob));
  }
  getGroupState(groupId: string) {
    return this.inner.getGroupState(groupId);
  }
  getTransitions(groupId: string, sinceEpoch?: number) {
    return this.inner.getTransitions(groupId, sinceEpoch);
  }
  getRecord(groupId: string, recordId: string) {
    // Reads leak identifiers just as writes do — a relay that is told
    // which record to return learns the same name either way.
    return this.inner.getRecord(groupId, this.capture(recordId));
  }
  listRecords(groupId: string) {
    return this.inner.listRecords(groupId);
  }
  getBackupBlob(handle: string) {
    return this.inner.getBackupBlob(this.capture(handle));
  }

  /** Everything the relay was handed, as one searchable string. */
  captured(): string {
    return JSON.stringify(this.sent);
  }

  /** Just the transitions, for shape comparisons. */
  transitions(): WireTransition[] {
    return this.sent.filter(
      (value): value is WireTransition =>
        typeof value === "object" && value !== null && "sealed_body" in value,
    );
  }
}

describe("no secret ever crosses the Transport port (spec §12, §5.1)", () => {
  it("survives a full lifecycle with every secret withheld", async () => {
    const inner = new MockTransport();
    const transport = new RecordingTransport(inner);
    const aliceStorage = new MemoryStore();
    const bobStorage = new MemoryStore();

    const options = (userId: string, storage: MemoryStore) => ({
      transport,
      userId,
      crypto,
      storage,
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });

    // --- exercise essentially everything ---
    const alice = await GroupVault.open(options("alice", aliceStorage));
    const credential = await completeEnrollment(alice);
    const bob = await GroupVault.open(options("bob", bobStorage));
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    const plaintext = { title: "quarterly numbers", secret: "PLAINTEXT-CANARY" };
    await alice.putJsonRecord(g, "doc-1", plaintext);
    await alice.addMember(g, { userId: "bob", devicePubkey: bob.devicePublicKey() });
    await bob.syncGroup(g);
    await alice.promoteMember(g, "bob");
    await bob.syncGroup(g);

    // Device linking, so add_device traffic is covered too.
    const phoneStorage = new MemoryStore();
    const phone = await GroupVault.open(options("alice", phoneStorage));
    await alice.linkDevice(phone.devicePublicKey());

    await alice.putRecordBytes(g, "doc-2", new TextEncoder().encode("BYTES-CANARY"));
    await alice.removeMember(g, "bob");
    await alice.setPolicy(g, { min_managers: 1 });

    // --- collect what must never appear ---
    const secretsByEpoch = await aliceStorage.getGroupSecrets(g);
    expect(secretsByEpoch.size).toBeGreaterThan(1); // several epochs happened

    const identity = await aliceStorage.getIdentity();
    const aliceKeys = await km.deviceKeysFromIdentity(
      identity?.identityPrivateKey ?? new Uint8Array(32),
    );

    const forbidden: { label: string; needles: string[] }[] = [
      {
        label: "record plaintext",
        needles: ["PLAINTEXT-CANARY", "BYTES-CANARY", "quarterly numbers"],
      },
      {
        label: "recovery credential",
        needles: [credential],
      },
      {
        label: "identity private key (Ed25519)",
        needles: [bytesToBase64Url(aliceKeys.identity.privateKey)],
      },
      {
        label: "device private key (X25519)",
        needles: [bytesToBase64Url(aliceKeys.encryption.privateKey)],
      },
      ...[...secretsByEpoch.entries()].map(([epoch, secret]) => ({
        label: `group_secret for epoch ${String(epoch)}`,
        needles: [bytesToBase64Url(secret)],
      })),
    ];

    // --- search everything the backend was handed ---
    expect(transport.sent.length).toBeGreaterThan(5);
    const traffic = JSON.stringify(transport.sent);
    for (const { label, needles } of forbidden) {
      for (const needle of needles) {
        expect(
          traffic.includes(needle),
          `${label} leaked to the backend (spec §12)`,
        ).toBe(false);
      }
    }

    // Also check the raw-byte spelling, in case something ever ships a
    // secret in some encoding other than base64url.
    const asChars = (bytes: Uint8Array): string =>
      Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
    for (const [epoch, secret] of secretsByEpoch) {
      expect(
        traffic.includes(asChars(secret)),
        `raw bytes of group_secret ${String(epoch)} leaked (spec §12)`,
      ).toBe(false);
    }
  });

  it("proves the search would actually catch a leak", async () => {
    // A canary: the assertions above only mean something if a planted
    // secret is genuinely detected by the same matching logic.
    const inner = new MockTransport();
    const transport = new RecordingTransport(inner);
    const storage = new MemoryStore();
    const vault = await GroupVault.open({
      transport,
      userId: "alice",
      crypto,
      storage,
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;

    const secret = (await storage.getGroupSecrets(g)).get(0);
    if (secret === undefined) throw new Error("expected an epoch-0 secret");

    // Simulate a defect that puts the group secret on the wire.
    await transport.putRecord(g, {
      record_id: "leaky",
      epoch: 0,
      ciphertext: bytesToBase64Url(secret),
      nonce: "n",
      suite: "gv1",
    });

    expect(JSON.stringify(transport.sent)).toContain(bytesToBase64Url(secret));
  });
});

// ---------------------------------------------------------------------------
// Metadata minimization (spec §5.8, §10.2).
// ---------------------------------------------------------------------------

describe("metadata withheld from the relay (spec §5.8)", () => {
  it("hands the relay no identity, device key, action, or policy", async () => {
    const recorder = new RecordingTransport(new MockTransport());
    const opts = (userId: string) => ({
      transport: recorder,
      userId,
      crypto,
      storage: new MemoryStore(),
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    const alice = await GroupVault.open(opts("alice-hr-lead"));
    const credential = await completeEnrollment(alice);
    const bob = await GroupVault.open(opts("bob-contractor"));
    await completeEnrollment(bob);

    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(g, {
      userId: "bob-contractor",
      devicePubkey: bob.devicePublicKey(),
    });
    await alice.putJsonRecord(g, "q3-layoff-plan", { headcount: 12 });
    await alice.getJsonRecord(g, "q3-layoff-plan"); // the read path too
    await alice.removeMember(g, "bob-contractor");

    const seen = recorder.captured();

    // Identities: neither user id reaches the relay, in any spelling.
    expect(seen).not.toContain("alice-hr-lead");
    expect(seen).not.toContain("bob-contractor");
    // Device keys: the most linkable value in the protocol (spec §6.5).
    expect(seen).not.toContain(alice.devicePublicKey());
    expect(seen).not.toContain(bob.devicePublicKey());
    // Governance: the relay cannot tell an add from a remove.
    for (const action of ["create", "add", "remove", "promote", "set_policy"]) {
      expect(seen).not.toContain(`"action":"${action}"`);
    }
    // Policy and membership structure.
    expect(seen).not.toContain("min_managers");
    expect(seen).not.toContain("is_manager");
    expect(seen).not.toContain("envelope_slots");
    // The credential must never leave the device at all.
    expect(seen).not.toContain(credential);

    // Chain structure: the hash link and the signature are inner fields
    // now (spec §6.5). A relay holding them could still order and
    // attribute governance without reading it.
    for (const field of [
      "prev_transition_hash",
      "signed_by",
      "signature",
      "members",
      "device_pubkeys",
      "user_id",
      "history_link",
    ]) {
      expect(seen, `${field} reached the relay`).not.toContain(field);
    }

    // Record identifiers must be derived, not the application's own key
    // — a filename discloses the content before any cryptography is
    // involved (spec §5.8 rule 2, §6.5).
    expect(seen).not.toContain("q3-layoff-plan");

    // Timestamps: `created_at` was removed, and nothing
    // else may reintroduce a wall-clock value the relay can correlate.
    expect(seen).not.toContain("created_at");
    expect(seen).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
  });

  it("leaks none of the above in a raw-byte spelling either", async () => {
    // base64url is what the wire uses today, but a defect that shipped
    // metadata some other way would slip past a base64url-only search.
    const recorder = new RecordingTransport(new MockTransport());
    const alice = await GroupVault.open({
      transport: recorder,
      userId: "alice-hr-lead",
      crypto,
      storage: new MemoryStore(),
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    await completeEnrollment(alice);
    const g = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.putJsonRecord(g, "q3-layoff-plan", { headcount: 12 });

    // A value that IS base64url-wrapped metadata, planted so the
    // decoding pass below has something it must find. Without it, every
    // negative assertion here would pass just as happily against a
    // decoder that silently produced nothing.
    const canary = "CANARY-METADATA-VALUE";
    await recorder.putRecord(g, {
      record_id: "r",
      epoch: 0,
      ciphertext: bytesToBase64Url(new TextEncoder().encode(canary)),
      nonce: "n",
      suite: "gv1",
    });

    // Decode every base64url-looking token the relay was handed and
    // search the decoded bytes, so an identifier hidden inside an
    // opaque-looking blob is still caught.
    const seen = recorder.captured();
    const decoded = (seen.match(/[A-Za-z0-9_-]{16,}/g) ?? [])
      .map((token) => {
        try {
          return utf8String(base64UrlToBytes(token));
        } catch {
          return "";
        }
      })
      .join(" ");

    expect(decoded, "the decoding pass found nothing at all").toContain(canary);
    for (const needle of ["alice-hr-lead", "q3-layoff-plan", "min_managers", "user_id"]) {
      expect(decoded, `${needle} recoverable from relay traffic`).not.toContain(needle);
    }
  });

  it("proves the metadata search would actually catch a leak", async () => {
    // The assertions above are all negative, so they would pass just as
    // happily against an empty string. This plants each class of
    // metadata in the traffic and requires the same matcher to find it.
    const recorder = new RecordingTransport(new MockTransport());
    const vault = await GroupVault.open({
      transport: recorder,
      userId: "alice-hr-lead",
      crypto,
      storage: new MemoryStore(),
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    await completeEnrollment(vault);
    const g = (await vault.createGroup({ min_managers: 1 })).group_id;

    // Modelled as extra *fields*, which is how a real regression would
    // arrive — a plaintext value stuffed into a string would be escaped
    // by JSON.stringify and would not exercise the same matching.
    await recorder.putRecord(g, {
      record_id: "q3-layoff-plan",
      epoch: 0,
      ciphertext: "x",
      nonce: "n",
      suite: "gv1",
      action: "remove",
      user_id: "alice-hr-lead",
      created_at: "2026-08-04T11:00:00Z",
    } as unknown as EncryptedRecord);

    const seen = recorder.captured();
    expect(seen).toContain("alice-hr-lead");
    expect(seen).toContain("q3-layoff-plan");
    expect(seen).toContain("user_id");
    expect(seen).toContain('"action":"remove"');
    expect(seen).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
  });

  it("makes every transition the same shape, whatever it did", async () => {
    const recorder = new RecordingTransport(new MockTransport());
    const opts = (userId: string) => ({
      transport: recorder,
      userId,
      crypto,
      storage: new MemoryStore(),
      locks: new InProcessLockProvider(),
      requestPersistentStorage: false,
      backup: FAST_BACKUP,
    });
    const alice = await GroupVault.open(opts("alice"));
    await completeEnrollment(alice);
    const bob = await GroupVault.open(opts("bob"));
    await completeEnrollment(bob);

    const shape = (await alice.createGroup({ min_managers: 1 })).group_id;
    await alice.addMember(shape, {
      userId: "bob",
      devicePubkey: bob.devicePublicKey(),
    });
    await alice.setPolicy(shape, { min_managers: 1 });
    await alice.removeMember(shape, "bob");

    const wires = recorder.transitions().filter((t) => t.epoch > 0);
    expect(wires.length).toBeGreaterThanOrEqual(3);

    // An add, a policy change and a removal are byte-identical in
    // shape: same envelope count, same body length, same notice length.
    const shapes = new Set(
      wires.map((t) =>
        [
          t.secret_envelopes.length,
          t.sealed_body.length,
          (t.removal_notice ?? "").length,
        ].join(":"),
      ),
    );
    expect(shapes.size).toBe(1);
  });
});
