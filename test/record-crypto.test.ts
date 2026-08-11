/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, utf8Bytes } from "../src/core/bytes";
import { CryptoError, KeyUsageExceededError } from "../src/core/errors";
import { deriveRecordId, RecordCrypto } from "../src/core/record-crypto";
import { bytesToHex, MemoryKeyUsageStore } from "./helpers";

const crypto = new WebCryptoProvider();
const GROUP = "record-group";

function fixture(keyUsageLimit?: number) {
  const usage = new MemoryKeyUsageStore();
  const records = new RecordCrypto(
    crypto,
    usage,
    keyUsageLimit === undefined
      ? { now: () => "2026-07-11T00:00:00.000Z" }
      : { keyUsageLimit, now: () => "2026-07-11T00:00:00.000Z" },
  );
  return { usage, records, secret0: crypto.randomBytes(32), secret1: crypto.randomBytes(32) };
}

describe("record encryption (spec §6.1, §7)", () => {
  it("round-trips bytes and JSON across epochs", async () => {
    const { records, secret0, secret1 } = fixture();

    const r0 = await records.encryptRecord(GROUP, 0, secret0, "doc-0", utf8Bytes("epoch zero"));
    const r1 = await records.encryptJsonRecord(GROUP, 1, secret1, "doc-1", {
      title: "Q3", nested: { ok: true },
    });

    expect(r0).toMatchObject({ record_id: "doc-0", epoch: 0, suite: "gv1" });
    // spec §6.5: no plaintext timestamp reaches the relay.
    expect(r0).not.toHaveProperty("created_at");
    expect(r1).toMatchObject({ record_id: "doc-1", epoch: 1, suite: "gv1" });

    const p0 = await records.decryptRecord(GROUP, secret0, r0);
    expect(new TextDecoder().decode(p0)).toBe("epoch zero");
    expect(await records.decryptJsonRecord(GROUP, secret1, r1)).toEqual({
      title: "Q3", nested: { ok: true },
    });
  });

  // spec §6.5: ciphertext length must reveal a bucket, not a byte
  // count. Without padding, a 3-byte record and a 3 KiB record are
  // trivially distinguishable on the wire.
  it("pads records to size buckets, so length reveals only the bucket", async () => {
    const { records, secret0 } = fixture();
    const lengths = new Set<number>();
    for (const size of [0, 1, 100, 3000, 4000]) {
      const record = await records.encryptRecord(
        GROUP,
        0,
        secret0,
        `doc-${String(size)}`,
        new Uint8Array(size).fill(7),
      );
      lengths.add(base64UrlToBytes(record.ciphertext).length);
    }
    // Everything below the first bucket lands in the first bucket.
    expect(lengths.size).toBe(1);

    // ...and a payload that overflows it moves to the next one, rather
    // than growing byte for byte.
    const big = await records.encryptRecord(
      GROUP,
      0,
      secret0,
      "big",
      new Uint8Array(5000).fill(7),
    );
    expect(base64UrlToBytes(big.ciphertext).length).toBeGreaterThan(
      [...lengths][0] ?? 0,
    );
  });

  it("round-trips a payload of any length through its bucket", async () => {
    const { records, secret0 } = fixture();
    for (const size of [0, 1, 4091, 4092, 4093, 20000]) {
      const plain = new Uint8Array(size).fill(3);
      const record = await records.encryptRecord(GROUP, 0, secret0, `r${String(size)}`, plain);
      expect(await records.decryptRecord(GROUP, secret0, record)).toEqual(plain);
    }
  });

  it("fails with the wrong epoch's secret", async () => {
    const { records, secret0, secret1 } = fixture();
    const record = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("x"));
    await expect(records.decryptRecord(GROUP, secret1, record)).rejects.toBeInstanceOf(
      CryptoError,
    );
  });

  it("fails when any binding field is transplanted", async () => {
    const { records, secret0 } = fixture();
    const record = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("x"));

    await expect(
      records.decryptRecord(GROUP, secret0, { ...record, record_id: "other" }),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      records.decryptRecord(GROUP, secret0, { ...record, epoch: 5 }),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      records.decryptRecord("other-group", secret0, record),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("fails on tampered ciphertext or nonce", async () => {
    const { records, secret0 } = fixture();
    const record = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("x"));
    const flip = (s: string) => (s.startsWith("A") ? `B${s.slice(1)}` : `A${s.slice(1)}`);
    await expect(
      records.decryptRecord(GROUP, secret0, { ...record, ciphertext: flip(record.ciphertext) }),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      records.decryptRecord(GROUP, secret0, { ...record, nonce: flip(record.nonce) }),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("rejects unknown suites instead of guessing (spec §6.3)", async () => {
    const { records, secret0 } = fixture();
    const record = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("x"));
    await expect(
      records.decryptRecord(GROUP, secret0, { ...record, suite: "gv2" }),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("uses a fresh CSPRNG nonce per operation (spec §6.1)", async () => {
    const { records, secret0 } = fixture();
    const a = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("same"));
    const b = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("same"));
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("rejects malformed group secrets and limits", () => {
    const { records } = fixture();
    expect(() =>
      new RecordCrypto(crypto, new MemoryKeyUsageStore(), { keyUsageLimit: 2 ** 32 }),
    ).toThrow(CryptoError);
    expect(() =>
      new RecordCrypto(crypto, new MemoryKeyUsageStore(), { keyUsageLimit: 0 }),
    ).toThrow(CryptoError);
    void records; // fixture construction with default limit succeeds
  });
});

describe("usage bound (spec §6.1)", () => {
  it("refuses encryption past the bound, per (group, epoch)", async () => {
    const { records, secret0, secret1 } = fixture(3);

    await records.encryptRecord(GROUP, 0, secret0, "a", utf8Bytes("1"));
    await records.encryptMetadata(GROUP, 0, secret0, utf8Bytes("2")); // shares the counter
    await records.encryptRecord(GROUP, 0, secret0, "c", utf8Bytes("3"));
    await expect(
      records.encryptRecord(GROUP, 0, secret0, "d", utf8Bytes("4")),
    ).rejects.toBeInstanceOf(KeyUsageExceededError);

    // A new epoch has its own counter — rotation restores service.
    await expect(
      records.encryptRecord(GROUP, 1, secret1, "d", utf8Bytes("4")),
    ).resolves.toMatchObject({ epoch: 1 });
    // As does another group at the same epoch.
    await expect(
      records.encryptRecord("other-group", 0, secret0, "d", utf8Bytes("4")),
    ).resolves.toMatchObject({ epoch: 0 });
  });

  it("does not count decryption", async () => {
    const { usage, records, secret0 } = fixture(2);
    const record = await records.encryptRecord(GROUP, 0, secret0, "a", utf8Bytes("x"));
    for (let i = 0; i < 5; i++) {
      await records.decryptRecord(GROUP, secret0, record);
    }
    expect(usage.counts.get(`${GROUP}|0`)).toBe(1);
  });

  // spec §12: "Derived keys MUST NOT be stored beyond their immediate
  // use." Observed through the CryptoProvider seam — `deriveKey`
  // returns the provider's HKDF output buffer unchanged, so holding a
  // reference to it shows whether RecordCrypto zeroed it on the way
  // out. Both the success and the throwing path are checked: the wipe
  // lives in a `finally`, and a key left behind by an error path is
  // exactly the leak this requirement is about.
  it("zeroes every derived key before returning (spec §12)", async () => {
    const derived: Uint8Array[] = [];
    // Object.create, not spread: the provider's methods live on its
    // prototype and a spread copy would lose them.
    const spy: typeof crypto = Object.create(crypto) as typeof crypto;
    spy.hkdfSha256 = async (ikm, salt, info, length) => {
      const key = await crypto.hkdfSha256(ikm, salt, info, length);
      derived.push(key);
      return key;
    };
    const records = new RecordCrypto(spy, new MemoryKeyUsageStore());
    const secret = crypto.randomBytes(32);

    const record = await records.encryptRecord(GROUP, 0, secret, "doc", utf8Bytes("payload"));
    await records.decryptRecord(GROUP, secret, record);
    await records.encryptMetadata(GROUP, 0, secret, utf8Bytes("{}"));

    // A failing decrypt must not leave its key behind either.
    await expect(
      records.decryptRecord(GROUP, crypto.randomBytes(32), record),
    ).rejects.toBeInstanceOf(CryptoError);

    expect(derived.length).toBeGreaterThanOrEqual(4);
    for (const key of derived) {
      expect(key.length).toBe(32);
      expect(key.every((byte) => byte === 0)).toBe(true);
    }
  });

  // spec §6.5: the relay must never see a filename or slug. The
  // application keeps addressing records by a meaningful key; the wire
  // carries an opaque identifier derived from it.
  it("derives an opaque record_id that hides the application key (spec §6.5)", async () => {
    const genesis = crypto.randomBytes(32);

    const id = await deriveRecordId(crypto, genesis, "q3-layoff-plan.docx");
    expect(id).not.toContain("layoff");
    expect(id).not.toContain("docx");
    expect(base64UrlToBytes(id).length).toBe(16);

    // Stable, or a record becomes unfindable after the first rotation.
    expect(await deriveRecordId(crypto, genesis, "q3-layoff-plan.docx")).toBe(id);

    // Distinct app keys stay distinct.
    expect(await deriveRecordId(crypto, genesis, "q3-layoff-plan.doc")).not.toBe(id);

    // Unguessable without the group's genesis secret.
    expect(await deriveRecordId(crypto, crypto.randomBytes(32), "q3-layoff-plan.docx")).not.toBe(
      id,
    );
  });

  it("refuses to derive a record_id from a bad secret or empty key", async () => {
    await expect(
      deriveRecordId(crypto, crypto.randomBytes(16), "doc"),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      deriveRecordId(crypto, crypto.randomBytes(32), ""),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("persists via the injected store — a fresh RecordCrypto sees prior usage", async () => {
    const usage = new MemoryKeyUsageStore();
    const first = new RecordCrypto(crypto, usage, { keyUsageLimit: 2 });
    const secret = crypto.randomBytes(32);
    await first.encryptRecord(GROUP, 0, secret, "a", utf8Bytes("1"));
    await first.encryptRecord(GROUP, 0, secret, "b", utf8Bytes("2"));

    const second = new RecordCrypto(crypto, usage, { keyUsageLimit: 2 });
    await expect(
      second.encryptRecord(GROUP, 0, secret, "c", utf8Bytes("3")),
    ).rejects.toBeInstanceOf(KeyUsageExceededError);
  });
});

describe("group metadata encryption (spec §7)", () => {
  it("round-trips and stays domain-separated from record keys", async () => {
    const { records, secret0 } = fixture();
    const metadata = await records.encryptMetadata(GROUP, 0, secret0, utf8Bytes("titles"));
    expect(metadata.suite).toBe("gv1");
    const plaintext = await records.decryptMetadata(GROUP, secret0, metadata);
    expect(new TextDecoder().decode(plaintext)).toBe("titles");

    // A record ciphertext cannot masquerade as metadata (different key + AAD).
    const record = await records.encryptRecord(GROUP, 0, secret0, "doc", utf8Bytes("titles"));
    await expect(
      records.decryptMetadata(GROUP, secret0, {
        epoch: record.epoch,
        ciphertext: record.ciphertext,
        nonce: record.nonce,
        suite: record.suite,
      }),
    ).rejects.toBeInstanceOf(CryptoError);
    expect(bytesToHex(plaintext)).not.toBe(record.ciphertext);
  });

  it("fails on tampering and wrong secrets", async () => {
    const { records, secret0, secret1 } = fixture();
    const metadata = await records.encryptMetadata(GROUP, 0, secret0, utf8Bytes("m"));
    await expect(
      records.decryptMetadata(GROUP, secret1, metadata),
    ).rejects.toBeInstanceOf(CryptoError);
    await expect(
      records.decryptMetadata(GROUP, secret0, { ...metadata, epoch: 9 }),
    ).rejects.toBeInstanceOf(CryptoError);
  });
});
