/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Group operations are blocked pre-enrollment, and
 * the lose-device → restore → resync flow recovers the same identity
 * and full group access.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import {
  BackupError,
  BackupRequiredError,
  StorageError,
} from "../src/core/errors";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { RecordCrypto } from "../src/core/record-crypto";
import {
  ARGON2ID_PARAMS,
  BackupManager,
  PBKDF2_ITERATIONS,
  type BackupManagerOptions,
} from "../src/managers/backup-manager";
import { GroupManager } from "../src/managers/group-manager";
import { SyncManager } from "../src/managers/sync-manager";
import type { CryptoProvider } from "../src/ports/crypto-provider";
import type { Transport } from "../src/ports/transport";
import {
  completeBackupEnrollment,
  FAST_BACKUP,
  MemoryKeyUsageStore,
  backupHandleFor,
} from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);
const TEST_ITERATIONS = must(FAST_BACKUP.kdfIterations, "FAST_BACKUP.kdfIterations");
const TEST_ARGON2 = must(FAST_BACKUP.argon2Params, "FAST_BACKUP.argon2Params");

function must<T>(value: T | undefined, what = "value"): T {
  if (value === undefined) throw new Error(`missing ${what}`);
  return value;
}

interface Device {
  userId: string;
  keys: DeviceKeys;
  storage: MemoryStore;
  backup: BackupManager;
  manager: GroupManager;
}

async function makeDevice(
  userId: string,
  transport: Transport,
  options: { enroll?: boolean; backup?: BackupManagerOptions } = {},
): Promise<Device & { credential?: string }> {
  const keys = await km.generateDeviceKeys();
  const storage = new MemoryStore();
  await storage.putIdentity({
    userId,
    identityPrivateKey: keys.identity.privateKey,
    backupEnrolled: false,
  });
  const backup = new BackupManager(
    crypto,
    storage,
    new SyncManager(transport),
    options.backup ?? FAST_BACKUP,
  );
  const manager = new GroupManager({
    crypto,
    storage,
    transport,
    locks: new InProcessLockProvider(),
    deviceKeys: keys,
    userId,
  });
  const credential =
    options.enroll === false ? undefined : await completeBackupEnrollment(backup);
  return credential === undefined
    ? { userId, keys, storage, backup, manager }
    : { userId, keys, storage, backup, manager, credential };
}

describe("mandatory enrollment gate (spec §9.6)", () => {
  it("blocks every group operation until enrollment completes", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport, { enroll: false });
    // The gate refuses before any group can be created, so there is no
    // generated id to use here — these calls address nothing on purpose.
    const g = "not-a-group";

    expect(await device.backup.isEnrolled()).toBe(false);
    await expect(
      device.manager.createGroup({ min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);
    await expect(device.manager.syncGroup(g)).rejects.toBeInstanceOf(
      BackupRequiredError,
    );
    await expect(
      device.manager.setPolicy(g, { min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);

    const credential = await device.backup.enroll();
    expect(credential.length).toBeGreaterThanOrEqual(22); // >= 128 bits

    // spec §9.6: issuing the credential is phase one. The gate stays
    // shut until the user confirms they stored it — otherwise a host
    // that dropped the string would leave an enrolled device whose
    // backup nobody can open, the exact failure §9.6 forbids.
    expect(await device.backup.isEnrolled()).toBe(false);
    await expect(
      device.manager.createGroup({ min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);

    await device.backup.confirmEnrollment(credential);
    expect(await device.backup.isEnrolled()).toBe(true);
    await expect(
      device.manager.createGroup({ min_managers: 1 }),
    ).resolves.toMatchObject({ epoch: 0 });
  });

  it("refuses to confirm with a credential that cannot open the backup", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport, { enroll: false });
    await device.backup.enroll();

    await expect(
      device.backup.confirmEnrollment("not-the-credential"),
    ).rejects.toBeInstanceOf(BackupError);
    // The gate must remain shut after a failed confirmation.
    expect(await device.backup.isEnrolled()).toBe(false);
    await expect(
      device.manager.createGroup({ min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);
  });

  it("blocks operations when no identity exists at all", async () => {
    const transport = new MockTransport();
    const keys = await km.generateDeviceKeys();
    const manager = new GroupManager({
      crypto,
      storage: new MemoryStore(),
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: keys,
      userId: "ghost",
    });
    await expect(
      manager.createGroup({ min_managers: 1 }),
    ).rejects.toBeInstanceOf(BackupRequiredError);
  });
});

describe("enrollment", () => {
  it("uploads a suite-tagged blob with its KDF parameters (spec §6.2)", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);

    const blob = await transport.getBackupBlob(
      await backupHandleFor(crypto, must(device.credential)),
    );
    expect(blob.suite).toBe("gv1");
    // Argon2id is the primary KDF (spec §6.2) — the default here.
    expect(blob.kdf).toBe("argon2id");
    expect(blob.kdf_params).toEqual({
      iterations: TEST_ARGON2.iterations,
      memory_kib: TEST_ARGON2.memoryKiB,
      parallelism: TEST_ARGON2.parallelism,
    });
    expect(blob.salt.length).toBeGreaterThan(0);
  });

  it("cannot enroll twice or without an identity", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);
    await expect(device.backup.enroll()).rejects.toBeInstanceOf(BackupError);

    const bare = new BackupManager(
      crypto,
      new MemoryStore(),
      new SyncManager(transport),
      { kdfIterations: TEST_ITERATIONS },
    );
    await expect(bare.enroll()).rejects.toBeInstanceOf(StorageError);
  });
});

describe("restore", () => {
  it("recovers the exact identity onto a fresh device", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);

    const freshStorage = new MemoryStore();
    const restorer = new BackupManager(crypto, freshStorage, new SyncManager(transport));
    const identity = await restorer.restore("alice", must(device.credential));

    expect(identity.backupEnrolled).toBe(true);
    expect(identity.identityPrivateKey).toEqual(device.keys.identity.privateKey);
    const rebuilt = await km.deviceKeysFromIdentity(identity.identityPrivateKey);
    expect(km.devicePublicKey(rebuilt)).toBe(km.devicePublicKey(device.keys));
  });

  it("rejects wrong credentials, tampering, and foreign formats", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);
    const restorer = new BackupManager(crypto, new MemoryStore(), new SyncManager(transport));

    await expect(restorer.restore("alice", "wrong-credential")).rejects.toBeInstanceOf(
      BackupError,
    );

    const blob = await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)));
    const flip = (s: string) => (s.startsWith("A") ? `B${s.slice(1)}` : `A${s.slice(1)}`);
    await transport.putBackupBlob(
      await backupHandleFor(crypto, must(device.credential)),
      { ...blob, ciphertext: flip(blob.ciphertext) },
    );
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);

    // Relabelling the KDF cannot help: the key would be derived by a
    // different function than the one that sealed the blob.
    await transport.putBackupBlob("alice", { ...blob, kdf: "pbkdf2-sha256" });
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);

    // An unknown KDF is refused rather than guessed at. (A backend can
    // send any string here, hence the deliberate widening.)
    const unknownKdf = "scrypt" as string;
    await transport.putBackupBlob("alice", {
      ...blob,
      kdf: unknownKdf,
    } as typeof blob);
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);

    // An Argon2id blob missing its memory/parallelism costs is refused.
    await transport.putBackupBlob("alice", {
      ...blob,
      kdf_params: { iterations: blob.kdf_params.iterations },
    });
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);

    await transport.putBackupBlob(
      await backupHandleFor(crypto, must(device.credential)),
      { ...blob, suite: "gv9" },
    );
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);

    // The handle derives from the credential alone, so a wrong user id
    // still *finds* the blob (spec §6.5) — the relay has no idea whose
    // it is. What stops the restore is the AAD, which binds the real
    // user id: you cannot adopt someone else's backup under your own
    // name.
    await expect(
      restorer.restore("nobody", must(device.credential)),
    ).rejects.toBeInstanceOf(BackupError);
  });

  it("honors the KDF parameters stored in the blob, not local config", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport); // enrolled at TEST_ARGON2
    const restorer = new BackupManager(
      crypto,
      new MemoryStore(),
      new SyncManager(transport),
      // Deliberately different local costs — the blob's must win, or
      // this would take 19 MiB × 2 and derive the wrong key anyway.
      { argon2Params: ARGON2ID_PARAMS, kdfIterations: 7777 },
    );
    await expect(
      restorer.restore("alice", must(device.credential)),
    ).resolves.toMatchObject({ userId: "alice" });
  });
});

describe("refresh", () => {
  it("verifies the credential before overwriting — a typo cannot destroy the backup", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);
    const before = await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)));

    await expect(device.backup.refresh("wrong-credential")).rejects.toBeInstanceOf(
      BackupError,
    );
    expect((await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)))).ciphertext).toBe(before.ciphertext);
  });

  it("snapshots current secrets so restore works even without resync", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport);
    const g = (await device.manager.createGroup({ min_managers: 1 })).group_id;
    await device.backup.refresh(must(device.credential));

    const freshStorage = new MemoryStore();
    const restorer = new BackupManager(crypto, freshStorage, new SyncManager(transport));
    await restorer.restore("alice", must(device.credential));
    expect(await freshStorage.getGroupSecret(g, 0)).toEqual(
      await device.storage.getGroupSecret(g, 0),
    );
  });
});

describe("lose device → restore → resync", () => {
  it("recovers identity, group access, and manager authority from a pre-group backup", async () => {
    const transport = new MockTransport();
    const records = new RecordCrypto(crypto, new MemoryKeyUsageStore());
    const sync = new SyncManager(transport);

    // Enrollment happens FIRST (spec §9.6) — the blob predates the
    // group entirely, so recovery of its secrets must come from the
    // §9.7 history chain, not from the snapshot.
    const alice = await makeDevice("alice", transport);
    const bob = await makeDevice("bob", transport);

    const g = (await alice.manager.createGroup({ min_managers: 1 })).group_id;
    await alice.manager.addMember(g, {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob.keys)],
      is_manager: false,
    });
    await bob.manager.syncGroup(g);

    const secret1 = must(await alice.manager.getCurrentSecret(g));
    await sync.putRecord(
      g,
      await records.encryptJsonRecord(g, 1, secret1, "doc", { vital: "data" }),
    );

    // 💥 The device is lost: all local state is gone.
    const freshStorage = new MemoryStore();
    const restorer = new BackupManager(crypto, freshStorage, new SyncManager(transport));
    const identity = await restorer.restore("alice", must(alice.credential));
    const recoveredKeys = await km.deviceKeysFromIdentity(identity.identityPrivateKey);
    expect(km.devicePublicKey(recoveredKeys)).toBe(km.devicePublicKey(alice.keys));

    const recovered = new GroupManager({
      crypto,
      storage: freshStorage,
      transport,
      locks: new InProcessLockProvider(),
      deviceKeys: recoveredKeys,
      userId: "alice",
    });
    expect((await recovered.start()).size).toBe(0); // nothing local
    const state = await recovered.syncGroup(g);
    expect(state).toEqual(bob.manager.getState(g));

    // Secrets recovered through the head envelope + history chain.
    expect(await freshStorage.getGroupSecret(g, 0)).toBeDefined();
    const fetched = await sync.getRecord(g, "doc");
    const recordSecret = must(await freshStorage.getGroupSecret(g, fetched.epoch));
    expect(await records.decryptJsonRecord(g, recordSecret, fetched)).toEqual({
      vital: "data",
    });

    // Same identity ⇒ same manager authority.
    await expect(
      recovered.setPolicy(g, { min_managers: 1 }),
    ).resolves.toMatchObject({ epoch: 2 });
    await expect(bob.manager.syncGroup(g)).resolves.toMatchObject({ epoch: 2 });
  });
});

// ---------------------------------------------------------------------------
// Argon2id as the primary backup KDF (spec §6.2).
// ---------------------------------------------------------------------------

describe("KDF selection (spec §6.2)", () => {
  /** A provider without Argon2id — spec §6.2's fallback environment. */
  function withoutArgon2(): CryptoProvider {
    const provider = new WebCryptoProvider();
    // Structural omission, exactly as the optional port method allows.
    return new Proxy(provider, {
      get: (target, property, receiver) =>
        property === "argon2id"
          ? undefined
          : (Reflect.get(target, property, receiver) as unknown),
    });
  }

  it("defaults to Argon2id when the provider implements it", () => {
    const manager = new BackupManager(
      crypto,
      new MemoryStore(),
      new SyncManager(new MockTransport()),
    );
    expect(manager.activeKdf).toBe("argon2id");
  });

  it("falls back to PBKDF2 when the provider omits Argon2id", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport, { enroll: false });
    const fallback = new BackupManager(
      withoutArgon2(),
      device.storage,
      new SyncManager(transport),
      { kdfIterations: TEST_ITERATIONS },
    );
    expect(fallback.activeKdf).toBe("pbkdf2-sha256");

    const credential = await fallback.enroll();
    const blob = await transport.getBackupBlob(await backupHandleFor(crypto, credential));
    expect(blob.kdf).toBe("pbkdf2-sha256");
    expect(blob.kdf_params).toEqual({ iterations: TEST_ITERATIONS });
    await expect(
      new BackupManager(
        withoutArgon2(),
        new MemoryStore(),
        new SyncManager(transport),
      ).restore("alice", credential),
    ).resolves.toMatchObject({ userId: "alice" });
  });

  it("refuses an explicit Argon2id request the provider cannot satisfy", () => {
    expect(
      () =>
        new BackupManager(
          withoutArgon2(),
          new MemoryStore(),
          new SyncManager(new MockTransport()),
          { kdf: "argon2id" },
        ),
    ).toThrow(BackupError);
  });

  it("uses the spec §6.2 baseline parameters by default", async () => {
    // Real cost, so this asserts the shipped default, not a test value.
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport, {
      enroll: false,
      backup: {},
    });
    const credential = await device.backup.enroll();

    const blob = await transport.getBackupBlob(await backupHandleFor(crypto, credential));
    expect(blob.kdf).toBe("argon2id");
    expect(blob.kdf_params).toEqual({
      iterations: ARGON2ID_PARAMS.iterations,
      memory_kib: ARGON2ID_PARAMS.memoryKiB,
      parallelism: ARGON2ID_PARAMS.parallelism,
    });
    expect(blob.kdf_params.memory_kib).toBeGreaterThanOrEqual(19_456);

    await expect(
      new BackupManager(crypto, new MemoryStore(), new SyncManager(transport)).restore(
        "alice",
        credential,
      ),
    ).resolves.toMatchObject({ userId: "alice" });
  }, 30_000);

  it("keeps PBKDF2's default at the spec §6.2 minimum", () => {
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(600_000);
  });
});

describe("backup round-trips under both KDFs", () => {
  for (const kdf of ["argon2id", "pbkdf2-sha256"] as const) {
    it(`round-trips a full enroll → restore under ${kdf}`, async () => {
      const transport = new MockTransport();
      const device = await makeDevice("alice", transport, {
        backup: { ...FAST_BACKUP, kdf },
      });
      expect((await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)))).kdf).toBe(kdf);

      const g = (await device.manager.createGroup({ min_managers: 1 })).group_id;
      await device.backup.refresh(must(device.credential));

      const freshStorage = new MemoryStore();
      const identity = await new BackupManager(
        crypto,
        freshStorage,
        new SyncManager(transport),
      ).restore("alice", must(device.credential));

      expect(identity.identityPrivateKey).toEqual(device.keys.identity.privateKey);
      expect(await freshStorage.getGroupSecret(g, 0)).toEqual(
        await device.storage.getGroupSecret(g, 0),
      );
    });
  }

  it("opens a legacy PBKDF2 blob on an Argon2id-default client — no migration", async () => {
    const transport = new MockTransport();
    // A device enrolled before Argon2id support: PBKDF2 blob on the backend.
    const legacy = await makeDevice("alice", transport, {
      backup: { kdf: "pbkdf2-sha256", kdfIterations: TEST_ITERATIONS },
    });
    expect(
      (await transport.getBackupBlob(await backupHandleFor(crypto, must(legacy.credential))))
        .kdf,
    ).toBe("pbkdf2-sha256");

    // A client whose own default is Argon2id restores it fine,
    // because the KDF travels with the blob (spec §6.2).
    const modern = new BackupManager(
      crypto,
      new MemoryStore(),
      new SyncManager(transport),
      FAST_BACKUP,
    );
    expect(modern.activeKdf).toBe("argon2id");
    await expect(
      modern.restore("alice", must(legacy.credential)),
    ).resolves.toMatchObject({ userId: "alice" });
  });

  it("re-seals a legacy PBKDF2 blob under Argon2id on refresh", async () => {
    const transport = new MockTransport();
    const device = await makeDevice("alice", transport, {
      backup: { kdf: "pbkdf2-sha256", kdfIterations: TEST_ITERATIONS },
    });
    const credential = must(device.credential);
    expect((await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)))).kdf).toBe("pbkdf2-sha256");

    // Same storage/credential, but a manager that prefers Argon2id.
    const upgraded = new BackupManager(
      crypto,
      device.storage,
      new SyncManager(transport),
      FAST_BACKUP,
    );
    await upgraded.refresh(credential);

    expect((await transport.getBackupBlob(await backupHandleFor(crypto, must(device.credential)))).kdf).toBe("argon2id");
    await expect(
      new BackupManager(crypto, new MemoryStore(), new SyncManager(transport)).restore(
        "alice",
        credential,
      ),
    ).resolves.toMatchObject({ userId: "alice" });
  });
});
