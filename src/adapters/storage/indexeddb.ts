/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * IndexedDB `StorageAdapter`: the default
 * browser persistence, one database per origin with the object stores
 * `identity` / `transitions` / `groups` / `secrets` / `key_usage` /
 * `records_meta`.
 *
 * Atomicity notes:
 * - `incrementKeyUsage` performs its read-modify-write inside a single
 *   `readwrite` transaction; IndexedDB serializes overlapping
 *   `readwrite` transactions across connections (and tabs), which is
 *   what makes the counter safe without an extra lock.
 * - `appendTransition` relies on `add()`'s native uniqueness
 *   constraint for its append-only guarantee.
 *
 * The whole database is subject to browser eviction unless persistent
 * storage is granted — the facade requests it during onboarding;
 * loss is recoverable only through backup (spec §9.6).
 */

import { StorageError } from "../../core/errors";
import type { GroupState } from "../../core/group-state";
import type { EncryptedRecord, WireTransition } from "../../core/types";
import type { StorageAdapter, StoredIdentity } from "../../ports/storage";

/**
 * v2 added `records_meta` and upgraded in place.
 *
 * **v3 is destructive, deliberately.** The metadata-minimization work changed the wire
 * format: stored transitions have no `sealed_body`, no `auth_pubkey`
 * and no `removal_notice`, and there is no way to synthesize them —
 * the sealed body would have to be encrypted under a secret the old
 * record never captured. Group data written by v1/v2 therefore cannot
 * be verified by this code at all, and keeping it would mean carrying
 * unreadable rows that fail replay at every startup.
 *
 * The upgrade drops the group stores and keeps `identity`. That
 * distinction matters: the identity key is what makes recovery
 * possible, so preserving it turns a destructive upgrade into an
 * ordinary resync for a member (their envelopes are re-fetched) rather
 * than an involuntary "lost device" needing the backup credential
 * (spec §9.6). `key_usage` goes too — its counters are meaningless
 * against secrets that no longer exist, and a stale counter would
 * under-count the nonce budget for a *new* epoch (spec §6.1).
 *
 * Pre-1.0 data was fictitious and disposable, so no migration path is
 * owed for it — but a host application must be told before adopting a
 * release that carries this upgrade.
 */
const DB_VERSION = 3;

/** Dropped and recreated by the v3 upgrade; `identity` is preserved. */
const VOLATILE_STORES = ["transitions", "groups", "secrets", "key_usage", "records_meta"];
const STORES = [
  "identity",
  "transitions",
  "groups",
  "secrets",
  "key_usage",
  "records_meta",
] as const;
const IDENTITY_KEY = "device";

export interface IndexedDbStoreOptions {
  /** Database name; default `"circlekey"`. */
  name?: string;
  /** Factory override (tests inject `fake-indexeddb`); default global. */
  factory?: IDBFactory;
}

export class IndexedDbStore implements StorageAdapter {
  private constructor(private readonly db: IDBDatabase) {}

  static open(options: IndexedDbStoreOptions = {}): Promise<IndexedDbStore> {
    // DOM types declare the global as always present; it is undefined
    // outside browsers unless a test injects a factory.
    const factory =
      options.factory ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (factory === undefined) {
      return Promise.reject(
        new StorageError("IndexedDB is unavailable in this environment"),
      );
    }
    return new Promise((resolve, reject) => {
      const request = factory.open(options.name ?? "circlekey", DB_VERSION);
      request.onupgradeneeded = (event) => {
        const db = request.result;
        // Anything written before v3 is in a wire format
        // this code cannot verify, so it is dropped rather than left to
        // fail replay forever. Identity survives (see above).
        if (event.oldVersion > 0 && event.oldVersion < 3) {
          for (const store of VOLATILE_STORES) {
            if (db.objectStoreNames.contains(store)) {
              db.deleteObjectStore(store);
            }
          }
        }
        for (const store of STORES) {
          if (!db.objectStoreNames.contains(store)) {
            db.createObjectStore(store);
          }
        }
      };
      request.onsuccess = () => {
        resolve(new IndexedDbStore(request.result));
      };
      request.onerror = () => {
        reject(toStorageError(request.error));
      };
    });
  }

  close(): void {
    this.db.close();
  }

  async getIdentity(): Promise<StoredIdentity | undefined> {
    const tx = this.db.transaction("identity", "readonly");
    const identity = await req<StoredIdentity | undefined>(
      tx.objectStore("identity").get(IDENTITY_KEY),
    );
    await done(tx);
    return identity;
  }

  async putIdentity(identity: StoredIdentity): Promise<void> {
    const tx = this.db.transaction("identity", "readwrite");
    tx.objectStore("identity").put(identity, IDENTITY_KEY);
    await done(tx);
  }

  async appendTransition(transition: WireTransition): Promise<void> {
    const tx = this.db.transaction("transitions", "readwrite");
    // add() enforces key uniqueness — the append-only guarantee.
    tx.objectStore("transitions").add(transition, [transition.group_id, transition.epoch]);
    try {
      await done(tx);
    } catch (error) {
      if (error instanceof StorageError && error.message.includes("ConstraintError")) {
        throw new StorageError(
          `transition for ${transition.group_id} epoch ${String(transition.epoch)} already stored — history is append-only`,
        );
      }
      throw error;
    }
  }

  async getTransitions(groupId: string): Promise<WireTransition[]> {
    const tx = this.db.transaction("transitions", "readonly");
    const transitions = await req<WireTransition[]>(
      tx.objectStore("transitions").getAll(groupRange(groupId)),
    );
    await done(tx);
    return transitions; // composite keys sort by epoch ascending
  }

  async listGroupIds(): Promise<string[]> {
    const tx = this.db.transaction("transitions", "readonly");
    const keys = await req<IDBValidKey[]>(tx.objectStore("transitions").getAllKeys());
    await done(tx);
    const ids = new Set<string>();
    for (const key of keys) {
      if (Array.isArray(key) && typeof key[0] === "string") ids.add(key[0]);
    }
    return [...ids];
  }

  async getGroupState(groupId: string): Promise<GroupState | undefined> {
    const tx = this.db.transaction("groups", "readonly");
    const state = await req<GroupState | undefined>(tx.objectStore("groups").get(groupId));
    await done(tx);
    return state;
  }

  async putGroupState(state: GroupState): Promise<void> {
    const tx = this.db.transaction("groups", "readwrite");
    tx.objectStore("groups").put(state, state.group_id);
    await done(tx);
  }

  async putGroupSecret(groupId: string, epoch: number, secret: Uint8Array): Promise<void> {
    const tx = this.db.transaction("secrets", "readwrite");
    const store = tx.objectStore("secrets");
    const existing = await req<Uint8Array | undefined>(store.get([groupId, epoch]));
    if (existing !== undefined) {
      if (sameBytes(existing, secret)) return; // idempotent no-op
      tx.abort();
      throw new StorageError(
        `conflicting group_secret for ${groupId} epoch ${String(epoch)}`,
      );
    }
    store.put(secret, [groupId, epoch]);
    await done(tx);
  }

  async getGroupSecret(groupId: string, epoch: number): Promise<Uint8Array | undefined> {
    const tx = this.db.transaction("secrets", "readonly");
    const secret = await req<Uint8Array | undefined>(
      tx.objectStore("secrets").get([groupId, epoch]),
    );
    await done(tx);
    return secret;
  }

  async getGroupSecrets(groupId: string): Promise<Map<number, Uint8Array>> {
    const tx = this.db.transaction("secrets", "readonly");
    const store = tx.objectStore("secrets");
    const range = groupRange(groupId);
    const keys = await req<IDBValidKey[]>(store.getAllKeys(range));
    const values = await req<Uint8Array[]>(store.getAll(range));
    await done(tx);
    const secrets = new Map<number, Uint8Array>();
    keys.forEach((key, index) => {
      const value = values[index];
      if (Array.isArray(key) && typeof key[1] === "number" && value !== undefined) {
        secrets.set(key[1], value);
      }
    });
    return secrets;
  }

  async incrementKeyUsage(groupId: string, epoch: number): Promise<number> {
    // Single readwrite transaction = atomic read-modify-write, also
    // across tabs.
    const tx = this.db.transaction("key_usage", "readwrite");
    const store = tx.objectStore("key_usage");
    const current = await req<number | undefined>(store.get([groupId, epoch]));
    const next = (current ?? 0) + 1;
    store.put(next, [groupId, epoch]);
    await done(tx);
    return next;
  }

  async putCachedRecord(groupId: string, record: EncryptedRecord): Promise<void> {
    const tx = this.db.transaction("records_meta", "readwrite");
    tx.objectStore("records_meta").put(record, [groupId, record.record_id]);
    await done(tx);
  }

  async getCachedRecord(
    groupId: string,
    recordId: string,
  ): Promise<EncryptedRecord | undefined> {
    const tx = this.db.transaction("records_meta", "readonly");
    const record = await req<EncryptedRecord | undefined>(
      tx.objectStore("records_meta").get([groupId, recordId]),
    );
    await done(tx);
    return record;
  }

  async listCachedRecords(groupId: string): Promise<EncryptedRecord[]> {
    const tx = this.db.transaction("records_meta", "readonly");
    const records = await req<EncryptedRecord[]>(
      tx.objectStore("records_meta").getAll(groupPrefixRange(groupId)),
    );
    await done(tx);
    return records;
  }

  async deleteCachedRecord(groupId: string, recordId: string): Promise<void> {
    const tx = this.db.transaction("records_meta", "readwrite");
    tx.objectStore("records_meta").delete([groupId, recordId]);
    await done(tx);
  }

  async clear(): Promise<void> {
    const tx = this.db.transaction([...STORES], "readwrite");
    for (const store of STORES) {
      tx.objectStore(store).clear();
    }
    await done(tx);
  }
}

/** `[groupId, epoch]` keys, whose second component is numeric. */
function groupRange(groupId: string): IDBKeyRange {
  return IDBKeyRange.bound(
    [groupId, Number.NEGATIVE_INFINITY],
    [groupId, Number.POSITIVE_INFINITY],
  );
}

/**
 * `[groupId, *]` keys whatever the second component's type — needed
 * for `records_meta`, whose second component is a *string* record id.
 * The numeric range above would match nothing there, because
 * IndexedDB orders every number before every string.
 *
 * In IndexedDB key order a shorter array sorts before any longer one
 * sharing its prefix, and an array sorts after every string, so
 * `[groupId]` … `[groupId, []]` brackets the whole group.
 */
function groupPrefixRange(groupId: string): IDBKeyRange {
  return IDBKeyRange.bound([groupId], [groupId, []]);
}

function req<T>(request: IDBRequest): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => {
      resolve(request.result as T);
    };
    request.onerror = () => {
      reject(toStorageError(request.error));
    };
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => {
      resolve();
    };
    tx.onabort = () => {
      reject(toStorageError(tx.error));
    };
    tx.onerror = () => {
      reject(toStorageError(tx.error));
    };
  });
}

function toStorageError(error: DOMException | null): StorageError {
  return new StorageError(
    `IndexedDB operation failed — ${error?.name ?? "UnknownError"}: ${error?.message ?? "no detail"}`,
  );
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
