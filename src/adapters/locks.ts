/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * LockProvider adapters.
 *
 * `WebLocksProvider` wraps the Web Locks API — the only correct
 * choice in a browser, where multiple tabs share one IndexedDB.
 * `InProcessLockProvider` is a promise-queue mutex for Node and
 * tests, where a single process owns the store.
 */

import { LockError } from "../core/errors";
import type { LockProvider } from "../ports/locks";

export class WebLocksProvider implements LockProvider {
  private readonly locks: LockManager;

  constructor() {
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (locks === undefined) {
      throw new LockError(
        "Web Locks API is unavailable — requires a secure browser context; use InProcessLockProvider in single-instance environments",
      );
    }
    this.locks = locks;
  }

  async withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    // LockManager.request types its callback result as `any`; capture
    // the value ourselves to keep the return type sound.
    const box: { value?: T } = {};
    await this.locks.request(name, { mode: "exclusive" }, async () => {
      box.value = await fn();
    });
    return box.value as T;
  }
}

export class InProcessLockProvider implements LockProvider {
  /** Per-name tail of the wait queue; resolves when the holder releases. */
  private readonly tails = new Map<string, Promise<void>>();

  async withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(name) ?? Promise.resolve();
    let release: () => void = () => undefined;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.tails.set(name, current);

    await previous; // gate promises only ever resolve — never reject
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(name) === current) {
        this.tails.delete(name);
      }
    }
  }
}
