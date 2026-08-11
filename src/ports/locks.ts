/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * LockProvider port: cross-tab mutual
 * exclusion. Every open browser tab is an independent CircleKey
 * instance sharing one IndexedDB, so chain mutations run under a
 * named exclusive lock — an in-process mutex is not sufficient in the
 * browser. Adapters: Web Locks API (default) and an in-process
 * fallback for Node and tests (`adapters/locks.ts`).
 */

export interface LockProvider {
  /**
   * Run `fn` while exclusively holding the named lock; resolves with
   * `fn`'s result after the lock is released. Locks are granted in
   * request order and always released, even when `fn` throws.
   */
  withLock<T>(name: string, fn: () => Promise<T>): Promise<T>;
}

/** Per-group chain-mutation lock name. */
export function groupLockName(groupId: string): string {
  return `circlekey/group/${groupId}`;
}
