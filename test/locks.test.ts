/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { describe, expect, it } from "vitest";

import { InProcessLockProvider, WebLocksProvider } from "../src/adapters/locks";
import { LockError } from "../src/core/errors";
import { groupLockName } from "../src/ports/locks";

function deferred() {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("InProcessLockProvider", () => {
  it("serializes holders of the same lock in request order", async () => {
    const lock = new InProcessLockProvider();
    const events: string[] = [];
    const gate = deferred();

    const first = lock.withLock("g", async () => {
      events.push("first-start");
      await gate.promise;
      events.push("first-end");
    });
    const second = lock.withLock("g", async () => {
      events.push("second-start");
      return Promise.resolve("result");
    });

    await Promise.resolve(); // give the first holder a chance to start
    expect(events).toEqual(["first-start"]); // second is blocked

    gate.resolve();
    await first;
    await expect(second).resolves.toBe("result");
    expect(events).toEqual(["first-start", "first-end", "second-start"]);
  });

  it("releases the lock when the holder throws", async () => {
    const lock = new InProcessLockProvider();
    await expect(
      lock.withLock("g", () => Promise.reject(new Error("boom"))),
    ).rejects.toThrow("boom");
    await expect(lock.withLock("g", () => Promise.resolve("ok"))).resolves.toBe("ok");
  });

  it("does not serialize distinct lock names", async () => {
    const lock = new InProcessLockProvider();
    const events: string[] = [];
    const gateA = deferred();

    const a = lock.withLock("a", async () => {
      events.push("a-start");
      await gateA.promise;
    });
    // "b" completes while "a" is still held.
    await lock.withLock("b", () => {
      events.push("b-start");
      return Promise.resolve();
    });
    expect(events).toEqual(["a-start", "b-start"]);

    gateA.resolve();
    await a;
  });

  it("supports many queued waiters without losing updates", async () => {
    const lock = new InProcessLockProvider();
    let counter = 0;
    await Promise.all(
      Array.from({ length: 25 }, () =>
        lock.withLock("counter", async () => {
          const read = counter;
          await Promise.resolve(); // yield inside the critical section
          counter = read + 1;
        }),
      ),
    );
    expect(counter).toBe(25);
  });
});

describe("WebLocksProvider", () => {
  it("fails fast with LockError where the Web Locks API is unavailable", () => {
    // vitest runs in Node: navigator.locks does not exist here. The
    // positive-path Web Locks tests belong to the browser suite.
    expect(() => new WebLocksProvider()).toThrow(LockError);
  });
});

describe("groupLockName", () => {
  it("matches the documented lock naming scheme", () => {
    expect(groupLockName("g-1")).toBe("circlekey/group/g-1");
  });
});
