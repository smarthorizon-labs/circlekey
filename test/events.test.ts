/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * The facade's event hub carries `forkDetected` — an integrity alarm
 * (spec §9.1). Its documented guarantee is that a listener cannot
 * affect the protocol: a handler that throws must not silence its
 * peers or fail the operation that emitted. That claim was previously
 * only a comment.
 */

import { describe, expect, it, vi } from "vitest";

import { EventHub } from "../src/api/events";

interface TestEvents extends Record<string, unknown[]> {
  changed: [groupId: string, epoch: number];
  other: [];
}

describe("EventHub", () => {
  it("delivers arguments to every subscriber", () => {
    const hub = new EventHub<TestEvents>();
    const first = vi.fn();
    const second = vi.fn();
    hub.on("changed", first);
    hub.on("changed", second);

    hub.emit("changed", "g", 3);

    expect(first).toHaveBeenCalledWith("g", 3);
    expect(second).toHaveBeenCalledWith("g", 3);
  });

  it("keeps events separate and tolerates emitting with no listeners", () => {
    const hub = new EventHub<TestEvents>();
    const handler = vi.fn();
    hub.on("changed", handler);

    expect(() => {
      hub.emit("other");
    }).not.toThrow();
    expect(handler).not.toHaveBeenCalled();
  });

  it("stops delivering after unsubscribe, without disturbing others", () => {
    const hub = new EventHub<TestEvents>();
    const kept = vi.fn();
    const dropped = vi.fn();
    hub.on("changed", kept);
    const off = hub.on("changed", dropped);

    off();
    hub.emit("changed", "g", 1);

    expect(dropped).not.toHaveBeenCalled();
    expect(kept).toHaveBeenCalledTimes(1);
    expect(() => {
      off(); // idempotent
    }).not.toThrow();
  });

  it("isolates a throwing handler from its peers and from the emitter", () => {
    const hub = new EventHub<TestEvents>();
    const before = vi.fn();
    const after = vi.fn();
    hub.on("changed", before);
    hub.on("changed", () => {
      throw new Error("listener exploded");
    });
    hub.on("changed", after);

    // The emit itself must not throw — a buggy host listener cannot
    // break the protocol operation that reported a fork.
    expect(() => {
      hub.emit("changed", "g", 7);
    }).not.toThrow();

    // And the listener registered *after* the thrower still ran.
    expect(before).toHaveBeenCalledTimes(1);
    expect(after).toHaveBeenCalledTimes(1);
  });

  it("does not double-register the same handler", () => {
    const hub = new EventHub<TestEvents>();
    const handler = vi.fn();
    hub.on("changed", handler);
    hub.on("changed", handler);

    hub.emit("changed", "g", 1);

    expect(handler).toHaveBeenCalledTimes(1);
  });
});
