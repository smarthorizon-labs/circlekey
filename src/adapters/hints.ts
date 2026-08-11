/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * HintChannel adapters.
 *
 * `BroadcastChannelHints` is the browser implementation — every tab on
 * the origin joins one named channel. `InProcessHintChannel` is an
 * in-memory stand-in for Node and tests, and `NoopHintChannel` is the
 * fallback where neither is available (hints are an optimization, so
 * losing them costs latency, never correctness: every operation still
 * syncs under the group lock).
 */

import { HintChannelError } from "../core/errors";
import type { GroupHint, HintChannel } from "../ports/hints";

const CHANNEL_NAME = "circlekey/hints";

export class BroadcastChannelHints implements HintChannel {
  private readonly channel: BroadcastChannel;

  constructor(name: string = CHANNEL_NAME) {
    const ctor = (globalThis as { BroadcastChannel?: typeof BroadcastChannel })
      .BroadcastChannel;
    if (ctor === undefined) {
      throw new HintChannelError(
        "BroadcastChannel is unavailable — use InProcessHintChannel or NoopHintChannel",
      );
    }
    this.channel = new ctor(name);
  }

  publish(hint: GroupHint): void {
    // Only the group id crosses the channel (ports/hints.ts).
    this.channel.postMessage({ groupId: hint.groupId });
  }

  subscribe(handler: (hint: GroupHint) => void): () => void {
    const listener = (event: MessageEvent): void => {
      // Treat the payload as untrusted: accept it only as "this group
      // may have moved", and discard anything else it carries.
      const data = event.data as { groupId?: unknown } | null;
      const groupId = data?.groupId;
      if (typeof groupId === "string") handler({ groupId });
    };
    this.channel.addEventListener("message", listener as EventListener);
    return () => {
      this.channel.removeEventListener("message", listener as EventListener);
    };
  }

  close(): void {
    this.channel.close();
  }
}

/** Shared bus so instances in one process can hint each other. */
const inProcessBuses = new Map<string, Set<(hint: GroupHint) => void>>();

export class InProcessHintChannel implements HintChannel {
  private readonly handlers = new Set<(hint: GroupHint) => void>();

  constructor(private readonly busName: string = CHANNEL_NAME) {}

  private bus(): Set<(hint: GroupHint) => void> {
    let bus = inProcessBuses.get(this.busName);
    if (bus === undefined) {
      bus = new Set();
      inProcessBuses.set(this.busName, bus);
    }
    return bus;
  }

  publish(hint: GroupHint): void {
    for (const handler of this.bus()) {
      // Siblings only — never loop a tab's own hint back to itself.
      if (this.handlers.has(handler)) continue;
      handler({ groupId: hint.groupId });
    }
  }

  subscribe(handler: (hint: GroupHint) => void): () => void {
    this.handlers.add(handler);
    this.bus().add(handler);
    return () => {
      this.handlers.delete(handler);
      this.bus().delete(handler);
    };
  }

  close(): void {
    for (const handler of this.handlers) this.bus().delete(handler);
    this.handlers.clear();
  }
}

export class NoopHintChannel implements HintChannel {
  publish(): void {
    // Nothing to announce to.
  }

  subscribe(): () => void {
    return () => undefined;
  }

  close(): void {
    // Nothing to release.
  }
}
