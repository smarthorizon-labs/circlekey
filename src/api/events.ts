/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Minimal typed event hub for the facade.
 * Handlers are fire-and-forget; a throwing handler does not affect
 * other handlers or the emitting operation.
 */

export class EventHub<Events extends Record<string, unknown[]>> {
  private readonly handlers = new Map<string, Set<unknown>>();

  /** Register a handler; returns an unsubscribe function. */
  on<K extends keyof Events & string>(
    event: K,
    handler: (...args: Events[K]) => void,
  ): () => void {
    let set = this.handlers.get(event);
    if (set === undefined) {
      set = new Set();
      this.handlers.set(event, set);
    }
    set.add(handler);
    return () => {
      set.delete(handler);
    };
  }

  emit<K extends keyof Events & string>(event: K, ...args: Events[K]): void {
    const set = this.handlers.get(event);
    if (set === undefined) return;
    for (const handler of set) {
      try {
        (handler as (...handlerArgs: Events[K]) => void)(...args);
      } catch {
        // Listener errors never break the protocol operation.
      }
    }
  }
}
