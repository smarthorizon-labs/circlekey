/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * HintChannel port: cross-tab
 * notification that a group's locally persisted state may have moved.
 *
 * A hint is a **wake-up signal, not data**. It carries only which
 * group changed — deliberately not the new epoch or the transition —
 * so a receiver has nothing it could be tempted to apply. On receipt
 * a tab re-reads the verified state its sibling already persisted;
 * it never trusts the message itself. Same posture as §5.1, applied
 * to sibling tabs.
 */

export interface GroupHint {
  /** The group whose persisted state may have advanced. */
  groupId: string;
}

export interface HintChannel {
  /** Announce that this tab advanced `groupId`. Best-effort. */
  publish(hint: GroupHint): void;
  /** Listen for sibling announcements; returns an unsubscribe. */
  subscribe(handler: (hint: GroupHint) => void): () => void;
  /** Release the underlying channel. */
  close(): void;
}
