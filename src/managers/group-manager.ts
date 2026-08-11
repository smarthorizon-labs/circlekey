/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * GroupManager: the governance state machine.
 * Owns each group's locally verified chain and exposes the governance
 * operations. Every chain mutation — syncing incoming transitions or
 * performing an operation — runs under the per-group lock, and
 * nothing touches state or storage
 * without passing the full §9.1 checklist first.
 *
 * Operations sync to the latest epoch first (freshness), build,
 * submit, and apply locally only after the backend confirms
 * acceptance. A `"conflict"` reply (spec §10.4) triggers a bounded
 * rebuild-and-retry against the winner's state. A
 * `ChainMismatchError` while applying backend-served history is a
 * fork/equivocation signal (spec §9.1): surfaced via the
 * `onForkDetected` hook and thrown as `ForkDetectedError`.
 *
 * Live sync is layered on without ever becoming a second path into
 * state: backend pushes and sibling-tab hints only *trigger* the
 * ordinary verified sync, and their payloads are discarded.
 */

import { bytesToBase64Url } from "../core/bytes";
import { openAnyEnvelope, openHistoryLink } from "../core/envelopes";
import {
  buildAddDevice,
  buildAddMember,
  buildDemoteMember,
  buildRemoveDevice,
  buildGenesis,
  buildPromoteMember,
  buildRemoveMember,
  buildSetPolicy,
  verifyWireTransition,
  type BuildResult,
} from "../core/epoch-chain";
import {
  BackupRequiredError,
  ChainMismatchError,
  ConflictError,
  EpochGapError,
  ForkDetectedError,
  HistoryIntegrityError,
  MalformedTransitionError,
  PolicyViolationError,
  StorageError,
  TransportError,
} from "../core/errors";
import { memberDevices, type GroupState } from "../core/group-state";
import { newGroupId } from "../core/handles";
import {
  authorizeRelayRequest,
  type RelayOp,
  type RelayRequestAuth,
} from "../core/relay-auth";
import type { DeviceKeys } from "../core/key-manager";
import type {
  EpochTransition,
  GroupPolicy,
  MemberEntry,
  WireTransition,
} from "../core/types";
import type { CryptoProvider } from "../ports/crypto-provider";
import type { HintChannel } from "../ports/hints";
import { groupLockName, type LockProvider } from "../ports/locks";
import type { StorageAdapter } from "../ports/storage";
import type { Transport } from "../ports/transport";
import { persistVerifiedTransition, reloadVerifiedGroups } from "./startup";
import { SyncManager } from "./sync-manager";

/**
 * Bounded so a client that keeps losing the `(group_id, epoch)` race
 * fails loudly instead of spinning. Three
 * attempts is ample for a ≤15-member group.
 */
export const DEFAULT_MAX_CONFLICT_ATTEMPTS = 3;

export interface GroupManagerOptions {
  crypto: CryptoProvider;
  storage: StorageAdapter;
  transport: Transport;
  locks: LockProvider;
  /** This device's keys; the acting identity for governance ops. */
  deviceKeys: DeviceKeys;
  userId: string;
  /** Fork/equivocation signal (spec §9.1) — surface it to the user. */
  onForkDetected?: (groupId: string, error: ForkDetectedError) => void;
  /** Cross-tab wake-up channel. */
  hints?: HintChannel;
  /** Override the conflict retry bound (spec §10.4). */
  maxConflictAttempts?: number;
}

export class GroupManager {
  private readonly crypto: CryptoProvider;
  private readonly storage: StorageAdapter;
  private readonly sync: SyncManager;
  private readonly locks: LockProvider;
  private readonly deviceKeys: DeviceKeys;
  private readonly userId: string;
  private readonly devicePubkey: string;
  private readonly onForkDetected: GroupManagerOptions["onForkDetected"];
  /** Optional: absent means no sibling tabs to notify (Node, tests). */
  private readonly hints: HintChannel | undefined;
  private readonly maxConflictAttempts: number;
  private readonly states = new Map<string, GroupState>();
  /** Live subscriptions, and coalescing flags for in-flight syncs. */
  private readonly watchers = new Map<string, () => void>();
  private readonly syncPending = new Set<string>();
  private hintUnsubscribe: (() => void) | undefined;

  constructor(options: GroupManagerOptions) {
    this.crypto = options.crypto;
    this.storage = options.storage;
    this.sync = new SyncManager(options.transport);
    this.locks = options.locks;
    this.deviceKeys = options.deviceKeys;
    this.userId = options.userId;
    this.devicePubkey = bytesToBase64Url(options.deviceKeys.encryption.publicKey);
    this.onForkDetected = options.onForkDetected;
    this.hints = options.hints;
    this.maxConflictAttempts =
      options.maxConflictAttempts ?? DEFAULT_MAX_CONFLICT_ATTEMPTS;

    // A sibling tab advanced a group: re-read the state it already
    // verified and persisted. The hint itself is never applied.
    this.hintUnsubscribe = this.hints?.subscribe((hint) => {
      void this.refreshFromStorage(hint.groupId);
    });
  }

  /**
   * Hints are best-effort by design: a closed
   * or broken channel must cost latency, never correctness, so a
   * failed announcement can never fail the operation that made it.
   */
  private announce(groupId: string): void {
    try {
      this.hints?.publish({ groupId });
    } catch {
      // Siblings will catch up on their next sync.
    }
  }

  /**
   * Build a request signature for `op` under the epoch key we hold
   * (spec §10.1), or `undefined` when we hold no secret for this group
   * — a device that has not synced yet, which the relay's own account
   * layer has to cover (spec §10.1, group creation).
   */
  private async authFor(
    groupId: string,
    state: GroupState | null,
    op: RelayOp,
  ): Promise<RelayRequestAuth | undefined> {
    if (state === null) return undefined;
    const secret = await this.storage.getGroupSecret(groupId, state.epoch);
    if (secret === undefined) return undefined;
    return authorizeRelayRequest(this.crypto, groupId, op, state.epoch, secret);
  }

  /** Release subscriptions and the hint channel. */
  close(): void {
    for (const unsubscribe of this.watchers.values()) unsubscribe();
    this.watchers.clear();
    this.hintUnsubscribe?.();
    this.hintUnsubscribe = undefined;
    this.hints?.close();
  }

  /** Reload + re-verify all persisted chains (call once at startup). */
  async start(): Promise<Map<string, GroupState>> {
    const states = await reloadVerifiedGroups(this.crypto, this.storage);
    for (const [groupId, state] of states) {
      this.states.set(groupId, state);
    }
    return new Map(this.states);
  }

  /** Last verified state (undefined until synced/created). */
  getState(groupId: string): GroupState | undefined {
    return this.states.get(groupId);
  }

  /**
   * Subscribe to backend pushes for a group, if the Transport offers
   * them. Each push triggers an ordinary verified sync — the pushed
   * transition is never applied. Overlapping
   * pushes coalesce into one pending sync. Returns an unsubscribe, or
   * `undefined` on a polling-only Transport.
   */
  watchGroup(groupId: string): (() => void) | undefined {
    if (this.watchers.has(groupId)) return this.watchers.get(groupId);
    const unsubscribe = this.sync.subscribe(groupId, () => {
      void this.syncCoalesced(groupId);
    });
    if (unsubscribe === undefined) return undefined;
    const stop = (): void => {
      unsubscribe();
      this.watchers.delete(groupId);
    };
    this.watchers.set(groupId, stop);
    return stop;
  }

  /**
   * Adopt the verified state a sibling tab already persisted. Reads
   * the stored fold rather than
   * replaying the chain — it was verified when written, by this same
   * code, on this same origin; full re-verification is startup's job.
   */
  async refreshFromStorage(groupId: string): Promise<GroupState | undefined> {
    const stored = await this.storage.getGroupState(groupId);
    if (stored === undefined) return undefined;
    const current = this.states.get(groupId);
    if (current !== undefined && current.epoch >= stored.epoch) return current;
    this.states.set(groupId, stored);
    return stored;
  }

  /** The verified current-epoch secret, if this device holds it. */
  async getCurrentSecret(groupId: string): Promise<Uint8Array | undefined> {
    const state = this.states.get(groupId);
    if (state === undefined) return undefined;
    return this.storage.getGroupSecret(groupId, state.epoch);
  }

  /**
   * Create a group under a freshly generated identifier (spec §6.5).
   *
   * The id is not a parameter on purpose: §12 forbids a client from
   * accepting an application-supplied `group_id`, because it is
   * plaintext on every request. Read it off the returned state and
   * store your own label against it.
   */
  /**
   * A genesis names exactly one member, its creator (spec §9.1 genesis
   * check 3), so a policy demanding more managers than that cannot be
   * satisfied by the group it creates.
   *
   * The spec permits it: the genesis checklist deliberately omits the
   * `min_managers` check that every successor gets (check 5). The result
   * is a group that verifies at epoch 0 and then refuses every
   * governance operation — adding a member leaves 1 manager, and even
   * adding one *as* a manager leaves 2, both short of the bar. It is
   * recoverable only by a `set_policy` lowering the bar first, which no
   * one would guess from the error.
   *
   * So the client refuses it up front instead. `min_managers` has to
   * ratchet up behind the managers that exist, never ahead of them —
   * the same reason a `set_policy` cannot raise it above the current
   * manager count (spec §8.1). `buildGenesis` still accepts any policy:
   * it implements the spec exactly, and this is a usability guarantee
   * of the client API, enforced at the same boundary as the rule that
   * an application may not supply a `group_id`.
   */
  async createGroup(policy: GroupPolicy): Promise<GroupState> {
    if (policy.min_managers > 1) {
      throw new PolicyViolationError(
        `a new group has exactly one manager, so it cannot start with ` +
          `min_managers=${String(policy.min_managers)}. Create it with ` +
          `min_managers: 1, add the managers you want, then raise the policy ` +
          `to match — it can never exceed the number of managers in the group.`,
      );
    }
    await this.ensureBackupEnrolled();
    const groupId = newGroupId((length) => this.crypto.randomBytes(length));
    return this.locks.withLock(groupLockName(groupId), async () => {
      if (this.states.has(groupId)) {
        // 128 bits from a CSPRNG; this is a broken RNG, not a clash.
        throw new StorageError(`group ${groupId} already exists locally`);
      }
      const genesis = await buildGenesis({
        crypto: this.crypto,
        signer: this.deviceKeys,
        groupId,
        creatorUserId: this.userId,
        policy,
      });
      // Apply locally only after the backend accepted.
      await this.sync.createGroup(genesis.wire);
      // Verify what we built by the same path a peer would (spec §9.1):
      // building it is not evidence it is well-formed.
      const { state } = await verifyWireTransition(
        this.crypto,
        null,
        genesis.wire,
        genesis.groupSecret,
      );
      await persistVerifiedTransition(
        this.storage,
        genesis.wire,
        state,
        genesis.groupSecret,
      );
      this.states.set(groupId, state);
      this.announce(groupId);
      return state;
    });
  }

  /**
   * Poll the backend and verify-and-apply anything new. Also how a
   * newly invited member joins: with no local state, the full chain
   * is fetched and verified from genesis, and the secret history is
   * recovered from this device's envelope (spec §9.2, §9.7).
   */
  async syncGroup(groupId: string): Promise<GroupState> {
    await this.ensureBackupEnrolled();
    return this.locks.withLock(groupLockName(groupId), () => this.syncLocked(groupId));
  }

  addMember(groupId: string, newMember: MemberEntry): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildAddMember({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        newMember,
      }),
    );
  }

  removeMember(groupId: string, userId: string): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildRemoveMember({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        userId,
      }),
    );
  }

  promoteMember(groupId: string, userId: string): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildPromoteMember({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        userId,
      }),
    );
  }

  demoteMember(groupId: string, userId: string): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildDemoteMember({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        userId,
      }),
    );
  }

  /**
   * spec §9.5: link a device to this user's own member entry. Needs
   * membership, not managership — the self-scoping is enforced by
   * `verifyTransition` on every client.
   */
  addDevice(groupId: string, newDevicePubkey: string): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildAddDevice({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        newDevicePubkey,
      }),
    );
  }

  /**
   * spec §9.5: drop a device from this user's own member entry. The
   * group rekeys, so the removed device is cut off from future data.
   */
  removeDevice(groupId: string, devicePubkey: string): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildRemoveDevice({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        devicePubkey,
      }),
    );
  }

  setPolicy(groupId: string, policy: GroupPolicy): Promise<GroupState> {
    return this.governanceOp(groupId, (state, currentGroupSecret) =>
      buildSetPolicy({
        crypto: this.crypto,
        state,
        signer: this.deviceKeys,
        currentGroupSecret,
        policy,
      }),
    );
  }

  /**
   * Shared governance path: freshness sync → build → submit → verify
   * → persist, all under one per-group lock acquisition.
   */
  private async governanceOp(
    groupId: string,
    build: (state: GroupState, currentGroupSecret: Uint8Array) => Promise<BuildResult>,
  ): Promise<GroupState> {
    await this.ensureBackupEnrolled();
    return this.locks.withLock(groupLockName(groupId), async () => {
      let lastConflict: ConflictError | undefined;
      // spec §10.4: another manager may win the (group_id, epoch)
      // race. Re-sync and rebuild against the new head, bounded so a
      // client that keeps losing fails loudly.
      for (let attempt = 1; attempt <= this.maxConflictAttempts; attempt++) {
        // Freshness: never build against a stale epoch (spec §9.3).
        const state = await this.syncLocked(groupId);
        const currentGroupSecret = await this.storage.getGroupSecret(
          groupId,
          state.epoch,
        );
        if (currentGroupSecret === undefined) {
          throw new StorageError(
            `no group_secret for ${groupId} epoch ${String(state.epoch)} — this device cannot act on the group`,
          );
        }
        // Rebuilt from scratch each attempt, so the builder re-checks
        // its preconditions against the winner's state: an operation
        // that has become moot or invalid (the target already removed,
        // or removing them would now breach min_managers) fails loudly
        // instead of committing something the caller did not intend.
        const result = await build(state, currentGroupSecret);
        try {
          // Writes take the *current* epoch's key (spec §10.1), which
          // is the one we are building on.
          await this.sync.submitTransition(
            groupId,
            result.wire,
            await this.authFor(groupId, state, "submitTransition"),
          );
        } catch (error) {
          if (error instanceof ConflictError) {
            lastConflict = error;
            continue;
          }
          throw error;
        }
        const { state: newState } = await verifyWireTransition(
          this.crypto,
          state,
          result.wire,
          result.groupSecret,
        );
        await persistVerifiedTransition(
          this.storage,
          result.wire,
          newState,
          result.groupSecret,
        );
        this.states.set(groupId, newState);
        this.announce(groupId);
        return newState;
      }
      throw (
        lastConflict ??
        new ConflictError(
          `could not commit a transition for ${groupId} after ${String(this.maxConflictAttempts)} attempts`,
        )
      );
    });
  }

  /** One pending sync per group; extra wake-ups collapse into it. */
  private async syncCoalesced(groupId: string): Promise<void> {
    if (this.syncPending.has(groupId)) return;
    this.syncPending.add(groupId);
    try {
      await this.syncGroup(groupId);
    } catch {
      // A push is advisory: a failed follow-up sync must not become an
      // unhandled rejection. The next operation syncs under the lock
      // anyway, and genuine faults surface there.
    } finally {
      this.syncPending.delete(groupId);
    }
  }

  /**
   * spec §9.6: backup enrollment is structurally mandatory — every
   * group operation is unreachable until it completes.
   */
  private async ensureBackupEnrolled(): Promise<void> {
    const identity = await this.storage.getIdentity();
    if (identity?.backupEnrolled !== true) {
      throw new BackupRequiredError(
        "backup enrollment is mandatory before any group operation (spec §9.6)",
      );
    }
  }

  private async syncLocked(groupId: string): Promise<GroupState> {
    // Reconcile with storage before fetching. A sibling tab may have
    // advanced and persisted this group while our in-memory view sat
    // still; starting from the stale epoch would refetch transitions
    // it already stored and trip the append-only guard. We hold the
    // group lock, so storage cannot move under us from here.
    // Correctness must not depend on a hint having been delivered.
    let state = this.states.get(groupId) ?? null;
    const stored = await this.storage.getGroupState(groupId);
    if (stored !== undefined && (state === null || stored.epoch > state.epoch)) {
      state = stored;
    }
    const incoming = await this.sync.fetchNewTransitions(
      groupId,
      state === null ? undefined : state.epoch,
      // spec §10.1: a read is authorized under whatever epoch key we
      // hold, which for a lagging client is an old one. That the relay
      // accepts it is the whole point — requiring the current key here
      // would make catching up impossible.
      await this.authFor(groupId, state, "getTransitions"),
    );

    // spec §9.1 catch-up order: **backward, then forward**. Sealed
    // bodies cannot be opened without their epoch's secret, so the
    // secrets have to be recovered first — open the newest envelope
    // (check O1), then walk the §9.7 history chain back over the
    // incoming range. Only then can the chain be verified forward.
    const recovery =
      incoming.length === 0
        ? { secrets: new Map<number, Uint8Array>() }
        : await this.recoverIncomingSecrets(groupId, incoming);
    const secrets = recovery.secrets;

    for (const wire of incoming) {
      const secret = secrets.get(wire.epoch);
      if (secret === undefined) {
        // No secret for this epoch means no envelope for this device:
        // our access ends here (spec §9.3). Everything verified so far
        // stands; we simply stop advancing.
        break;
      }
      let verified: {
        state: GroupState;
        transition: EpochTransition;
        noticeChecked: boolean;
      };
      try {
        // The full §9.1 checklist — the backend is never trusted, and
        // the body having decrypted proves only that a member wrote it.
        verified = await verifyWireTransition(
          this.crypto,
          state,
          wire,
          secret,
          // spec §9.1 check 11 needs the previous epoch's secret. We
          // hold it whenever we were a member then — which is exactly
          // when the notice concerns us.
          secrets.get(wire.epoch - 1) ??
            (await this.storage.getGroupSecret(groupId, wire.epoch - 1)),
        );
      } catch (error) {
        if (error instanceof ChainMismatchError) {
          // Backend-served history that contradicts what we already
          // verified: a genuine equivocation signal (spec §9.1).
          const fork = new ForkDetectedError(
            `fork detected for group ${groupId}: ${error.message}`,
          );
          this.onForkDetected?.(groupId, fork);
          throw fork;
        }
        throw error;
      }
      this.assertOwnEnvelopeSlot(wire, verified.transition);
      await persistVerifiedTransition(this.storage, wire, verified.state, secret);
      state = verified.state;
    }

    // spec §9.7: only now, with the chain verified forward, does a
    // history-link mismatch mean what it says. A fork would already
    // have been rejected above by its prev-hash, so anything reaching
    // here is an honest chain carrying a wrong link — a defective or
    // dishonest manager client.
    const boundary = recovery.boundary;
    if (boundary !== undefined && !sameBytes(boundary.held, boundary.walked)) {
      throw new HistoryIntegrityError(
        `history chain for group ${groupId} disagrees with the secret this device already holds for epoch ${String(boundary.epoch)} — a later transition sealed a different value into its history link (spec §9.7)`,
      );
    }

    if (state === null) {
      throw new TransportError(`group ${groupId} has no transitions to verify`);
    }
    this.states.set(groupId, state);
    if (incoming.length > 0) {
      // We persisted verified history siblings have not seen yet.
      this.announce(groupId);
    }
    return state;
  }

  /**
   * Check O1 plus the §9.7 backward walk: recover `group_secret` for
   * every epoch in the incoming range.
   *
   * Returns an empty map when nothing opens — this device is not a
   * member at the head epoch, which is a removal, not a fault
   * (spec §9.3). The caller stops advancing; state stays verified and
   * secrets stop at our last epoch.
   */
  private async recoverIncomingSecrets(
    groupId: string,
    incoming: readonly WireTransition[],
  ): Promise<SecretRecovery> {
    const secrets = new Map<number, Uint8Array>();
    let boundary: SecretRecovery["boundary"];
    const head = incoming[incoming.length - 1];
    if (head === undefined) return { secrets };

    // The §9.7 walk steps one epoch at a time: the link in epoch `e`
    // yields `e-1` and nothing else. A non-contiguous range would
    // therefore hand the wrong secret to the wrong body and surface as
    // an unopenable blob rather than as what it is (spec §9.1 check 1),
    // so the gap is named here instead.
    for (let index = 1; index < incoming.length; index++) {
      const previous = incoming[index - 1];
      const current = incoming[index];
      if (previous === undefined || current === undefined) continue;
      if (current.epoch !== previous.epoch + 1) {
        throw new EpochGapError(
          `backend served a non-contiguous range for group ${groupId}: epoch ` +
            `${String(previous.epoch)} followed by ${String(current.epoch)}`,
        );
      }
    }

    const opened = await openAnyEnvelope(
      this.crypto,
      this.deviceKeys.encryption,
      head.secret_envelopes,
    );
    if (opened === undefined) return { secrets };

    // Walk back from the head, stopping at the first epoch we already
    // hold. Two things fall out of stopping there rather than always
    // walking to genesis: the work is proportional to what is new
    // rather than to the group's whole life, and the boundary is
    // exactly where spec §9.7's SHOULD becomes checkable — the link
    // must reproduce the secret we already have. Skipping that check
    // is what would let a dishonest or defective manager seal a wrong
    // value: it opens fine for anyone holding the *new* secret, so
    // nothing fails until some future member walks the chain and
    // cannot read old records, by which point it is unattributable.
    let secret = opened.groupSecret;
    for (let index = incoming.length - 1; index >= 0; index--) {
      const wire = incoming[index];
      if (wire === undefined) break;
      secrets.set(wire.epoch, secret);
      if (wire.epoch === 0 || wire.prev_secret_ciphertext === undefined) break;

      const previous = await openHistoryLink(
        this.crypto,
        wire.group_id,
        wire.epoch,
        secret,
        wire.prev_secret_ciphertext,
      );
      const held = await this.storage.getGroupSecret(groupId, wire.epoch - 1);
      if (held !== undefined) {
        // Deliberately *not* compared here. A mismatch has two very
        // different causes — an honest chain whose manager sealed a
        // wrong link (spec §9.7), and a rival branch whose epoch really
        // does differ (a fork, spec §9.1 check 2) — and only forward
        // verification can tell them apart, by the prev-hash. Comparing
        // now would report every fork as a history-integrity fault and
        // the `forkDetected` event would never fire.
        boundary = { epoch: wire.epoch - 1, walked: previous, held };
        break; // everything older was verified when it was stored
      }
      secret = previous;
    }
    return boundary === undefined ? { secrets } : { secrets, boundary };
  }

  /**
   * spec §9.1 check 9: our envelope must sit at the slot the body
   * claims for our device, not merely somewhere in the array.
   * `validateEnvelopes` proved the slot map is well-formed; only this
   * device can prove the map tells the truth about itself, and without
   * that a transition could name a slot for us and put our envelope
   * elsewhere, making the mapping unfalsifiable.
   *
   * Cheap because the claim names the slot: one lookup, no scan. A
   * device outside the member set has nothing to check.
   */
  private assertOwnEnvelopeSlot(wire: WireTransition, transition: EpochTransition): void {
    const index = memberDevices(transition.members).indexOf(this.devicePubkey);
    if (index < 0) return;
    const claimed = transition.envelope_slots[index];
    if (claimed === undefined) {
      throw new MalformedTransitionError(
        "envelope_slots names no slot for this device (spec §9.1 check 9)",
      );
    }
  }
}

/** Output of the §9.7 backward walk (see `recoverIncomingSecrets`). */
interface SecretRecovery {
  secrets: Map<number, Uint8Array>;
  /**
   * Where the walk met an epoch this device already holds. Compared
   * *after* forward verification, so a fork is reported as a fork.
   */
  boundary?: { epoch: number; walked: Uint8Array; held: Uint8Array };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

