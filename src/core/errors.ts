/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Typed error taxonomy.
 *
 * Declared inside `core/` so the pure protocol core can throw typed
 * errors without importing upward; the package root re-exports them.
 * Library code never throws a bare `Error`.
 */

export abstract class CircleKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Invalid input to the canonical codec. */
export class EncodingError extends CircleKeyError {}

/**
 * A cryptographic primitive failed or refused its input — including
 * AES-GCM authentication failure on decrypt.
 */
export class CryptoError extends CircleKeyError {}

/**
 * Base for every spec §9.1 checklist rejection. One subclass per
 * checklist item so tests can assert the exact check that fired. A
 * rejected transition MUST NOT be applied,
 * regardless of what the backend claims (spec §9.1).
 */
export abstract class TransitionRejectedError extends CircleKeyError {}

/** spec §9.1 check 1: epoch is not exactly `current + 1` (gap, replay, or rollback). */
export class EpochGapError extends TransitionRejectedError {}

/** spec §9.1 check 2: `prev_transition_hash` does not match the last accepted transition. */
export class ChainMismatchError extends TransitionRejectedError {}

/**
 * A `ChainMismatchError` for an epoch this client already holds —
 * a genuine equivocation/fork signal that MUST be surfaced to the
 * user (spec §9.1). Raised by the sync layer when comparing an
 * incoming transition against stored history.
 */
export class ForkDetectedError extends ChainMismatchError {}

/** spec §9.1 check 3: `signed_by` was not a manager before this transition. */
export class UnauthorizedSignerError extends TransitionRejectedError {}

/** spec §9.1 check 4: the Ed25519 signature over the transition is invalid. */
export class BadSignatureError extends TransitionRejectedError {}

/** spec §9.1 check 5 / §8.1: the resulting member set violates `min_managers`. */
export class PolicyViolationError extends TransitionRejectedError {}

/**
 * Structural violation: malformed member set, wrong action semantics
 * (e.g. an `add` that also mutates flags), missing/foreign secret
 * envelopes, malformed keys, or an invalid genesis shape.
 */
export class MalformedTransitionError extends TransitionRejectedError {}

/** Sealing or opening a secret envelope failed. */
export class EnvelopeError extends CircleKeyError {}

/**
 * The secret history chain (spec §9.7) contradicts a secret this
 * device already holds. The transition itself verified — signatures
 * and hashes are sound — so this is not equivocation by the backend
 * but a defective or dishonest *manager client* sealing the wrong
 * value into a link. Surface it as an integrity issue: future members
 * would otherwise inherit an unreadable history.
 */
export class HistoryIntegrityError extends CircleKeyError {}

/**
 * The per-key encryption usage bound was hit (spec §6.1): encryption
 * under this epoch's keys is refused until the group rotates to a new
 * epoch. Never raised on decrypt.
 */
export class KeyUsageExceededError extends CircleKeyError {}

/**
 * Local persistence violation — e.g. attempting to overwrite an
 * already-stored transition epoch or replace a stored group secret
 * with a different value. Verified history is append-only.
 */
export class StorageError extends CircleKeyError {}

/** A lock provider is unavailable or failed. */
export class LockError extends CircleKeyError {}

/**
 * A cross-tab hint channel is unavailable.
 * Hints are an optimization, so callers may fall back to a noop
 * channel rather than treating this as fatal.
 */
export class HintChannelError extends CircleKeyError {}

/**
 * Transport/backend failure that is not a protocol-level rejection:
 * unknown group, missing record or backup blob, malformed submission.
 */
export class TransportError extends CircleKeyError {}

/**
 * spec §10.4: another manager won the `(group_id, epoch)` slot.
 * Retryable — rebuild against the new head and resubmit
 * (the sync layer rebuilds and retries automatically).
 */
export class ConflictError extends CircleKeyError {}

/**
 * The backend's freshness gate rejected a write tagged with a
 * superseded epoch (spec §9.3). Retryable after syncing.
 */
export class StaleEpochError extends CircleKeyError {}

/**
 * The backend refused a submission for a non-retryable reason
 * (`invalid_signature`, `policy_violation`) — a client bug or a
 * hostile backend; never silently swallowed.
 */
export class SubmitRejectedError extends CircleKeyError {}

/**
 * A backup blob could not be created or opened: wrong recovery
 * credential, unsupported KDF/suite, or corrupted blob (spec §9.6).
 */
export class BackupError extends CircleKeyError {}

/**
 * spec §9.6: backup enrollment is mandatory with no opt-out — group
 * operations are unreachable until enrollment completes.
 */
export class BackupRequiredError extends CircleKeyError {}

/**
 * WebCrypto is unavailable — CircleKey requires a secure context
 * (HTTPS or localhost) or Node ≥ 20. Thrown
 * at facade construction so failures are immediate, not mid-crypto.
 */
export class InsecureContextError extends CircleKeyError {}
