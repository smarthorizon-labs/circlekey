/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * CircleKey — reference implementation of the GroupVault Protocol.
 *
 * Public entry point: the `GroupVault` facade,
 * protocol types, error taxonomy, canonical codec, KDF labels, chain
 * verification, and ports. Platform adapters ship as subpath exports
 * (`circlekey/adapters/webcrypto`).
 */

/**
 * The library's own version, independent of the protocol version.
 *
 * Which protocol versions this build speaks is answered by
 * {@link SUPPORTED_SUITES}, not by this number: a single release may
 * read and write several suites (spec §6.3), so the two cannot be the
 * same value. This follows semver on the *API* — a major bump means
 * the TypeScript surface changed, not that the protocol did.
 */
export const CIRCLEKEY_VERSION = "1.0.0";

export * from "./core/types";
export {
  CircleKeyError,
  CryptoError,
  EncodingError,
  EnvelopeError,
  HistoryIntegrityError,
  KeyUsageExceededError,
  StorageError,
  LockError,
  HintChannelError,
  TransportError,
  ConflictError,
  StaleEpochError,
  SubmitRejectedError,
  BackupError,
  BackupRequiredError,
  InsecureContextError,
  TransitionRejectedError,
  EpochGapError,
  ChainMismatchError,
  ForkDetectedError,
  UnauthorizedSignerError,
  BadSignatureError,
  PolicyViolationError,
  MalformedTransitionError,
} from "./core/errors";
export {
  canonicalize,
  canonicalBytes,
  transitionSigningBytes,
  hashTransition,
  genesisMarker,
} from "./core/codec";
export type { JsonValue, Sha256Fn, UnsignedEpochTransition } from "./core/codec";
export { KDF_LABELS, DERIVED_KEY_LENGTH, kdfInfo, deriveKey, deriveBytes } from "./core/kdf";
export type { KdfLabel, HkdfSha256Fn } from "./core/kdf";
// --- Metadata minimization (spec §5.8, §6.5) ---
export {
  CAPACITY_PROFILES,
  DEFAULT_CAPACITY,
  isCapacityName,
  profileFor,
  profileForPolicy,
} from "./core/profiles";
export type { CapacityName, CapacityProfile } from "./core/profiles";
export {
  pad,
  unpad,
  recordBucket,
  RECORD_BUCKETS,
  MAX_RECORD_BUCKET,
  LENGTH_PREFIX_BYTES,
} from "./core/padding";
export {
  deriveRelayHandle,
  newGroupId,
  GROUP_ID_LENGTH,
  HANDLE_LENGTH,
} from "./core/handles";
export {
  deriveRelayAuthKeyPair,
  deriveRelayAuthPublicKey,
  signRelayRequest,
  verifyRelayRequest,
} from "./core/relay-auth";
export {
  utf8Bytes,
  concatBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  wipe,
} from "./core/bytes";
export { parseEpochTransition, parseEpochTransitions } from "./core/wire";
export {
  managerCount,
  findMember,
  memberDevices,
  satisfiesPolicy,
  cloneMembers,
} from "./core/group-state";
export type { GroupState } from "./core/group-state";
export {
  sealEnvelope,
  openEnvelope,
  envelopeEpoch,
  sealHistoryLink,
  openHistoryLink,
  ENVELOPE_VERSION,
  GROUP_SECRET_LENGTH,
  // spec §6.5: unaddressed envelopes, sealed bodies and
  // removal notices.
  makeDecoyEnvelope,
  openAnyEnvelope,
  placeEnvelopes,
  sealTransitionBody,
  openTransitionBody,
  sealRemovalNotice,
  openRemovalNotice,
} from "./core/envelopes";
export { KeyManager } from "./core/key-manager";
export type { DeviceKeys } from "./core/key-manager";
export { RecordCrypto, DEFAULT_KEY_USAGE_LIMIT, deriveRecordId } from "./core/record-crypto";
export type { EncryptedMetadata, RecordCryptoOptions } from "./core/record-crypto";
export type { KeyUsageStore, StorageAdapter, StoredIdentity } from "./ports/storage";
export { groupLockName } from "./ports/locks";
export type { LockProvider } from "./ports/locks";
export type { HintChannel, GroupHint } from "./ports/hints";
export { reloadVerifiedGroups, persistVerifiedTransition } from "./managers/startup";
export type { Transport } from "./ports/transport";
export { SyncManager } from "./managers/sync-manager";
export {
  GroupManager,
  DEFAULT_MAX_CONFLICT_ATTEMPTS,
} from "./managers/group-manager";
export type { GroupManagerOptions } from "./managers/group-manager";
export { DeviceManager } from "./managers/device-manager";
export type {
  LinkDeviceResult,
  UnlinkDeviceResult,
  LostDeviceRoute,
} from "./managers/device-manager";
export {
  BackupManager,
  PBKDF2_ITERATIONS,
  ARGON2ID_PARAMS,
  ARGON2ID_PARAMS_HIGH_MEMORY,
  DEFAULT_RELAY_ID,
} from "./managers/backup-manager";
export type { BackupManagerOptions, BackupKdf } from "./managers/backup-manager";
export { GroupVault } from "./api/group-vault";
export type {
  GroupVaultOptions,
  GroupVaultEvents,
  AddMemberInput,
} from "./api/group-vault";
export {
  verifyTransition,
  replayChain,
  // spec §6.5, §9.1: the outer layer. `verifyWireTransition`
  // is the entry point callers should use; `verifyTransition` runs the
  // inner checklist alone and is exported for tests and tooling.
  verifyWireTransition,
  openWireTransition,
  replayWireChain,
  removedDevices,
  noticePolicy,
  DEFAULT_REMOVAL_NOTICE,
  signTransition,
  recoverSecretHistory,
  buildGenesis,
  buildAddDevice,
  buildRemoveDevice,
  buildAddMember,
  buildRemoveMember,
  buildPromoteMember,
  buildDemoteMember,
  buildSetPolicy,
} from "./core/epoch-chain";
export type { BuildResult } from "./core/epoch-chain";
export { parseWireTransition, parseWireTransitions, parseRemovalNotice } from "./core/wire";
export type { CryptoProvider, KeyPair, Argon2Params } from "./ports/crypto-provider";
