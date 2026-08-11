/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Device identity key custody.
 *
 * Device key model (implementation decision): each device holds a
 * single Ed25519 identity keypair; its X25519 encryption keypair is
 * the deterministic birational (Edwards → Montgomery) image. This is
 * what lets spec §9.1 check 3 bind `signed_by` (an Ed25519 key) to a
 * member's `device_pubkeys` entry (an X25519 key) with pure math —
 * no backend-provided mapping to trust.
 *
 * Private keys live here and leave only through the backup wrapping
 * path (spec §5.1, §9.6).
 */

import { bytesToBase64Url } from "./bytes";
import type { CryptoProvider, KeyPair } from "../ports/crypto-provider";

export interface DeviceKeys {
  /** Ed25519 — signs transitions and certificates; `signed_by` on the wire. */
  identity: KeyPair;
  /** X25519 birational image — envelope decryption; `device_pubkeys` on the wire. */
  encryption: KeyPair;
}

export class KeyManager {
  constructor(private readonly crypto: CryptoProvider) {}

  async generateDeviceKeys(): Promise<DeviceKeys> {
    const identity = await this.crypto.generateEd25519KeyPair();
    return this.deviceKeysFromIdentity(identity.privateKey);
  }

  /** Rebuild the full device keypair set from the Ed25519 private key (restore path, spec §9.6). */
  async deviceKeysFromIdentity(identityPrivateKey: Uint8Array): Promise<DeviceKeys> {
    const publicKey = await this.crypto.ed25519PublicKey(identityPrivateKey);
    const encryption: KeyPair = {
      privateKey: await this.crypto.ed25519ToX25519PrivateKey(identityPrivateKey),
      publicKey: await this.crypto.ed25519ToX25519PublicKey(publicKey),
    };
    return {
      identity: { privateKey: identityPrivateKey, publicKey },
      encryption,
    };
  }

  /** The wire form listed in transition member sets (spec §9.1). */
  devicePublicKey(keys: DeviceKeys): string {
    return bytesToBase64Url(keys.encryption.publicKey);
  }

  /** The wire form of `signed_by` (spec §9.1). */
  identityPublicKey(keys: DeviceKeys): string {
    return bytesToBase64Url(keys.identity.publicKey);
  }
}
