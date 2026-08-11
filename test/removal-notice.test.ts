/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Removal notices — spec §6.5 and §9.1 checks 10–11.
 *
 * The notice is the one thing a removed member can still read, so its
 * two failure modes both matter: a manager omitting it under a
 * `"required"` policy (the member is never told), and a peer forging
 * one (the member is told a lie they will act on). The forgery case is
 * why the signature exists at all — every member holds
 * `group_secret[epoch-1]`, so sealing alone authenticates nothing.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { bytesToBase64Url, utf8Bytes, utf8String } from "../src/core/bytes";
import { canonicalBytes } from "../src/core/codec";
import { openRemovalNotice, sealRemovalNotice } from "../src/core/envelopes";
import {
  buildAddMember,
  buildGenesis,
  buildRemoveMember,
  buildSetPolicy,
  removedDevices,
  verifyWireTransition,
} from "../src/core/epoch-chain";
import { BadSignatureError, MalformedTransitionError } from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { CAPACITY_PROFILES } from "../src/core/profiles";
import type { RemovalNotice, WireTransition } from "../src/core/types";
import { parseRemovalNotice } from "../src/core/wire";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);
const GROUP = "removal-notice-group";
const NOTICE_SIZE = CAPACITY_PROFILES.lite.removalNoticeSize;

let alice: DeviceKeys;
let bob: DeviceKeys;

interface Fixture {
  state: GroupState;
  secret: Uint8Array;
  bobDevice: string;
}

/** create → add bob, under the given notice policy. */
async function groupWithBob(
  removal_notice: "required" | "suppressed",
): Promise<Fixture> {
  const genesis = await buildGenesis({
    crypto,
    signer: alice,
    groupId: GROUP,
    creatorUserId: "alice",
    policy: { min_managers: 1, removal_notice },
  });
  const state0 = (await verifyWireTransition(crypto, null, genesis.wire, genesis.groupSecret))
    .state;
  const bobDevice = km.devicePublicKey(bob);
  const add = await buildAddMember({
    crypto,
    state: state0,
    signer: alice,
    currentGroupSecret: genesis.groupSecret,
    newMember: { user_id: "bob", device_pubkeys: [bobDevice], is_manager: false },
  });
  const state1 = (
    await verifyWireTransition(
      crypto,
      state0,
      add.wire,
      add.groupSecret,
      genesis.groupSecret,
    )
  ).state;
  return { state: state1, secret: add.groupSecret, bobDevice };
}

beforeAll(async () => {
  alice = await km.generateDeviceKeys();
  bob = await km.generateDeviceKeys();
});

describe("removal notice round-trip (spec §6.5)", () => {
  it("is readable by the removed member, using the secret they still hold", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });

    // Bob cannot open the body — it is sealed to an epoch he never
    // receives — but he holds group_secret[1], which is what the notice
    // is sealed under. That asymmetry is the entire design.
    expect(remove.wire.removal_notice).toBeDefined();
    const bytes = await openRemovalNotice(
      crypto,
      GROUP,
      remove.wire.epoch,
      fx.secret,
      remove.wire.removal_notice ?? "",
      NOTICE_SIZE,
    );
    const notice = parseRemovalNotice(JSON.parse(utf8String(bytes)) as unknown);

    expect(notice.removed_devices).toEqual([fx.bobDevice]);
    expect(notice.epoch).toBe(remove.wire.epoch);
    expect(notice.signed_by).toBe(km.identityPublicKey(alice));
    expect(() => new Date(notice.removed_at).toISOString()).not.toThrow();
  });

  it("carries only the removed devices — never the membership that remains", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    const bytes = await openRemovalNotice(
      crypto,
      GROUP,
      2,
      fx.secret,
      remove.wire.removal_notice ?? "",
      NOTICE_SIZE,
    );
    const text = utf8String(bytes);

    expect(text).not.toContain("alice");
    expect(text).not.toContain(km.devicePublicKey(alice));
  });

  it("is present and identically sized when nothing was removed", async () => {
    const fx = await groupWithBob("required");
    const quiet = await buildSetPolicy({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      policy: { min_managers: 1, removal_notice: "required" },
    });
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });

    // A relay comparing the two learns nothing: same length either way.
    expect(quiet.wire.removal_notice).toBeDefined();
    expect((quiet.wire.removal_notice ?? "").length).toBe(
      (remove.wire.removal_notice ?? "").length,
    );

    // ...and the padded one really is empty.
    const bytes = await openRemovalNotice(
      crypto,
      GROUP,
      2,
      fx.secret,
      quiet.wire.removal_notice ?? "",
      NOTICE_SIZE,
    );
    expect(bytes.length).toBe(0);
  });

  it("cannot be opened with the current epoch's secret", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    // Sealing under group_secret[e] instead of [e-1] would deliver the
    // notice to everyone except the person it is addressed to.
    await expect(
      openRemovalNotice(
        crypto,
        GROUP,
        2,
        remove.groupSecret,
        remove.wire.removal_notice ?? "",
        NOTICE_SIZE,
      ),
    ).rejects.toThrow();
  });

  it("genesis carries no notice", async () => {
    const genesis = await buildGenesis({
      crypto,
      signer: alice,
      groupId: GROUP,
      creatorUserId: "alice",
      policy: { min_managers: 1 },
    });
    expect(genesis.wire.removal_notice).toBeUndefined();
  });
});

describe("policy enforcement, both directions (spec §8.1, §9.1 check 11)", () => {
  it("required: rejects a removal whose notice was stripped", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    // Replace the notice with sealed padding — the shape a manager
    // suppressing a removal would produce.
    const stripped: WireTransition = {
      ...remove.wire,
      removal_notice: await sealRemovalNotice(
        crypto,
        GROUP,
        2,
        fx.secret,
        new Uint8Array(0),
        NOTICE_SIZE,
      ),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, stripped, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("suppressed: emits no notice, and rejects one that appears", async () => {
    const fx = await groupWithBob("suppressed");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });

    const bytes = await openRemovalNotice(
      crypto,
      GROUP,
      2,
      fx.secret,
      remove.wire.removal_notice ?? "",
      NOTICE_SIZE,
    );
    expect(bytes.length).toBe(0);

    // A manager who emits one anyway is refused.
    const chatty: WireTransition = {
      ...remove.wire,
      removal_notice: await sealRemovalNotice(
        crypto,
        GROUP,
        2,
        fx.secret,
        canonicalBytes({
          group_id: GROUP,
          epoch: 2,
          removed_devices: [fx.bobDevice],
          removed_at: "2026-01-01T00:00:00.000Z",
          signed_by: km.identityPublicKey(alice),
          signature: bytesToBase64Url(new Uint8Array(64)),
        }),
        NOTICE_SIZE,
      ),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, chatty, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("accepts a conforming removal under either policy", async () => {
    for (const mode of ["required", "suppressed"] as const) {
      const fx = await groupWithBob(mode);
      const remove = await buildRemoveMember({
        crypto,
        state: fx.state,
        signer: alice,
        currentGroupSecret: fx.secret,
        userId: "bob",
      });
      const verified = await verifyWireTransition(
        crypto,
        fx.state,
        remove.wire,
        remove.groupSecret,
        fx.secret,
      );
      expect(verified.noticeChecked).toBe(true);
    }
  });

  it("reports when check 11 could not run, rather than implying it passed", async () => {
    // A device restored from backup may not hold group_secret[e-1].
    // spec §9.1: that is not a failure, but it must not be recorded as
    // a pass either.
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    const verified = await verifyWireTransition(
      crypto,
      fx.state,
      remove.wire,
      remove.groupSecret,
    );
    expect(verified.noticeChecked).toBe(false);
  });
});

describe("notice forgery (spec §6.5)", () => {
  /** Seal an arbitrary notice as some signer, under epoch 1's secret. */
  async function forge(
    fx: Fixture,
    signer: DeviceKeys,
    patch: Partial<RemovalNotice> = {},
  ): Promise<string> {
    const unsigned = {
      group_id: GROUP,
      epoch: 2,
      removed_devices: [fx.bobDevice],
      removed_at: "2026-01-01T00:00:00.000Z",
      signed_by: km.identityPublicKey(signer),
      ...patch,
    };
    const signature = await crypto.ed25519Sign(
      signer.identity.privateKey,
      canonicalBytes(unsigned),
    );
    return sealRemovalNotice(
      crypto,
      GROUP,
      2,
      fx.secret,
      canonicalBytes({ ...unsigned, signature: bytesToBase64Url(signature) }),
      NOTICE_SIZE,
    );
  }

  // The case the signature exists for: bob holds group_secret[1] like
  // everyone else, so he can seal a perfectly well-formed notice. If
  // sealing were the only authentication, any peer could tell any other
  // member they had been removed — and applications act on that.
  it("rejects a notice sealed and signed by a non-manager peer", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    const forged: WireTransition = {
      ...remove.wire,
      removal_notice: await forge(fx, bob),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, forged, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects a notice whose signature does not verify", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    // Signed by alice over one payload, then the payload is changed.
    const tampered: WireTransition = {
      ...remove.wire,
      removal_notice: await forge(fx, alice, {
        removed_at: "1999-01-01T00:00:00.000Z",
        signature: bytesToBase64Url(new Uint8Array(64)),
      }),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, tampered, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(BadSignatureError);
  });

  it("rejects a notice listing devices the transition did not remove", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    const lying: WireTransition = {
      ...remove.wire,
      removal_notice: await forge(fx, alice, {
        removed_devices: [km.devicePublicKey(alice)],
      }),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, lying, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects a notice replayed onto another epoch", async () => {
    const fx = await groupWithBob("required");
    const remove = await buildRemoveMember({
      crypto,
      state: fx.state,
      signer: alice,
      currentGroupSecret: fx.secret,
      userId: "bob",
    });
    const replayed: WireTransition = {
      ...remove.wire,
      removal_notice: await forge(fx, alice, { epoch: 7 }),
    };
    await expect(
      verifyWireTransition(crypto, fx.state, replayed, remove.groupSecret, fx.secret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });
});

describe("removedDevices (spec §6.5)", () => {
  it("reports exactly the devices that left, in ascending order", () => {
    const before = [
      { user_id: "a", device_pubkeys: ["zzz", "aaa"], is_manager: true },
      { user_id: "b", device_pubkeys: ["mmm"], is_manager: false },
    ];
    const after = [{ user_id: "a", device_pubkeys: ["aaa"], is_manager: true }];
    expect(removedDevices(before, after)).toEqual(["mmm", "zzz"]);
    expect(removedDevices(before, before)).toEqual([]);
  });

  it("counts a device moved between members as neither added nor removed", () => {
    const before = [{ user_id: "a", device_pubkeys: ["k"], is_manager: true }];
    const after = [{ user_id: "b", device_pubkeys: ["k"], is_manager: true }];
    expect(removedDevices(before, after)).toEqual([]);
  });
});

describe("notice sizing (spec §6.5)", () => {
  it("refuses a notice too large for the profile", async () => {
    const huge = utf8Bytes("x".repeat(NOTICE_SIZE));
    await expect(
      sealRemovalNotice(crypto, GROUP, 1, new Uint8Array(32), huge, NOTICE_SIZE),
    ).rejects.toThrow();
  });

  it("rejects a notice padded to a different profile's size", async () => {
    const secret = crypto.randomBytes(32);
    const sealed = await sealRemovalNotice(
      crypto,
      GROUP,
      1,
      secret,
      new Uint8Array(0),
      CAPACITY_PROFILES.x.removalNoticeSize,
    );
    await expect(
      openRemovalNotice(crypto, GROUP, 1, secret, sealed, NOTICE_SIZE),
    ).rejects.toThrow();
  });
});
