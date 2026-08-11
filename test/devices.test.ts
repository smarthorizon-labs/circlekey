/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Device linking (spec §9.5). Devices live in the epoch chain's
 * member set, changed by the self-scoped `add_device` action, so the
 * security question is: can a signer touch anything that isn't their
 * own device list? Every answer below must be no.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { InProcessLockProvider } from "../src/adapters/locks";
import { MemoryStore } from "../src/adapters/storage/memory";
import { MockTransport } from "../src/adapters/transport/mock";
import { GroupVault } from "../src/api/group-vault";
import { placeEnvelopes, sealEnvelope } from "../src/core/envelopes";
import { profileForPolicy } from "../src/core/profiles";
import {
  buildAddDevice,
  buildGenesis,
  buildRemoveDevice,
  replayChain,
  signTransition,
  verifyTransition,
} from "../src/core/epoch-chain";
import {
  MalformedTransitionError,
  ConflictError,
  UnauthorizedSignerError,
} from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import type { UnsignedEpochTransition } from "../src/core/codec";
import type { EpochTransition, MemberEntry, TransitionAction } from "../src/core/types";
import { completeEnrollment, FAST_BACKUP } from "./helpers";
import { canOpenEnvelope } from "./helpers";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);

function must<T>(value: T | undefined, what = "value"): T {
  if (value === undefined) throw new Error(`missing ${what}`);
  return value;
}

function vaultOptions(transport: MockTransport, userId: string, storage = new MemoryStore()) {
  return {
    transport,
    userId,
    crypto,
    storage,
    locks: new InProcessLockProvider(),
    requestPersistentStorage: false,
    backup: FAST_BACKUP,
  };
}

// ---------------------------------------------------------------------------
// Core verification: what an add_device transition may and may not do.
// ---------------------------------------------------------------------------

interface Fixture {
  alice: DeviceKeys;
  bob: DeviceKeys;
  spare: DeviceKeys;
  aliceLaptop: string;
  bobPhone: string;
  newDevice: string;
  state: GroupState; // alice (manager) + bob (member), epoch 1
  secret: Uint8Array;
  chain: EpochTransition[];
}

let fx: Fixture;

beforeAll(async () => {
  const alice = await km.generateDeviceKeys();
  const bob = await km.generateDeviceKeys();
  const spare = await km.generateDeviceKeys();

  const genesis = await buildGenesis({
    crypto,
    signer: alice,
    groupId: "dev-group",
    creatorUserId: "alice",
    policy: { min_managers: 1 },
  });
  let state = await verifyTransition(crypto, null, genesis.transition);

  const { buildAddMember } = await import("../src/core/epoch-chain");
  const add = await buildAddMember({
    crypto,
    state,
    signer: alice,
    currentGroupSecret: genesis.groupSecret,
    newMember: {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob)],
      is_manager: false,
    },
  });
  state = await verifyTransition(crypto, state, add.transition);

  fx = {
    alice,
    bob,
    spare,
    aliceLaptop: km.devicePublicKey(alice),
    bobPhone: km.devicePublicKey(bob),
    newDevice: km.devicePublicKey(spare),
    state,
    secret: add.groupSecret,
    chain: [genesis.transition, add.transition],
  };
});

interface CraftOptions {
  action: TransitionAction;
  members: MemberEntry[];
  signer: DeviceKeys;
}

/** Hand-craft a transition the builders would refuse to produce. */
async function craftFrom(
  state: GroupState,
  prevSecret: Uint8Array,
  options: CraftOptions,
): Promise<EpochTransition> {
  const epoch = state.epoch + 1;
  const secret = crypto.randomBytes(32);
  const envelopes = [];
  for (const device of options.members.flatMap((m) => m.device_pubkeys)) {
    envelopes.push(await sealEnvelope(crypto, device, epoch, secret));
  }
  const placed = placeEnvelopes(
    crypto,
    envelopes,
    epoch,
    profileForPolicy(state.policy).envelopeSlots,
  );
  const unsigned: UnsignedEpochTransition = {
    group_id: state.group_id,
    epoch,
    prev_transition_hash: state.last_transition_hash,
    action: options.action,
    members: options.members,
    envelope_slots: placed.slots,
    signed_by: km.identityPublicKey(options.signer),
  };
  return signTransition(crypto, unsigned, options.signer.identity.privateKey);
}

/** Craft against the shared two-member fixture state. */
const craft = (options: CraftOptions): Promise<EpochTransition> =>
  craftFrom(fx.state, fx.secret, options);

const withDevices = (userId: string, devices: string[], isManager: boolean): MemberEntry => ({
  user_id: userId,
  device_pubkeys: devices,
  is_manager: isManager,
});

describe("add_device verification (spec §9.5)", () => {
  it("accepts a member linking a device to their own entry", async () => {
    const built = await buildAddDevice({
      crypto,
      state: fx.state,
      signer: fx.bob, // a REGULAR member — no manager needed
      currentGroupSecret: fx.secret,
      newDevicePubkey: fx.newDevice,
    });
    const next = await verifyTransition(crypto, fx.state, built.transition);

    expect(next.epoch).toBe(2);
    const bob = must(next.members.find((m) => m.user_id === "bob"));
    expect(bob.device_pubkeys).toEqual([fx.bobPhone, fx.newDevice]);
    expect(bob.is_manager).toBe(false);
    // Alice untouched.
    expect(must(next.members.find((m) => m.user_id === "alice")).device_pubkeys).toEqual([
      fx.aliceLaptop,
    ]);
  });

  it("rejects editing another member's devices — even by a manager", async () => {
    // Alice (manager) tries to add a device to Bob's entry.
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], false),
      ],
      signer: fx.alice,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects a device action signed by a non-member", async () => {
    const outsider = await km.generateDeviceKeys();
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], false),
      ],
      signer: outsider,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects smuggling a privilege change alongside a device change", async () => {
    // Bob links a device AND promotes himself in one transition.
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], true),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects smuggling a membership change alongside a device change", async () => {
    const intruder = await km.generateDeviceKeys();
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], false),
        withDevices("mallory", [km.devicePublicKey(intruder)], false),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects changing two members' device lists at once", async () => {
    const extraA = await km.generateDeviceKeys();
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop, km.devicePublicKey(extraA)], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], false),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects a swap disguised as add_device", async () => {
    // Same list length: drop the real device, insert an attacker's.
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.newDevice], false),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects adding more than one device at once", async () => {
    const another = await km.generateDeviceKeys();
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices(
          "bob",
          [fx.bobPhone, fx.newDevice, km.devicePublicKey(another)],
          false,
        ),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("rejects an add_device that changes nothing", async () => {
    const bad = await craft({
      action: "add_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone], false),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("still rejects device changes hidden in a governance action", async () => {
    const bad = await craft({
      action: "promote",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone, fx.newDevice], true),
      ],
      signer: fx.alice,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });

  it("refuses at build time to link a device already in the group", async () => {
    await expect(
      buildAddDevice({
        crypto,
        state: fx.state,
        signer: fx.bob,
        currentGroupSecret: fx.secret,
        newDevicePubkey: fx.aliceLaptop,
      }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("refuses at build time when the acting device is not a member", async () => {
    const outsider = await km.generateDeviceKeys();
    await expect(
      buildAddDevice({
        crypto,
        state: fx.state,
        signer: outsider,
        currentGroupSecret: fx.secret,
        newDevicePubkey: fx.newDevice,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedSignerError);
  });

  it("envelopes the fresh secret to the new device, and the chain replays", async () => {
    const built = await buildAddDevice({
      crypto,
      state: fx.state,
      signer: fx.bob,
      currentGroupSecret: fx.secret,
      newDevicePubkey: fx.newDevice,
    });
    // Every current device — including the newly linked one — can open
    // an envelope; verified by trial decryption (spec §6.5).
    for (const keys of [fx.alice, fx.bob, fx.spare]) {
      expect(await canOpenEnvelope(crypto, keys, built.wire)).toBe(true);
    }

    const replayed = await replayChain(crypto, [...fx.chain, built.transition]);
    expect(replayed.epoch).toBe(2);
  });
});

describe("remove_device verification (spec §9.5)", () => {
  /** State where bob has two devices, so one can be removed. */
  async function twoDeviceState(): Promise<{ state: GroupState; secret: Uint8Array }> {
    const built = await buildAddDevice({
      crypto,
      state: fx.state,
      signer: fx.bob,
      currentGroupSecret: fx.secret,
      newDevicePubkey: fx.newDevice,
    });
    return {
      state: await verifyTransition(crypto, fx.state, built.transition),
      secret: built.groupSecret,
    };
  }

  it("accepts a member dropping one of their own devices", async () => {
    const { state, secret } = await twoDeviceState();
    const built = await buildRemoveDevice({
      crypto,
      state,
      signer: fx.bob,
      currentGroupSecret: secret,
      devicePubkey: fx.newDevice,
    });
    const next = await verifyTransition(crypto, state, built.transition);

    expect(must(next.members.find((m) => m.user_id === "bob")).device_pubkeys).toEqual([
      fx.bobPhone,
    ]);
    // The removed device opens nothing at any slot in the new epoch.
    expect(await canOpenEnvelope(crypto, fx.spare, built.wire)).toBe(false);
  });

  it("rejects removing another member's device — even by a manager", async () => {
    const { state, secret } = await twoDeviceState();
    const bad = await craftFrom(state, secret, {
      action: "remove_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone], false), // alice drops bob's device
      ],
      signer: fx.alice,
    });
    await expect(verifyTransition(crypto, state, bad)).rejects.toBeInstanceOf(
      UnauthorizedSignerError,
    );
  });

  it("rejects removing a member's last device", async () => {
    // Chain-level: bob has one device and the transition empties it.
    const bad = await craft({
      action: "remove_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [], false),
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, fx.state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );

    // Build-level: refused before anything is signed.
    await expect(
      buildRemoveDevice({
        crypto,
        state: fx.state,
        signer: fx.bob,
        currentGroupSecret: fx.secret,
        devicePubkey: fx.bobPhone,
      }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("refuses at build time to remove a device the member does not have", async () => {
    await expect(
      buildRemoveDevice({
        crypto,
        state: fx.state,
        signer: fx.bob,
        currentGroupSecret: fx.secret,
        devicePubkey: fx.aliceLaptop, // belongs to alice
      }),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects removing two devices at once", async () => {
    // Grow bob to three devices, then try to drop two in one go.
    const two = await twoDeviceState();
    const extra = await km.generateDeviceKeys();
    const third = await buildAddDevice({
      crypto,
      state: two.state,
      signer: fx.bob,
      currentGroupSecret: two.secret,
      newDevicePubkey: km.devicePublicKey(extra),
    });
    const state = await verifyTransition(crypto, two.state, third.transition);

    const bad = await craftFrom(state, third.groupSecret, {
      action: "remove_device",
      members: [
        withDevices("alice", [fx.aliceLaptop], true),
        withDevices("bob", [fx.bobPhone], false), // dropped two at once
      ],
      signer: fx.bob,
    });
    await expect(verifyTransition(crypto, state, bad)).rejects.toBeInstanceOf(
      MalformedTransitionError,
    );
  });
});

// ---------------------------------------------------------------------------
// End-to-end.
// ---------------------------------------------------------------------------

describe("link-device flow end to end", () => {
  it("a second device joins, reads history, and acts as the same user", async () => {
    const transport = new MockTransport();

    // Alice's laptop: enrolls, creates a group, writes a record.
    const laptop = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(laptop);
    const g = (await laptop.createGroup({ min_managers: 1 })).group_id;
    await laptop.putJsonRecord(g, "doc-1", { written: "on the laptop" });

    // A member exists too, to prove linking does not disturb others.
    const bobVault = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(bobVault);
    await laptop.addMember(g, {
      userId: "bob",
      devicePubkey: bobVault.devicePublicKey(),
    });
    await bobVault.syncGroup(g);

    // Alice's phone: a brand-new device with its own storage/identity.
    const phoneStorage = new MemoryStore();
    const phone = await GroupVault.open(vaultOptions(transport, "alice", phoneStorage));
    const phonePubkey = phone.devicePublicKey();
    expect(phonePubkey).not.toBe(laptop.devicePublicKey());

    // The phone cannot touch the group before it is linked.
    await expect(phone.syncGroup(g)).rejects.toThrow();

    // Link from the laptop (out-of-band pubkey transfer is the user's job).
    const result = await laptop.linkDevice(phonePubkey);
    expect(result.linked).toEqual([{ groupId: g, epoch: 2 }]);
    expect(result.skipped).toEqual([]);

    // The phone now joins by the ordinary path: verify chain, open its
    // envelope, walk the §9.7 history — no special-casing.
    await completeEnrollment(phone); // its own mandatory backup (spec §9.6)
    const phoneState = await phone.syncGroup(g);
    expect(phoneState.epoch).toBe(2);
    expect(laptop.devicesOf(g, "alice").sort()).toEqual(
      [laptop.devicePublicKey(), phonePubkey].sort(),
    );

    // It reads a record written before it existed (history chain).
    expect(await phone.getJsonRecord(g, "doc-1")).toEqual({ written: "on the laptop" });

    // It acts with Alice's authority — a manager op from the phone.
    await phone.addMember(g, {
      userId: "carol",
      devicePubkey: km.devicePublicKey(await km.generateDeviceKeys()),
    });
    const laptopView = await laptop.syncGroup(g);
    expect(laptopView.members.map((m) => m.user_id).sort()).toEqual([
      "alice",
      "bob",
      "carol",
    ]);

    // Both of Alice's devices, and Bob, converge on the same state.
    expect(await phone.syncGroup(g)).toEqual(laptopView);
    expect(await bobVault.syncGroup(g)).toEqual(laptopView);

    // Records written from either device are readable on the other.
    await phone.putJsonRecord(g, "doc-2", { written: "on the phone" });
    expect(await laptop.getJsonRecord(g, "doc-2")).toEqual({ written: "on the phone" });
  });

  it("cuts a removed device off from post-removal data", async () => {
    const transport = new MockTransport();

    // Alice runs a laptop and a phone; both are linked and in sync.
    const laptop = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(laptop);
    const g = (await laptop.createGroup({ min_managers: 1 })).group_id;
    await laptop.putJsonRecord(g, "before", { era: "both devices" });

    const phoneStorage = new MemoryStore();
    const phone = await GroupVault.open(vaultOptions(transport, "alice", phoneStorage));
    const phonePubkey = phone.devicePublicKey();
    await laptop.linkDevice(phonePubkey);
    await completeEnrollment(phone);
    await phone.syncGroup(g);
    expect(await phone.getJsonRecord(g, "before")).toEqual({ era: "both devices" });

    // 📱💧 The phone is lost. The laptop is the surviving device.
    expect(laptop.lostDeviceOptions(g, phonePubkey)).toEqual({
      route: "remove-from-other-device",
      usableDevices: [laptop.devicePublicKey()],
    });

    // create(0) → link(1) → unlink(2); records do not advance epochs.
    const result = await laptop.unlinkDevice(phonePubkey);
    expect(result.unlinked).toEqual([{ groupId: g, epoch: 2 }]);
    expect(laptop.devicesOf(g, "alice")).toEqual([laptop.devicePublicKey()]);

    // Data written after the removal is unreachable for the phone.
    await laptop.putJsonRecord(g, "after", { era: "laptop only" });

    // The unlink transition is sealed to a secret the phone no longer
    // receives, so it cannot open it and stops at its last accessible
    // epoch — loss of access rather than a verified eviction
    // (spec §6.5, §9.3).
    const phoneState = await phone.syncGroup(g);
    expect(phoneState.epoch).toBe(1);
    expect(await phoneStorage.getGroupSecret(g, 2)).toBeUndefined();
    await expect(phone.getJsonRecord(g, "after")).rejects.toThrow();

    // ...but what it legitimately held before remains readable — the
    // documented limitation, identical to member removal (spec §13).
    expect(await phone.getJsonRecord(g, "before")).toEqual({ era: "both devices" });

    // The phone also cannot act as Alice any more. It trips the
    // missing-secret guard before the signer check is even reached —
    // it was rekeyed out, so it has nothing to build a transition on.
    // The removed device is refused, but note *how*: it still holds the
    // epoch-1 secret, so it builds a rival epoch 2, loses the
    // uniqueness race, resyncs, cannot open the winning epoch 2, and
    // rebuilds the same losing transition until the retry bound is
    // spent. The refusal is solid; the diagnosis is poor, because a
    // removed device cannot distinguish removal from a relay that keeps
    // withholding (spec §9.3). Worth improving at the API layer.
    await expect(
      phone.setPolicy(g, { min_managers: 1 }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it("routes a lost sole device to backup restore, which needs no device action", async () => {
    const transport = new MockTransport();
    const laptop = await GroupVault.open(vaultOptions(transport, "alice"));
    const credential = await completeEnrollment(laptop);
    const g = (await laptop.createGroup({ min_managers: 1 })).group_id;
    await laptop.putJsonRecord(g, "doc", { keep: "me" });
    const laptopPubkey = laptop.devicePublicKey();

    // Only device lost: there is nothing to remove it *from*.
    expect(laptop.lostDeviceOptions(g, laptopPubkey)).toEqual({
      route: "restore-from-backup",
    });

    // Restore rebuilds the SAME device key, so the replacement is
    // already listed in the member set — no add_device needed.
    const replacement = await GroupVault.restore({
      ...vaultOptions(transport, "alice"),
      credential,
    });
    expect(replacement.devicePublicKey()).toBe(laptopPubkey);
    await replacement.syncGroup(g);
    expect(replacement.devicesOf(g, "alice")).toEqual([laptopPubkey]);
    expect(await replacement.getJsonRecord(g, "doc")).toEqual({ keep: "me" });
  });

  it("escalates to a manager when the member has no route of their own", async () => {
    const transport = new MockTransport();
    const owner = await GroupVault.open(vaultOptions(transport, "owner"));
    await completeEnrollment(owner);
    const g = (await owner.createGroup({ min_managers: 1 })).group_id;

    const bobVault = await GroupVault.open(vaultOptions(transport, "bob"));
    await completeEnrollment(bobVault);
    const bobPubkey = bobVault.devicePublicKey();
    await owner.addMember(g, { userId: "bob", devicePubkey: bobPubkey });
    await owner.syncGroup(g);

    // Bob lost his only device AND his credential. A manager cannot
    // remove someone else's device (self-scoping), so the route is
    // governance: remove the member, then re-add with a new device.
    await expect(
      owner.unlinkDeviceFromGroup(g, bobPubkey),
    ).rejects.toBeInstanceOf(MalformedTransitionError);

    await owner.removeMember(g, "bob");
    const bobReplacement = await km.generateDeviceKeys();
    const after = await owner.addMember(g, {
      userId: "bob",
      devicePubkey: km.devicePublicKey(bobReplacement),
    });
    expect(after.members.map((m) => m.user_id).sort()).toEqual(["bob", "owner"]);
    expect(owner.devicesOf(g, "bob")).toEqual([km.devicePublicKey(bobReplacement)]);
  });

  it("reports groups it cannot link into instead of failing outright", async () => {
    const transport = new MockTransport();
    const alice = await GroupVault.open(vaultOptions(transport, "alice"));
    await completeEnrollment(alice);
    const mine = (await alice.createGroup({ min_managers: 1 })).group_id;

    // A group Alice is removed from: linking must skip, not throw.
    const owner = await GroupVault.open(vaultOptions(transport, "owner"));
    await completeEnrollment(owner);
    const theirs = (await owner.createGroup({ min_managers: 1 })).group_id;
    await owner.addMember(theirs, {
      userId: "alice",
      devicePubkey: alice.devicePublicKey(),
    });
    await alice.syncGroup(theirs);
    await owner.removeMember(theirs, "alice");
    await alice.syncGroup(theirs); // sees the verified removal

    const spare = await km.generateDeviceKeys();
    const result = await alice.linkDevice(km.devicePublicKey(spare));
    expect(result.linked.map((entry) => entry.groupId)).toEqual([mine]);
    expect(result.skipped.map((entry) => entry.groupId)).toEqual([theirs]);
  });
});