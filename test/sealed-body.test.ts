/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Sealed transition bodies — spec §6.5 and the §9.1 outer checks
 *.
 *
 * The most important case in this file is the last one: a body that
 * **decrypts** but is **not authorized**. Spec §9.1 is explicit that
 * opening a sealed body proves a member wrote it and nothing more, and
 * an implementation that accepted on successful decrypt would pass
 * every other test here while having removed the entire trust root.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import { base64UrlToBytes, bytesToBase64Url, utf8Bytes } from "../src/core/bytes";
import { canonicalBytes } from "../src/core/codec";
import { openTransitionBody, sealTransitionBody } from "../src/core/envelopes";
import {
  buildAddMember,
  buildGenesis,
  openWireTransition,
  replayWireChain,
  signTransition,
  verifyWireTransition,
} from "../src/core/epoch-chain";
import {
  EnvelopeError,
  MalformedTransitionError,
  UnauthorizedSignerError,
} from "../src/core/errors";
import type { GroupState } from "../src/core/group-state";
import { KeyManager, type DeviceKeys } from "../src/core/key-manager";
import { CAPACITY_PROFILES } from "../src/core/profiles";
import { deriveRelayAuthPublicKey } from "../src/core/relay-auth";
import type { EpochTransition, WireTransition } from "../src/core/types";

const crypto = new WebCryptoProvider();
const km = new KeyManager(crypto);
const GROUP = "sealed-body-group";
const BODY_SIZE = CAPACITY_PROFILES.lite.sealedBodySize;

let alice: DeviceKeys;
let bob: DeviceKeys;
let genesis: Awaited<ReturnType<typeof buildGenesis>>;
let state0: GroupState;
let addBob: Awaited<ReturnType<typeof buildAddMember>>;
let state1: GroupState;

beforeAll(async () => {
  alice = await km.generateDeviceKeys();
  bob = await km.generateDeviceKeys();
  genesis = await buildGenesis({
    crypto,
    signer: alice,
    groupId: GROUP,
    creatorUserId: "alice",
    policy: { min_managers: 1 },
  });
  state0 = (await verifyWireTransition(crypto, null, genesis.wire, genesis.groupSecret)).state;
  addBob = await buildAddMember({
    crypto,
    state: state0,
    signer: alice,
    currentGroupSecret: genesis.groupSecret,
    newMember: {
      user_id: "bob",
      device_pubkeys: [km.devicePublicKey(bob)],
      is_manager: false,
    },
  });
  state1 = (await verifyWireTransition(crypto, state0, addBob.wire, addBob.groupSecret)).state;
});

/**
 * The §9.7 history link moved from the inner body to the outer wire in
 * the outer layer, and its rejection tests did not move with it — the verifier kept
 * enforcing all three rules while nothing exercised them. Found by
 * auditing docs/conformance.md against the suite: rows 9.1-G6,
 * 9.1-S6, 9.7-1 and 9.7-2 all cited tests that no longer existed.
 */
describe("§9.7 history link, now an outer field (spec §9.1 check 6)", () => {
  it("rejects a genesis carrying a history link", async () => {
    const wire: WireTransition = {
      ...genesis.wire,
      prev_secret_ciphertext: addBob.wire.prev_secret_ciphertext ?? "x",
    };
    await expect(
      verifyWireTransition(crypto, null, wire, genesis.groupSecret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects a successor transition without a history link", async () => {
    const wire: WireTransition = { ...addBob.wire };
    delete wire.prev_secret_ciphertext;
    await expect(
      verifyWireTransition(crypto, state0, wire, addBob.groupSecret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects a malformed history link blob", async () => {
    for (const blob of ["", "!!!not-base64url!!!", "AA"]) {
      await expect(
        verifyWireTransition(
          crypto,
          state0,
          { ...addBob.wire, prev_secret_ciphertext: blob },
          addBob.groupSecret,
        ),
      ).rejects.toBeInstanceOf(MalformedTransitionError);
    }
  });
});

describe("sealed body round-trip (spec §6.5)", () => {
  it("seals to a fixed size regardless of payload, and opens back", async () => {
    const small = utf8Bytes('{"a":1}');
    const large = utf8Bytes(JSON.stringify({ padding: "x".repeat(2000) }));

    const sealedSmall = await sealTransitionBody(
      crypto,
      GROUP,
      3,
      genesis.groupSecret,
      small,
      BODY_SIZE,
    );
    const sealedLarge = await sealTransitionBody(
      crypto,
      GROUP,
      3,
      genesis.groupSecret,
      large,
      BODY_SIZE,
    );

    // The whole point of padding: a 7-byte body and a 2 KiB body are
    // the same length on the wire (spec §5.8 rule 3).
    expect(base64UrlToBytes(sealedSmall).length).toBe(base64UrlToBytes(sealedLarge).length);

    const opened = await openTransitionBody(crypto, GROUP, 3, genesis.groupSecret, sealedSmall);
    expect(opened.innerBytes).toEqual(small);
    expect(opened.paddedSize).toBe(BODY_SIZE);
  });

  it("refuses a body that outgrows its capacity profile", async () => {
    const huge = utf8Bytes("x".repeat(BODY_SIZE));
    await expect(
      sealTransitionBody(crypto, GROUP, 1, genesis.groupSecret, huge, BODY_SIZE),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("cannot be opened with another epoch's secret", async () => {
    await expect(
      openTransitionBody(crypto, GROUP, 0, addBob.groupSecret, genesis.wire.sealed_body),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });
});

describe("outer checks O2-O4 (spec §9.1)", () => {
  it("O2: rejects a tampered sealed body", async () => {
    const blob = base64UrlToBytes(genesis.wire.sealed_body);
    blob.set([(blob.at(-1) ?? 0) ^ 0xff], blob.length - 1);
    const wire: WireTransition = { ...genesis.wire, sealed_body: bytesToBase64Url(blob) };

    await expect(
      verifyWireTransition(crypto, null, wire, genesis.groupSecret),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("O2: rejects a body relabelled onto another epoch — AAD binding", async () => {
    // The body is genuine; only the routing epoch was changed.
    const wire: WireTransition = { ...addBob.wire, epoch: 5 };
    await expect(
      verifyWireTransition(crypto, state0, wire, addBob.groupSecret),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("O2: rejects a body relabelled onto another group", async () => {
    const wire: WireTransition = { ...genesis.wire, group_id: "another-group" };
    await expect(
      verifyWireTransition(crypto, null, wire, genesis.groupSecret),
    ).rejects.toBeInstanceOf(EnvelopeError);
  });

  // O3 is redundant with the AAD by construction, so it is provoked by
  // sealing a body whose inner routing values disagree with the outer
  // ones — the shape a broken-AAD implementation would produce.
  it("O3: rejects inner/outer group_id and epoch mismatches", async () => {
    for (const patch of [{ group_id: "elsewhere" }, { epoch: 9 }]) {
      const forged: EpochTransition = { ...genesis.transition, ...patch };
      const wire: WireTransition = {
        ...genesis.wire,
        sealed_body: await sealTransitionBody(
          crypto,
          GROUP,
          0,
          genesis.groupSecret,
          canonicalBytes(forged),
          BODY_SIZE,
        ),
      };
      await expect(
        openWireTransition(crypto, wire, genesis.groupSecret),
      ).rejects.toBeInstanceOf(MalformedTransitionError);
    }
  });

  it("O4: rejects a body padded to the wrong profile size", async () => {
    const wire: WireTransition = {
      ...genesis.wire,
      sealed_body: await sealTransitionBody(
        crypto,
        GROUP,
        0,
        genesis.groupSecret,
        canonicalBytes(genesis.transition),
        CAPACITY_PROFILES.x.sealedBodySize,
      ),
    };
    await expect(
      verifyWireTransition(crypto, null, wire, genesis.groupSecret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });

  it("rejects an auth_pubkey nobody can derive (spec §9.1 check 7)", async () => {
    const foreign = await deriveRelayAuthPublicKey(crypto, crypto.randomBytes(32));
    const wire: WireTransition = {
      ...genesis.wire,
      auth_pubkey: bytesToBase64Url(foreign),
    };
    await expect(
      verifyWireTransition(crypto, null, wire, genesis.groupSecret),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });
});

// `acceptedState` must carry the *whole* policy forward, not just
// `min_managers`. Dropping `capacity` and `removal_notice` would
// resolve every group to the `lite` profile, and leave the
// capacity-immutability check comparing undefined with undefined — so
// it would enforce nothing. A lite-only suite cannot see any of that,
// which is why these cases use the `x` profile.
describe("capacity profile survives verification (spec §6.5, §8.1)", () => {
  it("an x-profile group verifies against x sizes, not the default", async () => {
    const g = await buildGenesis({
      crypto,
      signer: alice,
      groupId: "x-group",
      creatorUserId: "alice",
      policy: { min_managers: 1, capacity: "x" },
    });
    const { state } = await verifyWireTransition(crypto, null, g.wire, g.groupSecret);

    expect(state.policy.capacity).toBe("x");
    expect(g.wire.secret_envelopes).toHaveLength(CAPACITY_PROFILES.x.envelopeSlots);

    // The body really is padded to the x size — which the verifier just
    // accepted, so the two agree.
    const opened = await openTransitionBody(
      crypto,
      "x-group",
      0,
      g.groupSecret,
      g.wire.sealed_body,
    );
    expect(opened.paddedSize).toBe(CAPACITY_PROFILES.x.sealedBodySize);
  });

  it("carries the removal_notice policy into verified state", async () => {
    const g = await buildGenesis({
      crypto,
      signer: alice,
      groupId: "quiet-group",
      creatorUserId: "alice",
      policy: { min_managers: 1, removal_notice: "suppressed" },
    });
    const { state } = await verifyWireTransition(crypto, null, g.wire, g.groupSecret);
    expect(state.policy.removal_notice).toBe("suppressed");
  });
});

describe("catch-up: backward then forward (spec §9.1)", () => {
  it("replays a wire chain once every secret is recovered", async () => {
    const secrets = new Map([
      [0, genesis.groupSecret],
      [1, addBob.groupSecret],
    ]);
    const replayed = await replayWireChain(crypto, [genesis.wire, addBob.wire], secrets);

    expect(replayed.state).toEqual(state1);
    expect(replayed.transitions.map((t) => t.action)).toEqual(["create", "add"]);
  });

  it("refuses to replay past the epoch whose secret it lacks", async () => {
    const secrets = new Map([[0, genesis.groupSecret]]);
    await expect(
      replayWireChain(crypto, [genesis.wire, addBob.wire], secrets),
    ).rejects.toBeInstanceOf(MalformedTransitionError);
  });
});

// ---------------------------------------------------------------------------
// The case that matters most.
// ---------------------------------------------------------------------------

describe("decryption is authentication, never authorization (spec §9.1)", () => {
  it("rejects a body that decrypts but is not authorized to do what it says", async () => {
    // Bob is a regular member. He can seal a body that every verifier
    // will open, and sign it with his own key. He forges a promotion
    // of himself to manager.
    const forgedInner = {
      group_id: GROUP,
      epoch: 2,
      prev_transition_hash: state1.last_transition_hash,
      action: "promote" as const,
      members: state1.members.map((member) =>
        member.user_id === "bob" ? { ...member, is_manager: true } : { ...member },
      ),
      envelope_slots: addBob.transition.envelope_slots,
      signed_by: km.identityPublicKey(bob),
    };
    const signed = await signTransition(crypto, forgedInner, bob.identity.privateKey);

    const forgedSecret = crypto.randomBytes(32);
    const wire: WireTransition = {
      group_id: GROUP,
      epoch: 2,
      sealed_body: await sealTransitionBody(
        crypto,
        GROUP,
        2,
        forgedSecret,
        canonicalBytes(signed),
        BODY_SIZE,
      ),
      secret_envelopes: addBob.wire.secret_envelopes,
      auth_pubkey: bytesToBase64Url(await deriveRelayAuthPublicKey(crypto, forgedSecret)),
    };
    if (addBob.wire.prev_secret_ciphertext !== undefined) {
      wire.prev_secret_ciphertext = addBob.wire.prev_secret_ciphertext;
    }

    // It opens. That is the trap: the body is authentic, the padding is
    // right, the AAD binds, the signature over it verifies, and
    // auth_pubkey is derivable. Every outer check passes.
    await expect(openWireTransition(crypto, wire, forgedSecret)).resolves.toBeDefined();

    // And it is still refused, because a non-manager may not promote
    // (spec §9.1 check 3). This is the whole trust root.
    await expect(
      verifyWireTransition(crypto, state1, wire, forgedSecret),
    ).rejects.toBeInstanceOf(UnauthorizedSignerError);
  });
});
