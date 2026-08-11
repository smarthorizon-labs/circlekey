/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Frozen codec vectors (a non-negotiable invariant).
 *
 * `test/vectors/codec-v1.json` is FINAL: it freezes the canonical
 * encoding, transition signing bytes, chain hash, and genesis marker
 * for suite v1, and doubles as the interop reference for other
 * GroupVault implementations. If this suite fails after a code
 * change, the code is wrong — fix the code, never the vectors; a new
 * encoding is a new suite version with a new vector file.
 */

import { describe, expect, it } from "vitest";

import { WebCryptoProvider } from "../src/adapters/crypto/web";
import {
  canonicalize,
  genesisMarker,
  hashTransition,
  transitionSigningBytes,
} from "../src/core/codec";
import type { EpochTransition } from "../src/core/types";
import vectors from "./vectors/codec-v1.json";

const decoder = new TextDecoder();
const provider = new WebCryptoProvider();
const sha256 = (data: Uint8Array) => provider.sha256(data);

describe("codec-v1 vectors: canonicalization", () => {
  for (const entry of vectors.canonicalization) {
    it(entry.name, () => {
      expect(canonicalize(entry.input)).toBe(entry.canonical);
    });
  }
});

describe("codec-v1 vectors: genesis markers", () => {
  for (const entry of vectors.genesis_markers) {
    it(entry.group_id, async () => {
      expect(await genesisMarker(sha256, entry.group_id)).toBe(entry.marker);
    });
  }
});

describe("codec-v1 vectors: transitions", () => {
  for (const entry of vectors.transitions) {
    const transition = entry.transition as unknown as EpochTransition;

    it(`${entry.name}: signing bytes`, () => {
      expect(decoder.decode(transitionSigningBytes(transition))).toBe(
        entry.signing_string,
      );
    });

    it(`${entry.name}: chain hash`, async () => {
      expect(await hashTransition(sha256, transition)).toBe(entry.hash);
    });
  }

  it("links the chain: t1.prev_transition_hash === hash(t0)", () => {
    const [t0, t1] = vectors.transitions;
    expect(t1?.transition.prev_transition_hash).toBe(t0?.hash);
  });

  it("anchors genesis: t0.prev_transition_hash === genesis marker", () => {
    const [t0] = vectors.transitions;
    expect(t0?.transition.prev_transition_hash).toBe(vectors.genesis_markers[0]?.marker);
  });
});
