# Contributing to CircleKey

Thanks for considering a contribution. CircleKey is the reference
implementation of the open [GroupVault Protocol](https://github.com/groupvault/protocol/blob/main/README.md), and we
want it to earn trust the way protocol implementations should:
readable, well-tested, and honest about what it does and doesn't do
yet.

This document is the short version. For the *why* behind the rules
below, read [docs/architecture.md](./docs/architecture.md) — how the
library is arranged, the non-negotiable invariants, and the
pitfalls that are easy to walk into.

## Before you start

- **Questions or design discussion:** open an issue first for anything
  non-trivial. It's much cheaper to align before code is written than
  after.
- **Protocol-level issues** (a flaw or ambiguity in the protocol specification itself,
  not just this implementation) are welcome too — label the issue
  `spec-discussion`. Don't edit the protocol specification to make implementation
  easier; if it seems wrong, raise it.
- **Security vulnerabilities** go through [SECURITY.md](./SECURITY.md),
  not a public issue.
- Look for issues labeled `good first issue` (small, self-contained) or
  `help wanted` (roadmap items) if you're not sure where to start.

## Development setup

Requires **Node.js ≥ 20**.

```bash
git clone https://github.com/smarthorizon-labs/circlekey.git
cd circlekey
npm install
npm test          # should be green before you change anything
```

| Command | What it does |
|---|---|
| `npm test` | Run the test suite once (vitest) |
| `npm run test:watch` | Watch mode |
| `npm run typecheck` | `tsc --noEmit`, strict mode |
| `npm run lint` | ESLint over the whole repo |
| `npm run build` | Build `dist/` (tsup) |

**Before opening a merge request, all four must pass:**
```bash
npm run typecheck && npm run lint && npm test && npm run build
```
This is also what CI runs on every push and merge request, on Node 20
and 22.

## The rules that matter most

These aren't style preferences — they're what makes this a trustworthy
implementation of a security protocol. Merge requests that violate
them will be asked to change regardless of how the rest of the code
looks.

- **Respect the layering** ([docs/architecture.md](./docs/architecture.md)):
  `src/core/` is pure — no platform APIs, no I/O, no managers, no
  adapters. Only `SyncManager` touches `Transport`; only `adapters/`
  touches IndexedDB/WebCrypto. Protocol wire types live in
  `core/types.ts` only.
- **No new runtime dependencies** without discussion first. The
  allowlist is `@noble/curves` and `hash-wasm`, both used only inside
  the default `CryptoProvider` adapter. Never hand-roll a
  cryptographic primitive — compose audited libraries.
- **Cite the spec.** Where code implements a normative requirement,
  reference the section: `// spec §9.3 step 3`. It's how a reviewer
  (or a future implementer in another language) checks the code
  against the protocol, not just against itself.
- **Typed errors, never bare `Error`.** Every failure is a subclass of
  `CircleKeyError` (see `core/errors.ts` and
  [docs/architecture.md](./docs/architecture.md)). If your change needs a
  new failure mode, add a specific error class.
- **TypeScript `strict`, ESM, named exports only.**
- **Don't touch the canonical encoding or the frozen test vectors**
  (`test/vectors/*.json`) casually. They're the interoperability
  contract other implementations build against
  ([docs/architecture.md](./docs/architecture.md)). If a change legitimately
  requires updating them, say so explicitly in the merge request
  description — a silent vector diff is a red flag, not a routine
  change.

## Testing bar

We weight **rejection-path tests** over happy-path tests — proving we
correctly refuse bad input matters more here than proving we accept
good input, because this is the code standing between a hostile
backend and a client's data.

- Every check in the [spec §9.1 verification
  checklist](https://github.com/groupvault/protocol/blob/main/README.md#91-epoch-transition-format-and-verification)
  and every governance invariant needs an explicit test proving we
  *reject* the violation, not just one proving we accept the valid
  case.
- New protocol-facing behavior should come with adversarial
  `MockTransport` cases where relevant: replay, fork, gap, signature
  swap → a typed error and (where applicable) an event, never a
  silent failure.
- All tests run fully offline against `MemoryStore` + `MockTransport` —
  no real network, no real backend, no sleeps. If your test needs
  either, something's probably wrong with the design.

## Commit / merge request conventions

- **Sign off your commits** (Developer Certificate of Origin):
  `git commit -s` adds a `Signed-off-by:` trailer certifying you have
  the right to submit the contribution under the project's license.
  This is how we keep the project's licensing clean without requiring
  a separate CLA.
- Keep merge requests focused — one logical change per MR is much
  easier to review than a bundle of unrelated ones.
- Describe *why*, not just *what*, in the MR description, especially
  for anything touching `core/`.
- Update [docs/architecture.md](./docs/architecture.md) in the same
  pull request if you're making (or changing) a design decision the
  guide should reflect — it's meant to stay in sync with reality, not
  describe an aspirational state.

## Code of conduct

Be respectful, assume good faith, and keep disagreements about the
work, not the person. Security and protocol design attract strong
opinions — that's healthy, as long as it stays technical. Reports of
conduct issues can go to the same address as
[SECURITY.md](./SECURITY.md)'s contact.

## License

By contributing, you agree that your contributions are licensed under
the project's [Mozilla Public License 2.0](./LICENSE).
