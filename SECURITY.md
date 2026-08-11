# Security Policy

CircleKey implements real cryptography and handles key material. We
take security reports seriously and would rather hear about a problem
privately, early, and often, than not at all.

## Project status — read this first

CircleKey implements GroupVault Protocol v1 in full: every
client-observable MUST and MUST NOT in spec §5–§13 is satisfied and
held by a named test, mapped requirement-by-requirement in
[docs/conformance.md](./docs/conformance.md).

It has **not been independently security-audited by a third party.**
Conformance means the implementation matches the specification — it is
not a statement that either is free of flaws, and it is not a
substitute for external review.

**Make your own security assessment before production use**,
proportionate to what you intend to protect. We have tested our own
work thoroughly and documented exactly which test holds which
guarantee; no one outside the project has checked it yet. Judge the
residual risk yourself rather than taking ours on trust.

Reports that boil down to "the README already says this is unaudited"
are still welcome if they identify a concrete flaw — see below for what
we're most interested in.

## Reporting a vulnerability

**Please do not open a public issue for security reports.** Instead,
email:

**security@circlekey.io**

> **Maintainers:** this mailbox must be provisioned and monitored
> before the repository is made public — a security policy pointing at
> a dead address is worse than none. Remove this note once confirmed.

If you'd like to encrypt your report, ask for our PGP key in an
initial (non-sensitive) email and we'll provide one.

Please include, as available:

- A description of the issue and its potential impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The commit hash or version you tested against.
- Whether the issue is in the **protocol** (the protocol specification) or in
  **this implementation** (`src/`) — see below, since the fix path
  differs.

### What happens next

- We aim to acknowledge new reports within **5 business days**.
- We'll work with you to understand and confirm the issue, and agree on
  a disclosure timeline. As a small team, we ask for reasonable patience
  but commit to keeping you updated.
- With your permission, we credit reporters in the fix's release notes
  and commit message. Let us know if you'd prefer to stay anonymous.
- Please give us a reasonable window to ship a fix before public
  disclosure. If we go quiet for an extended period, escalate — that's
  a process failure on our end, not a reason to assume the report was
  dismissed.

## Scope

**In scope:**
- This repository (`src/`, including all `core/`, `managers/`,
  `adapters/`, `api/`, and `ports/` code).
- The protocol specification (the protocol specification) — if you find a flaw in the
  *design* (not just this implementation of it), please report it the
  same way; protocol-level issues affect every conforming
  implementation, not just this one.

**Out of scope / please use normal issues instead:**
- The interactive tutorials on https://circlekey.io (demo code, not
  library code) — unless the issue reveals a flaw in the library
  itself.
- Missing features already tracked on the roadmap in the README —
  e.g. "there is no streaming API for large files yet" is expected,
  not a vulnerability.
- Issues that only reproduce with a deliberately malicious *local*
  environment (compromised browser extension, root access to the
  device) — this is explicitly outside the threat model
  ([spec §13](https://github.com/groupvault/protocol/blob/main/README.md#13-threat-model)).

## What we're especially interested in

Given the project's stage, these categories are the highest-value
reports:

- A transition that **should** be rejected by the [spec §9.1
  checklist](https://github.com/groupvault/protocol/blob/main/README.md#91-epoch-transition-format-and-verification)
  but is accepted (or vice versa).
- A path where plaintext, a private key, a `group_secret`, or the
  backup recovery credential could reach the `Transport` port
  (spec §5.1) — this must never happen.
- A nonce-reuse or key-usage-bound bypass (spec §6.1).
- A way to violate the `min_managers` invariant (spec §5.6, §8.1),
  even transiently.
- A discrepancy between the canonical encoding used for signing/hashing
  (see the architecture guide) and what the frozen test vectors
  (`test/vectors/`) assert — this breaks interoperability between
  implementations, which is a protocol-level concern.
- Anything that lets a removed member decrypt data created *after*
  their removal (this would violate spec §9.3's immediate-revocation
  guarantee — as opposed to data legitimately accessed before removal,
  which is a documented, intentional limitation, not a bug).

## Threat model

See [spec §13](https://github.com/groupvault/protocol/blob/main/README.md#13-threat-model) for what the protocol is
designed to protect against (a curious/compromised backend, network
interception, storage compromise) and what it explicitly does not
(client-side malware, a removed member retaining previously-legitimate
access, availability denial by an uncooperative backend).

## Security-relevant design invariants

For context on what "a real vulnerability" looks like in this
codebase, the non-negotiable invariants are listed in
[docs/architecture.md](./docs/architecture.md#non-negotiable-invariants). Any change that
weakens one of them — even a passing test suite — is treated as a
regression.
