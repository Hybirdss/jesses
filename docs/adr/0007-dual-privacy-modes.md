---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0007 — Dual privacy modes (raw inputs vs input-hash only)

## Context and problem statement

Two audiences consume `.jes` files with incompatible privacy requirements.

Bounty-platform triage teams want the raw inputs (the actual URL a tool was called against, the actual path a file was read at) so they can tell whether the hunter stayed inside program scope. Without raw destinations, the `.jes` is evidence of a session but not evidence of compliance with scope.

Enterprise compliance teams pulling `.jes` files from an internal agent fleet want the opposite: an attestation that proves the session stayed inside its authorized action envelope without exfiltrating the internal URLs, database hostnames, or customer identifiers the session touched.

The envelope format, the Merkle leaves, and the signing primitives are the same for both cases. What differs is whether the canonical `Event` carries raw input fields or hashes of them.

## Decision drivers

- A single `.jes` format that supports both cases without forking the specification.
- Verifier binaries should accept both modes without a mode-specific code path beyond reading a single flag.
- The privacy mode must be detectable from the `.jes` without accessing the raw inputs, so a verifier knows which representation to expect in the leaves.
- Leaf hashes must be identical in both modes for the same underlying event up to the input field transformation; this preserves consistency-proof integrity regardless of mode.
- A future auditor with access to the raw inputs must be able to verify they hash to the leaf's input-hash field in hash-only mode.

## Considered options

- Two modes, selected per-session: `privacy=off` (raw), `privacy=on` (hash of inputs, deterministic)
- Separate predicate URIs for the two modes
- Always store raw inputs; let consumers decide what to redact at export time
- Always store only input-hashes; lose raw-input attestation entirely

## Decision outcome

**Chosen: two modes under the same predicate URI, selected per session by policy configuration.** The `Event` schema carries both `input_raw` (optional) and `input_hash` (always present). In `privacy=off` mode, `input_raw` is populated and `input_hash` is the hash of its canonical serialization. In `privacy=on` mode, `input_raw` is omitted and `input_hash` is the hash of the raw input computed locally and never emitted. The leaf hash is a function of `input_hash` and other fixed fields, so it is identical in both modes for the same underlying session.

### Positive consequences

- A verifier does not care which mode the producer used; it checks the same gates either way.
- A compliance officer can publish `privacy=on` attestations knowing that internal destinations never leave the producing machine.
- A bounty-platform intake can verify the raw destinations it needs in `privacy=off` mode without a separate file format.
- A future auditor given the raw inputs can re-derive and match `input_hash` for every event in a `privacy=on` attestation.

### Negative consequences

- Verifier implementers must handle both cases — one extra conditional branch per event.
- Producers misconfiguring their policy can accidentally leak (setting `privacy=off` when they meant `on`). Mitigation: CLI warnings, policy-file linting, and clear documentation.
- The schema carries an always-optional field (`input_raw`) which is a mild footgun; strict JSON validators must accept either presence or absence.

## Pros and cons of the options

### Two modes, one predicate URI

- Good: one format, one verifier code path
- Good: leaf hash invariant under mode selection
- Bad: optional field in the canonical schema — handled by clear specification

### Separate predicate URIs per mode

- Good: clearer-at-a-glance which mode a `.jes` is in
- Bad: two predicates to version in parallel forever; doubles the surface the TypeScript verifier must cover
- Bad: no technical benefit over a single mode flag

### Raw-only, redact at export

- Good: simplest producer
- Bad: redaction after the fact breaks Merkle leaf hashes; the `.jes` is no longer self-consistent after export redaction
- Bad: any tooling that forgets to redact leaks; attack surface expanded

### Hash-only

- Good: strongest privacy default
- Bad: unusable for bounty triage; defeats one of the two principal audiences

## Validation

- `spec/v0.1/test-vectors/privacy-off.jes` and `privacy-on.jes` exercise both modes end-to-end and share the same Merkle root for the same underlying session events (only `input_raw` differs; `input_hash` and leaf hash are identical).
- Verifier tests confirm that gate semantics are mode-independent.
- A policy-lint test rejects a scope whose `mode:` field is inconsistent with the emitting privacy mode (a future enhancement; tracked).

## Links

- `SPEC.md` §Event schema
- `SPEC.md` §Privacy modes
- `THREAT_MODEL.md` §Inadvertent disclosure
- ADR 0003 (Merkle tree) — leaf hash function is mode-independent
