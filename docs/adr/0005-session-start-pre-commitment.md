---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: [CT / RFC 6962 SCT design]
informed: []
supersedes: []
superseded_by: []
---

# 0005 — Mandatory session-start SCT-style pre-commitment

## Context and problem statement

If a `.jes` only anchors its Merkle root at session end, an adversarial submitter can fabricate an entire session post-hoc: run the agent, see what it did, construct a favorable canonical sequence, hash the root, anchor once. The anchor is real; the session, from the verifier's point of view, is indistinguishable from one that actually happened.

The only defense is to force a commitment before the first event is decided. In Certificate Transparency this is the Signed Certificate Timestamp (SCT): the log commits to including the leaf before the CA commits to issuing the certificate. The two-sided commitment is what makes fabrication detectable rather than merely prohibited.

`jesses` must have an analogous mechanism or its attestation is post-hoc narrative dressing.

## Decision drivers

- The pre-commitment must happen before any tool-call event can be recorded.
- The pre-commitment must be outside the submitter's control at the time of creation.
- The pre-commitment must be retrievable by a third-party verifier with no cooperation from the submitter.
- The mechanism must work with the v0.1 key model (software ed25519, ADR 0006) and not require TEE attestation.
- Omitting the pre-commitment must be detectable from the `.jes` alone, so a verifier can reject non-pre-committed attestations.

## Considered options

- Publish an SCT analog (session-start metadata) to Rekor before accepting any event
- Require a blockchain transaction per session start
- Rely on a commitment inside the first event's canonical form
- Derive "pre-commitment" synthetically from the key creation time
- No pre-commitment; accept fabrication as an open gap

## Decision outcome

**Chosen: mandatory Rekor-published session-start SCT analog.** Before the first `Append` on the audit log, the session emits a signed blob to Rekor containing: the session's public key fingerprint, the policy hash, and a nonce. The Rekor inclusion proof returned by that publication is then embedded as `session_start` in the final `.jes`. A verifier that does not find this pre-commitment, or finds one whose Rekor entry's inclusion timestamp is later than any event's timestamp, rejects the attestation.

### Positive consequences

- Fabricating an entire session now requires colluding with Rekor (or compromising it) to backdate a log entry. That is a qualitatively different threat than "the submitter ran it and lied."
- The v0.1 key model remains software-only; pre-commitment does not require hardware attestation.
- The inclusion proof is small (a few kilobytes) and fits inside the `.jes` without material bloat.
- The verifier's gate 2 (pre-commitment present and earlier than first event) is O(1) to check.

### Negative consequences

- Session startup now depends on Rekor availability. If Rekor is unreachable, the session cannot legitimately start. Operator guidance: retry with backoff, surface the outage to the user, do not allow a session that silently proceeded without pre-commitment.
- The pre-commitment blob inevitably contains metadata (public key fingerprint, policy hash). This is reviewed to ensure no session-private content is published.
- An adversary who can compromise Rekor operationally can still fabricate; see ADR 0004 for Rekor's v0.1 trust posture and the v0.2 federation plan that reduces this risk.

## Pros and cons of the options

### SCT analog on Rekor

- Good: reuses the transparency-log anchor we already integrate (ADR 0004)
- Good: proven CT design; reasoning about its guarantees is well-trodden
- Good: compatible with v0.1 software-key model
- Bad: introduces Rekor availability as a session-start dependency

### Blockchain transaction per session

- Good: strongest "outside the operator" property
- Bad: per-session cost (gas) makes this unworkable at scale
- Bad: confirmation latency multiplies session startup time by minutes
- Bad: adds multi-chain operational tax the project has ruled out

### Commitment inside the first event's canonical form

- Good: zero extra infrastructure
- Bad: does not defeat post-hoc fabrication — the submitter can choose what to put in the "first" event
- Bad: no detection mechanism for a verifier that has only the `.jes`

### Derived from key creation time

- Good: simple
- Bad: key creation time is set by the submitter's local clock; trivially forgeable
- Bad: does not prove "this session began at time T" — it proves "this key existed by time T", which is not the same statement

### No pre-commitment

- Good: simpler implementation
- Bad: post-hoc fabrication is undetectable. The project's entire value proposition dissolves. Not an acceptable v0.1 posture.

## Validation

- `internal/precommit` contains the implementation; a dedicated test asserts that a `.jes` missing `session_start` is rejected by `internal/verify` gate 2.
- `TestPrecommitTemporalOrdering` asserts that a `.jes` whose `session_start` Rekor inclusion-timestamp is later than any event's `ts` is rejected.
- `TestPrecommitForgedInclusion` asserts that a `.jes` with a fabricated `session_start` whose Rekor proof does not check out is rejected.
- End-to-end test in `examples/claude-code/` round-trips a session: the Rekor testnet entry is live-fetched during verification and the gate passes only when the actual Rekor record matches.

## Links

- [CT SCT design](https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
- `SPEC.md` §Pre-commitment
- `THREAT_MODEL.md` §3 (fabricate-session attack)
- ADR 0004 (Rekor as anchor)
- ADR 0006 (software ed25519 — the key whose public fingerprint is committed)
