---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0004 — OpenTimestamps + Rekor as the sole external anchors

## Context and problem statement

A `.jes` proves a session happened and its events are internally consistent, but the Merkle root itself means nothing unless it was committed to a medium outside the maintainer's control at a time the maintainer cannot later retro-date. External anchoring is what turns a self-signed log into a log whose history is independently attestable.

There are many candidates: public blockchains (Bitcoin, Ethereum, various L2s), transparency logs (Rekor, CT), third-party timestamping services, and in principle any public append-only medium. Which anchors are worth the integration and operational weight?

## Decision drivers

- The anchor must be genuinely outside the maintainer's control at the moment of anchoring.
- The anchor must be free or near-free per event at the volume `jesses` generates (one root anchor per session, thousands of sessions per day at scale).
- The anchor must have a documented public verification path so a third party can independently confirm the anchor without trusting the project.
- No blockchain beyond what is strictly required. Multi-chain integrations are a permanent operational tax for marginal added assurance.

## Considered options

- OpenTimestamps (Bitcoin via Merkle aggregation) + Rekor (Sigstore transparency log)
- Add Ethereum / L2 anchoring for "blockchain diversity"
- Use Rekor alone (skip OTS)
- Use OTS alone (skip Rekor)
- Proprietary timestamping authority (DigiStamp, Surety, etc.)

## Decision outcome

**Chosen: OpenTimestamps + Rekor, and no other external anchors.** OpenTimestamps batches thousands of roots into a single Bitcoin transaction via Merkle aggregation, making the per-session marginal cost effectively zero while inheriting Bitcoin's confirmation guarantees. Rekor publishes DSSE-envelope inclusion with a short latency and is natively consumed by the verifier tooling we already inherit (ADR 0002).

### Positive consequences

- Every session root is anchored in two independent, publicly auditable media. A third-party verifier can independently confirm both.
- Integration cost is bounded: one OTS client, one Rekor client, both small Go modules.
- No smart-contract maintenance burden; no gas fees; no governance exposure to L2 operators.
- If either anchor fails temporarily (Rekor outage, OTS calendar outage), the other continues working. Both failing simultaneously is highly correlated only with a global Bitcoin + Sigstore outage, at which point much of the internet is unavailable anyway.

### Negative consequences

- Bitcoin confirmation latency is minutes to hours. A verifier that requires OTS confirmation before accepting a `.jes` must either wait or treat the OTS proof as "upgrading" over time. The verifier spec addresses this with a confirmation-depth policy.
- We inherit the trust assumptions of Rekor's operators (currently Sigstore-run). If Rekor is compromised, half of our anchor assurance degrades until alternate log federation (v0.2+).
- OpenTimestamps relies on its calendar server network. We accept their availability profile and document it in `THREAT_MODEL.md` §External dependencies.

## Pros and cons of the options

### OpenTimestamps + Rekor

- Good: two independent anchors; both free at our volume; both have documented verifier paths
- Good: no project-operated infrastructure required
- Bad: inherits external operator trust for Rekor; v0.1 uses single-operator Rekor until federation ships

### Additional blockchain(s)

- Good: "diversity" headline
- Bad: smart-contract or on-chain anchoring introduces continual gas cost and a new attack surface (smart-contract bugs, bridge risk)
- Bad: no added assurance once Bitcoin-via-OTS is in place; diminishing returns are steep

### Rekor alone

- Good: one less integration
- Bad: single-operator risk; no cross-medium redundancy; split-view attack defense is weaker

### OTS alone

- Good: Bitcoin-backed
- Bad: long confirmation latency; fresh attestations have only local assurance until the next Bitcoin block ties them down

### Proprietary TSA

- Good: RFC 3161 is a standard
- Bad: proprietary operator trust; commercial per-timestamp fees do not scale
- Bad: not widely integrated with the Sigstore ecosystem we inherit

## Validation

- `internal/ots` and `internal/rekor` clients ship with v0.1; integration tests use the Rekor public testnet and an OTS calendar.
- The verifier emits distinct gate results for "anchor present", "anchor inclusion proof valid", and "anchor depth / confirmation sufficient". The depth threshold is a verifier policy knob, documented in `SPEC.md`.
- A test in `internal/verify` ensures that a `.jes` with a forged anchor fails gate 4 regardless of whether any other gate passes.

## Links

- [OpenTimestamps](https://opentimestamps.org/)
- [Rekor](https://docs.sigstore.dev/logging/overview/)
- `SPEC.md` §Verify gates 3 and 4
- `THREAT_MODEL.md` §External dependencies
- ADR 0003 (Merkle tree) — the root is what gets anchored
- ADR 0005 (pre-commitment) — uses Rekor as the anchor for the session-start SCT analog
