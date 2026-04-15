# Security Policy

`jesses` is an attestation primitive for AI-authored security deliverables. Bugs in `jesses` itself — especially in the verifier, the Merkle tree construction, the pre-commitment logic, or signing-key handling — can invalidate the trust property the project exists to provide. We take this seriously.

## Scope

### In scope

- **Verifier false accepts** — a tampered `.jes` that `jesses verify` classifies as valid
- **Verifier false rejects** — a genuine `.jes` that `jesses verify` classifies as invalid
- **Merkle tree construction bugs** — any deviation from RFC 6962 byte-exact behavior
- **Canonical serialization bugs** — any non-determinism in event or predicate serialization
- **Pre-commitment bypass** — any way to produce a valid `.jes` without a Rekor inclusion proof predating the first event
- **Key handling bugs** — key material leakage, signature forgery, weak randomness
- **Replay or split-view attacks** on the transparency log integration
- **Policy-parser bugs** — any scope rule that matches differently from the documented semantics

### Out of scope (v0.1)

- **Local privilege escalation on the submitter's own machine** — the v0.1 threat model assumes the submitter's machine is their own; hardware attestation against a modified binary is a v0.3 deliverable (TEE)
- **Attacks requiring physical access** to the signing device
- **Attacks on upstream transparency log operators** (Rekor, OpenTimestamps servers) — we inherit their trust assumptions
- **Attacks on upstream blockchains** (Bitcoin consensus) — same inheritance
- **Supply chain attacks on Go toolchain itself** — addressed by Go's own ecosystem

## How to report

v0.1 is pre-launch. Until the project has a public presence and a dedicated disclosure inbox, please:

1. Do **not** file public issues for security bugs
2. Do **not** post working proof-of-concepts on social media
3. Open a private GitHub Security Advisory on this repository once it is published, or contact the maintainer listed in the launch README

## Response expectations

- Initial acknowledgment: within 72 hours of report
- Triage decision: within 7 days
- Fix or mitigation plan: within 30 days for High/Critical
- Public disclosure: coordinated, typically 90 days from initial report, negotiable based on severity and fix availability

## Bounty

**There is no `jesses` bug bounty at v0.1.**

We believe the primitive must earn trust before it can responsibly accept the obligation of running a bounty program against itself. A premature bounty would create the wrong incentives — paying reporters before the project has the engineering capacity to fix findings within its own timeline. We would rather be honest about this than advertise a bounty we cannot sustain.

Researchers who find and responsibly disclose issues will be credited in the release notes and the `SECURITY.md` history once the project is public.

## For curious readers

If you are reading this looking for a clever way to forge a `.jes`, start with [`THREAT_MODEL.md`](./THREAT_MODEL.md). The seven attacks listed there are the ones we have already considered. If you find an 8th — one we have not listed and cannot defend against — that is exactly the kind of finding we are built to hear.
