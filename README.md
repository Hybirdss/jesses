# jesses

[![CI](https://github.com/Hybirdss/jesses/actions/workflows/ci.yml/badge.svg)](https://github.com/Hybirdss/jesses/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Hybirdss/jesses/actions/workflows/codeql.yml/badge.svg)](https://github.com/Hybirdss/jesses/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Hybirdss/jesses/badge)](https://scorecard.dev/viewer/?uri=github.com/Hybirdss/jesses)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/Hybirdss/jesses.svg)](https://pkg.go.dev/github.com/Hybirdss/jesses)

> _"In 13th-century English common law, a hawk without jesses was legally vermin — no proof of training meant no proof of responsible ownership. In 2026, an LLM agent without jesses is the same under EU AI Act Article 12."_

Cryptographic attestation standard for security deliverables produced by autonomous LLM agents.

When an AI agent produces a bug bounty report, a pentest finding, or a B2B security audit, `jesses` emits a tamper-evident `.jes` file alongside the deliverable. The file proves — to a regulator, a bounty triage team, or a client security officer — that the agent stayed inside an authorized action envelope during the session. Third parties verify the proof mathematically, without needing access to the underlying audit log.

---

## Status

**v0.1 scaffold.** No executable code yet. Architecture and specification locked.

v0.1 ship target: a Go binary that installs a PreToolUse hook into Claude Code, records every tool invocation under a policy, emits a signed in-toto ITE-6 attestation at session end, and ships a reference verifier that is bit-exact reproducible across machines.

---

## Where to look

| file | what it is |
|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | module layout, import rules, 7 invariants, build order |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | submitter-as-adversary premise, 7 attacks, defense matrix |
| [`SPEC.md`](./SPEC.md) | v0.1 standard — predicate URI, envelope, event schema, 6 verify gates |
| [`spec/v0.1/`](./spec/v0.1/) | language-independent JSON schema + test vectors (other-language verifiers must pass these) |
| [`SECURITY.md`](./SECURITY.md) | disclosure policy |
| [`GOVERNANCE.md`](./GOVERNANCE.md) | decision authority, Commonhaus transition plan, sustainability |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | DCO, bit-exact invariants, PR workflow |
| [`TRADEMARK.md`](./TRADEMARK.md) | word-mark policy and permitted uses |
| [`docs/adr/`](./docs/adr/) | Architecture Decision Records (MADR 3.0) — 10 foundational decisions |

---

## Design decisions (locked)

- **Language**: Go. Single static binary. No `pip install` for an adversary-resistant tool.
- **Format**: in-toto ITE-6 envelope + new predicate type `https://jesses.dev/v0.1/action-envelope`. Reuses Sigstore / cosign / Rekor for free.
- **Log structure**: RFC 6962 Merkle tree (byte-exact with Certificate Transparency). O(log n) inclusion and consistency proofs.
- **Anchors**: OpenTimestamps (Bitcoin) + Rekor (Sigstore transparency log). No other blockchain.
- **Pre-commitment**: session-start SCT analog, published before any tool event. Without this, the "fabricate entire session" attack is undetectable.
- **Signing key (v0.1)**: software ed25519 at `~/.jesses/key`. TPM / Secure Enclave / TEE attestation deferred to v0.3 — v0.1 ships an adversarial-economics defense in the interim.
- **Adoption lever**: HackerOne as the "Chrome" — the platform that enforces `.jes` attachment for AI-assisted Critical submissions. Without a platform enforcer, standards die.

---

## The one thing this is not

This is not a compliance SaaS. It is not a scope checker. It is not a dashboard. It is an **attestation primitive** — the unit of trust you attach to a deliverable when the deliverable was produced by an autonomous agent and the reader needs to verify the agent stayed inside authorized bounds.

Everything else (policy libraries, verifiers in other languages, transparency-log operators, HackerOne integration, ZK proofs, agent reputation, EU AI Act mapping) is built on top of this primitive or deferred to a later version.

---

## Governance (pre-commit)

`jesses` is committed to being a **primitive**, not a product. This commitment is pre-launch and operational:

- The primitive (hook, attestation format, verifier, spec) is MIT-licensed in perpetuity. MIT is structurally irrevocable; this statement is a reminder, not a contractual add-on.
- The format, the verifier semantics, and the test vectors will be held by a neutral fiscal and governance sponsor — the [Commonhaus Foundation](https://www.commonhaus.org/) — by v0.2. Commonhaus is a purpose-built home for established open-source projects that need neutral IP and trademark stewardship without Apache-scale process weight or CNCF's multi-organization-maintainer requirements. Pi4J (February 2026), Quarkus, and Micronaut are precedents. See [ADR 0010](./docs/adr/0010-commonhaus-over-self-foundation.md).
- Enterprise services _on top of_ the primitive (hosted verification, compliance dashboards, managed transparency logs) may be monetized by any party. The primitive itself is not.
- The maintainer will decline any acquisition or re-license offer that would change this stance.

This commitment exists because the dominant failure mode for a new primitive is the owner deciding to monetize it later, then losing community trust when the reference hub stops being neutral. `jesses` will not be that primitive.

See [`GOVERNANCE.md`](./GOVERNANCE.md) for decision authority, the Commonhaus transition timeline, and sustainability commitments. See [`ROADMAP.md`](./ROADMAP.md) for the full 90-day plan. See [`TRADEMARK.md`](./TRADEMARK.md) for the word-mark policy that complements the MIT copyright grant.

## Contributing

Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before opening a PR. Every commit must carry `Signed-off-by:` per the [DCO](https://developercertificate.org/); a CLA is not used. The project follows the [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md).

If you are filing a security report, open a private GitHub Security Advisory instead of a public issue — see [`SECURITY.md`](./SECURITY.md).

## License

MIT. See [`LICENSE`](./LICENSE).
