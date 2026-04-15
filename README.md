# jesses

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

`jesses` is committed to being a **primitive**, not a product. This commitment is pre-launch and irrevocable:

- The primitive (hook, attestation format, verifier, spec) will never be monetized. MIT forever.
- The format, the verifier semantics, and the test vectors are owned by a neutral foundation — the **jesses Foundation** — to be established before v1.0. No single maintainer or company can steer the standard unilaterally.
- Enterprise services _on top of_ the primitive (hosted verification, compliance dashboards, managed transparency logs) may be monetized by any party. The primitive itself is not.
- The maintainer will decline any acquisition or re-license offer that would change this stance.

This commitment exists because the dominant failure mode for a new primitive is the owner deciding to monetize it later, then losing community trust when the reference hub stops being neutral. `jesses` will not be that primitive.

See [`ROADMAP.md`](./ROADMAP.md) for the full 90-day plan and governance timeline.

## License

MIT. See [`LICENSE`](./LICENSE).
