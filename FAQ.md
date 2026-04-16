# FAQ

The adversarial questions. If you've read [`README.md`](./README.md), [`WHY.md`](./WHY.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), and [`SPEC.md`](./SPEC.md) and still have objections, they're probably below. If they're not, open a GitHub issue and they will be.

---

### Why not just use in-toto / Sigstore / cosign as-is?

`jesses` **does** use them. The outer envelope is a DSSE-wrapped in-toto v1 Statement; Rekor is the transparency log for the session-start pre-commitment; cosign will verify the envelope signature without any jesses-specific code.

What's new is the `predicate`. in-toto predicates today describe build artifacts (SLSA Provenance, SPDX, VEX, CycloneDX). None of them describe **what an LLM agent did during a session**. `https://jesses.dev/v0.1/action-envelope` is the new predicate type: it records the session start/end timestamps, the policy hash the session ran under, the RFC 6962 Merkle root over the audit log, the Rekor pre-commit index, and the OpenTimestamps anchor.

If you're in the Sigstore/in-toto ecosystem, `jesses` looks like "one more predicate." If you're a triager or an auditor, it looks like "the file I verify." Both framings are correct. See [`docs/adr/`](./docs/adr/) for the decision records.

---

### How is this different from Aegis (arxiv:2603.16938)?

Aegis is the closest academic neighbor. It defines an Immutable Logging Kernel (ILK), a policy-bound Ethics Verification Agent, and a runtime Enforcement Kernel Module. It's a serious piece of work.

Two differences matter:

1. **Threat model.** The Aegis paper's §5 explicitly states: *"does not defend against attacks that bypass the SDK entirely"* and *"direct database manipulation by root-privileged adversary is outside the current threat model."* `jesses` makes the opposite assumption — the submitter is root, has the source, and wants to forge. Every defense is evaluated against that single adversary. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) §0.
2. **Deployment shape.** Aegis is a runtime kernel that must be installed. `jesses` is a file format + CLI that a researcher attaches unilaterally to a submission. The researcher needs no platform agreement; the triager needs no account anywhere; the verification is offline.

In regulated deployments where the operator, the policy author, and the SDK vendor all trust each other, Aegis fits. In bounty, pentest, and third-party-audit settings where the deliverable crosses an adversarial trust boundary, `jesses` fits.

---

### Can't the submitter replace the jesses binary with a modified version that writes fake entries?

Yes, on a machine they control. That's why the pre-commit and the anchors exist.

- A modified binary can invent audit entries, but it cannot retroactively produce a Rekor inclusion proof that predates the first entry's timestamp (A3 attack; Rekor is a public log and the attacker does not control it).
- A modified binary can ship a fake Merkle tree, but the RFC 6962 root hash is included in the DSSE-signed predicate, and re-computing the tree from the included leaves is trivial (A1, A6).
- A modified binary can back-date the session's end time, but not past the OpenTimestamps Bitcoin anchor (A2, A5).

The one attack class that v0.1 does **not** close mathematically is A7 (interleave real + fabricated entries in real time during the session). v0.1 defends via adversarial economics; v0.3 closes it via TEE attestation. This is stated in [`THREAT_MODEL.md`](./THREAT_MODEL.md) §4 and [`ROADMAP.md`](./ROADMAP.md) v0.3.

---

### What prevents the submitter from running an honest session with fake intent — real merkle tree, real timestamps, fake purpose?

Nothing, at the jesses layer. jesses attests to **what the agent did**, not to **what the agent believed or intended**. If the submitter prompts the agent to do real work and then writes a misleading narrative in the deliverable, gates 1–6 still pass.

Gate 7 (deliverable provenance binding) is where narrative meets evidence. Every footnote `[^ev:N]` in the bound report must reference a real audit-log event; the verifier recomputes the report SHA-256 into the predicate and validates each citation. Under `bare-policy=strict`, uncited factual lines fail verification. This doesn't prevent lying — it forces every lie to have a specific event receipt backing it, which is an enormously harder forgery problem.

The long answer is in [`THREAT_MODEL.md`](./THREAT_MODEL.md) §2 under A8 (theater mode).

---

### Why not just use TEE attestation from day one?

Three reasons:

1. **TEE is the v0.3 answer**, not a v0.1 blocker. Shipping v0.1 without TEE means 95% of the threat model is mathematically closed today. Waiting for TEE means shipping zero percent for another year.
2. **TEE trust-roots belong to manufacturers.** AWS Nitro's attestation roots in AWS, Intel TDX in Intel, Apple Secure Enclave in Apple. Each choice is a governance decision, not just a technical one. Deferring the choice to when there's actual paying customer signal is correct discipline.
3. **TEE tooling ergonomics are still rough.** A CLI that exits in 3 μs per hook call is usable anywhere; a Nitro Enclave harness is not. v0.1 ergonomics are what get `.jes` in front of the first 100 users.

---

### Why a new spec instead of extending SLSA?

SLSA describes how an artifact was built. `jesses` describes how an agent **acted during a session that produced an artifact**. The two are compositional, not competitive:

- A SLSA Provenance attestation can describe the builder (GitHub Actions runner) that invoked a jesses-wrapped agent.
- A jesses action-envelope can sit inside the same repository as SLSA provenance for the same release.
- SLSA's verifier (slsa-verifier, cosign) will verify jesses envelopes structurally; the jesses-specific six-gate logic is layered above.

Extending SLSA Provenance to cover agent sessions was considered and rejected. The two shapes are sufficiently different (tool-event streams vs. build steps; session boundaries vs. build boundaries; privacy modes vs. build metadata) that forcing them into one schema would make both worse. See [`docs/adr/`](./docs/adr/) for the ADR.

---

### Does this actually work offline?

Yes. `jesses verify --offline session.jes` performs zero network calls. The Rekor inclusion proof and the OpenTimestamps Bitcoin proof are embedded in the envelope at session-end, not looked up at verification time. The only input the verifier needs is:

1. The `.jes` file.
2. The policy file whose SHA-256 matches the one recorded in the pre-commit.

That's the full attack surface. An air-gapped auditor running on a laptop with no internet can produce a verdict identical to one produced on a cloud verifier.

---

### Why RFC 6962 Merkle specifically, and not a hash chain or Tamper-Evident Log?

RFC 6962 gives **O(log n) inclusion and consistency proofs**. A hash chain is O(n). Consistency proofs matter for multi-checkpoint scenarios: a monitor that checkpointed the session's tree state at minute 30 can verify that the final tree is an append-only extension of that checkpoint, without re-reading the whole log. A hash chain cannot do this without replaying from genesis.

The byte-exact match with Certificate Transparency is also deliberate: existing CT verifier code in any language can be adapted to verify `.jes` Merkle proofs with minimal modification. `internal/merkle/rfc6962_test.go` runs against the official CT reference test vectors; that's commit [74acd6b](https://github.com/Hybirdss/jesses/commit/74acd6b).

---

### Why Go, and will you add a Python / Rust / TypeScript verifier?

Go for the reference implementation because:
- `pip install` is itself an adversarial attack surface; `jesses` ships as a static binary.
- The Sigstore ecosystem is Go-native. Reusing `sigstore/rekor/pkg/client` and related libraries is cheap in Go and expensive everywhere else.
- Dependency discipline is easier to enforce (compiler-level internal-package boundaries, no transitive-deps-from-hell).

A JavaScript second implementation already exists in [`verifier-js/`](./verifier-js/) — zero external dependencies, Node 20+ built-ins only, runs the full conformance corpus. A Rust third implementation is planned for v0.2. TypeScript-proper port of the JS verifier is planned for v0.1.1. Python is not planned; use the WASM build (v0.2) or shell out to the Go binary.

---

### Do I need a Rekor / Sigstore account?

No. Rekor is a public append-only log. Anyone can submit entries; nothing is rate-limited in a way that matters for individual submissions. The session-start pre-commitment is submitted to the public Rekor instance (`rekor.sigstore.dev`) by default. Self-hosted Rekor is also supported.

OpenTimestamps is the same: a free, public Bitcoin-anchored timestamp service. No account.

---

### What about privacy? Do my tool commands leak?

Two privacy modes, declared at session start and immutable for the session:

- **`privacy=off`** (default, for bug-bounty submissions) — full tool inputs are stored in the audit log. Triagers can see exact commands to reproduce findings.
- **`privacy=on`** (enterprise compliance) — only SHA-256 of canonical tool input is stored. The Merkle tree structure is identical; only the leaf canonical form changes. Verifiable but opaque.

In both modes, the envelope publicly records which mode was used, so a consumer cannot be deceived about what they're looking at.

The Rekor pre-commit contains only `{session_id, timestamp, policy_hash, pubkey}` — no tool data. The OTS anchor is of the Merkle root, which in `privacy=on` mode reveals nothing about specific commands.

---

### What's the relationship to OpenSSF / Sigstore TSC / Linux Foundation?

Presently: none, formally. The repo is MIT-licensed and Sigstore-compatible by construction. v1.0 roadmap includes an IETF internet-draft for the predicate type and canonical encoding, and an application to register the predicate type with Sigstore TSC as a standard type. Foundation-level governance (Linux Foundation / OpenSSF) is a v1.0+ conversation; v0.1 is a single-maintainer project and says so in `GOVERNANCE.md`.

---

### Can I use this without Claude Code?

Yes. The stdin event shape is documented in [`SPEC.md`](./SPEC.md) §5. Any agent harness that can emit line-delimited JSON events with a `tool` + `input` shape can pipe to `jesses hook`. Cursor's and Cline's agent event formats map directly; a custom Go harness can embed [`pkg/jesses`](./pkg/jesses) for tighter integration.

`jesses run -- <cmd>` additionally wraps an arbitrary child process and attestates the process-bound time interval, for harnesses that don't have a hook mechanism at all.

---

### What's the minimum viable demo?

```
git clone https://github.com/Hybirdss/jesses && cd jesses
go build -o jesses ./cmd/jesses/
./examples/demo-bounty/reproduce.sh
```

That runs a seven-event session end-to-end, produces a `.jes`, verifies it with the Go reference verifier, binds a report, re-verifies with G7 enforced, and cross-verifies with the JavaScript implementation to show byte-identical `Report` JSON. Total time: under 30 seconds once Go is installed.

---

### What breaks first if this scales?

Honestly? The `privacy=off` mode leaks proprietary commands to triagers, which is a **social** problem, not a cryptographic one. A researcher who copy-pastes the commands can re-run them verbatim; that's fine for curl but awkward for a SaaS customer's production environment. `privacy=on` addresses this, but the tradeoff (opaque audit) makes triage harder.

v0.2+ ZK compliance proofs and v0.3 TEE attestation together let us have both — a verifiable opaque log — but those are 6+ months of work each. If you're hitting this limit and want to be a design partner, that's the conversation to have.

---

### Who are you?

Solo maintainer, Korea-based, security + autonomous agent background. Building this alongside bounty work, not from a whiteboard. The commit history is the resume. If you want a call: open a GitHub issue with "demo call?" in the title and a proposed time slot, or reach through the address in `SECURITY.md`.
