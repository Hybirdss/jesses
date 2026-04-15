---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: [Sigstore-community guidance, SLSA reference implementations]
informed: []
supersedes: []
superseded_by: []
---

# 0002 — in-toto ITE-6 envelope with new predicate URI

## Context and problem statement

A `.jes` file must be verifiable by third parties (regulators, triage teams, client security officers) who have no prior relationship to the producing agent. The file must be self-contained enough that the verifier can reason about authenticity, integrity, and time-bound ordering using only well-known cryptographic primitives, and ideally inside an existing transparency-log and signature-verification ecosystem.

We can define a bespoke attestation format and write a standalone verifier and transparency-log client, or we can embed the project-specific payload inside an already-standardized envelope whose outer signature and log semantics are widely implemented.

## Decision drivers

- The verifier must compose with `cosign verify-blob`, `rekor-cli`, and `slsa-verifier` out of the box.
- The envelope must allow a predicate URI we can version independently, so that v0.1, v0.2, and v0.5 predicates live alongside one another.
- We should not reinvent the outer signature semantics, the DSSE payload type handling, or the transparency-log inclusion proof format.
- The envelope must tolerate future predicate structure changes without breaking existing verifiers.

## Considered options

- in-toto ITE-6 envelope with predicate type `https://jesses.dev/v0.1/action-envelope`
- Standalone JOSE (JWS) envelope with a custom `typ` header
- Standalone `.jes` binary format with an internal signature block
- SLSA Provenance predicate directly (no new predicate type)

## Decision outcome

**Chosen: in-toto ITE-6 envelope with new predicate URI `https://jesses.dev/v0.1/action-envelope`.** This reuses the Sigstore DSSE-based outer layer (cosign, Rekor, Fulcio identities) and inherits all their verifier tooling for free. The new predicate type declares that the inner payload is specifically an action-envelope — distinct from SLSA provenance and other attestation kinds — so verifiers can route correctly.

### Positive consequences

- `cosign verify-blob --bundle ... --certificate-identity-regexp ...` works on `.jes` files without modification.
- `rekor-cli search --artifact .jes` and inclusion-proof verification are native.
- A future `v0.2/action-envelope` predicate can ship alongside v0.1 because the envelope carries the URI.
- SLSA and in-toto tooling contributors can review the format as "predicate-type variant", not a brand-new format.

### Negative consequences

- DSSE adds a small overhead to the `.jes` file versus a tighter binary format.
- The `jesses.dev` domain hosting the predicate URI is now a stability dependency; documentation and schema served under that path must remain reachable forever. Mitigation: at foundation transition (ADR 0010), domain ownership moves to Commonhaus.
- Verifier implementations must understand DSSE in addition to the jesses-specific predicate. In practice this is a library dependency, not a hand-rolled parser.

## Pros and cons of the options

### in-toto ITE-6 envelope with new predicate URI

- Good: composes with the entire Sigstore / cosign / Rekor / SLSA verifier ecosystem
- Good: predicate URI is the natural versioning knob; predicates can evolve independently of the outer envelope
- Good: widely reviewed outer format; no novel crypto
- Bad: slightly larger file size; introduces domain stability as a dependency

### Standalone JOSE (JWS) envelope with a custom `typ`

- Good: smaller than DSSE; widely implemented in JS/TS
- Bad: loses native Rekor integration (Rekor indexes DSSE and intoto, not arbitrary JWS)
- Bad: loses cosign compatibility; verifier is standalone

### Standalone `.jes` binary format

- Good: smallest file size; maximal control
- Bad: requires writing and maintaining a transparency-log client from scratch (~6 months of negative-differentiation work)
- Bad: no independent review of format; easy to design in a subtle break

### SLSA Provenance predicate directly

- Good: predicate type already standardized; massive verifier coverage
- Bad: SLSA Provenance describes "how an artifact was built", not "what an agent did during a session"; the semantic fit is wrong
- Bad: using the URI for an unintended purpose misleads downstream consumers

## Validation

- Every test vector in `spec/v0.1/test-vectors/` is an in-toto ITE-6 envelope; `cosign verify-blob` accepts the signed vectors.
- CI job verifies that `rekor-cli` can locate a signed vector by its SHA-256 once published (see `spec/v0.1/test-vectors/README.md`).
- The v0.1 TypeScript verifier (commissioned) must accept the same envelopes — a cross-implementation conformance check.

## Links

- [in-toto attestation spec](https://in-toto.io/Attestation/)
- [DSSE](https://github.com/secure-systems-lab/dsse)
- [Sigstore cosign](https://docs.sigstore.dev/cosign/)
- `SPEC.md` §Predicate structure
- ADR 0003 (Merkle tree) — predicate carries the tree root
- ADR 0005 (pre-commitment) — predicate references the session-start Rekor entry
