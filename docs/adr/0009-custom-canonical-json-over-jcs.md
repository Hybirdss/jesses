---
status: accepted
date: 2026-04-17
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0009 — Strict subset of Go `encoding/json` as canonical form (instead of RFC 8785 JCS)

## Context and problem statement

`jesses` hashes every audit event into a Merkle leaf, and hashes the decoded DSSE payload into the envelope subject. Both operations are bit-exact: one byte of drift in the serializer silently rehashes every leaf in every existing `.jes`, and every verifier out there starts returning FAIL on files that were valid yesterday. The serializer is therefore load-bearing, not an implementation detail.

Two canonicalization contracts are available in 2026:

1. **RFC 8785 JSON Canonicalization Scheme (JCS)** — an Internet Standard. Sorts object keys lexicographically (Unicode code point), normalizes numbers through ECMAScript `Number.prototype.toString`, and leaves `<`, `>`, `&` raw. A growing list of attestation formats (W3C VC Data Integrity, some cosign deployments) specify JCS.

2. **Go `encoding/json` default output** — the stdlib's HTML-safe mode. Escapes `<`, `>`, `&` as `\u003c`, `\u003e`, `\u0026`; escapes U+2028 and U+2029 to `\u2028` / `\u2029`; emits struct fields in declaration order; emits map keys in byte-order (not code-point, though identical for ASCII).

v0.1 was built in Go and uses `encoding/json` by default. An early internal draft considered migrating to JCS before publishing `spec/canonical.md`. We did not.

This ADR records why.

## Decision drivers

- **v0.1 freezes the envelope format.** A `.jes` produced by any version-0.1 implementation must verify forever. The serializer is inside the Merkle leaf hash, so "frozen envelope" implies "frozen canonical form."
- **Cross-language verifiers must produce byte-identical output.** We ship `verifier-js/canonical.mjs` alongside the Go reference; a third-language implementation (Python, Rust) must pass the same conformance vectors. The spec that governs them must be writable without reference to a specific runtime.
- **The spec must be implementable without reading Go source.** `spec/canonical.md` is the source of truth; the Go code is one implementation of it.
- **Zero custom codec.** Maintaining a bespoke canonicalizer is a standing attack surface (floating-point edge cases, Unicode normalization bugs, number-encoding drift). We prefer to inherit a battle-tested codec and document its behavior.
- **JCS divergence cost is quantifiable and small.** `<`, `>`, `&`, U+2028, U+2029 appear in audit inputs only when an attacker or a weird tool output includes them. They encode identically as JSON characters; only the byte form differs.
- **Forward compatibility path exists.** A future predicate URI (`https://jesses.dev/v0.2/action-envelope`) can specify JCS bytes without invalidating any v0.1 `.jes`.

## Considered options

- **Option A — Go `encoding/json` default, documented as the canonical form.** Ship the spec as a byte-level description of what Go already emits. Conformance = match Go.
- **Option B — RFC 8785 JCS, custom Go encoder.** Replace Go's HTML-safe escaping and declaration-order struct output with JCS's code-point sort and raw `<>&`. Maintain our own canonicalizer in `internal/canonical`.
- **Option C — JCS via a wrapper library (e.g., `github.com/gowebpki/jcs`).** Delegate canonicalization to an external Go library that implements JCS.
- **Option D — Custom canonicalization (neither JCS nor Go default).** Design a format with properties we want (e.g., Merkle-friendly length prefixes, stable hex for bytes).

## Decision outcome

**Chosen: Option A — Go `encoding/json` default output, specified byte-level in `spec/canonical.md`.**

The spec is a **strict subset** of what `encoding/json` produces: struct fields emit in declaration order, maps sort by byte-order on keys, strings escape the five short forms plus control chars plus `<`, `>`, `&`, U+2028, U+2029. Numbers go through Go's `encoding/json` number encoding (integers as decimal, floats with Go's shortest round-trip). The `spec/canonical.md` text is readable without Go knowledge and is the ground truth; `internal/canonical/canonical.go` is the reference implementation of that spec.

We accept the divergence from JCS and document it explicitly. A verifier written against JCS that receives a v0.1 `.jes` will not match bytes. It will parse as JSON fine; the Merkle leaf bytes just differ, and the resulting root does not match. That is a correct failure of a non-conformant verifier, not a correctness bug in jesses.

### Positive consequences

- **No custom codec to maintain.** `encoding/json` is tested by the entire Go ecosystem. Every Go version upgrade passes a deterministic conformance vector before we tag a new jesses release; the vector commits us to specific bytes, not "whatever Go does next."
- **Second-implementation cost is bounded.** `verifier-js/canonical.mjs` is 70 lines. The JS implementation passes every v0.1 vector. A Python implementation would be similar.
- **Existing `.jes` files stay verifiable forever** — the format was produced by the default encoder, so any implementation matching the published spec will accept them.
- **The v0.2 path stays open.** Migrating to JCS (if the ecosystem converges) is a new predicate URI with a separate canonical spec. Existing v0.1 files remain valid under v0.1; new files can use v0.2.

### Negative consequences

- **Divergent from the emerging JCS ecosystem.** Tooling written against JCS (some cosign configurations, W3C VC profiles) does not consume v0.1 `.jes` bytes directly; it must be pointed at jesses's canonical spec, or it must re-canonicalize after parsing.
- **`<`, `>`, `&` encoding is surprising.** A reviewer unfamiliar with Go's HTML-safe default sees `\u003c` where JCS would have `<` and may file a false bug. Mitigation: `spec/canonical.md` §2.1 calls this out explicitly with the table showing why each escape exists.
- **Declaration-order struct fields are not a JSON standard.** They rely on the spec fixing the order in prose (`seq, ts, tool, ...`). An implementation that re-orders fields alphabetically will produce different bytes. Mitigation: a conformance vector in `spec/test-vectors/v0.1/` exercises the exact ordering.

## Pros and cons of the options

### Option A — Go `encoding/json` default

- Good — zero custom code; inherits Go's test surface.
- Good — the spec is descriptive of an existing encoder, not normative of a new one; easier to review for correctness.
- Good — byte-exact reproducibility across Go versions (verified per-release).
- Bad — diverges from JCS; external JCS-based tooling needs an adapter.
- Bad — HTML escapes are unfamiliar to readers expecting `<`/`>`/`&` raw.

### Option B — JCS with a hand-written encoder

- Good — aligns with emerging standard; easier to explain to a JCS-familiar reviewer.
- Bad — a custom encoder we have to maintain forever; every Unicode / number edge case is our bug.
- Bad — switching from Go's default to JCS mid-draft would have invalidated every `.jes` produced during development; v0.1 timeline does not absorb a silent rehash.
- Bad — migrating back to JCS later from a custom encoder is no easier than migrating from Go's default — the break is the format change, not the encoder shape.

### Option C — JCS via a wrapper library

- Good — less code than Option B; inherits library's test surface.
- Neutral — adds a dependency we must track for security advisories.
- Bad — library's output is not what jesses emitted during development; switching requires a forced break equal to Option B.
- Bad — the library becomes the spec; a v0.2 migration depends on the library's stability rather than on our own conformance vectors.

### Option D — Custom canonicalization (length prefixes, hex bytes, Merkle-friendly shape)

- Good — could in principle be faster to verify (no JSON parse needed).
- Bad — breaks compatibility with every JSON tool; loses "human-inspectable `.jes`" — a major v0.1 value prop.
- Bad — yet another canonical form in a world that already has too many.
- Bad — cannot be embedded inside DSSE payloads without custom wrappers, breaking ITE-6 compliance (ADR 0002).

## Validation

- `internal/canonical/conformance_test.go` exercises every construct in `spec/canonical.md` against a pinned byte-level expected output. A drift in Go's `encoding/json` between Go versions would fail this test before a jesses release tagged against that Go version ships.
- `spec/test-vectors/v0.1/` includes three golden sessions (happy-path, policy-breach, tampered-log). The Merkle root in each vector was computed from the event leaves canonicalized by `internal/canonical/canonical.go`. `verifier-js/canonical.mjs` must reproduce these bytes exactly.
- A hypothetical third-language verifier (Python / Rust) is conformant iff it passes the same vectors. No Go-source reading required.
- `spec/canonical.md` is reviewed whenever `internal/canonical/canonical.go` changes. A PR that touches one without touching the other is blocked in code review.

## Links

- `SPEC.md` §4 (predicate schema references `spec/canonical.md` for the leaf hash)
- `spec/canonical.md` §2.1 (string escaping table; explicit JCS-divergence note)
- ADR 0003 (RFC 6962 Merkle — parallel "match the stdlib exactly" philosophy)
- [RFC 8785 — JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785)
- [Go `encoding/json` `SetEscapeHTML` reference](https://pkg.go.dev/encoding/json#Encoder.SetEscapeHTML)
