---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: [Sigstore-community guidance]
informed: []
supersedes: []
superseded_by: []
---

# 0001 — Go as reference implementation language

## Context and problem statement

`jesses` installs on a security researcher's own machine and emits attestations the researcher cannot repudiate. The threat model (`THREAT_MODEL.md` §2) treats the submitter as the primary adversary: anyone running the tool has an incentive to tamper with its runtime to produce a favorable `.jes`. The language and runtime choice therefore determines the attack surface an adversarial user starts with.

The choice also determines adoption-adjacent properties: which ecosystem (Sigstore, cosign, SLSA) the verifier fits into natively; how easy it is for a bounty hunter to run the binary in under 10 seconds of install time; whether transitive dependencies can be poisoned across `pip install` / `npm install` / `go install` surfaces.

Which language should the reference implementation target?

## Decision drivers

- Binary distribution without a mandatory runtime install. Hunter install must be `curl | sh` level.
- Minimal transitive dependency surface. A supply-chain attack on a stdlib package is the same class of threat as a sandbox escape.
- First-class position in the Sigstore / SLSA ecosystem so that verifier composition is natural rather than hostile.
- Mature cryptographic standard library with long-term maintenance from the language's core team.
- Cross-platform single-binary produceability (Linux, macOS, Windows) from one build host.

## Considered options

- Go — static binary, stdlib-only crypto, native to Sigstore ecosystem
- Rust — static binary, strong type safety, less mature cosign/SLSA tooling surface
- Python — widest contributor pool, but `pip install` is the adversarial install surface we explicitly oppose
- C — smallest runtime, but modern cryptographic assurance requires a third-party library (OpenSSL, libsodium) which defeats the stdlib-only goal

## Decision outcome

**Chosen: Go.** It is the only option that delivers a single static binary, has its cryptographic primitives in the standard library maintained by the language's core team, and lives inside the Sigstore ecosystem where cosign, sigstore-go, in-toto, and SLSA tooling are all written in Go natively.

### Positive consequences

- Distribution is a single file. `curl -L ... | sudo tee /usr/local/bin/jesses` is a supported install path.
- `internal/` packages can hold to a zero-external-dependency rule and still implement every primitive the project needs (RFC 6962 Merkle tree, canonical JSON, ed25519, file locking).
- The verifier can import `github.com/sigstore/cosign`, `github.com/sigstore/sigstore-go`, and `github.com/in-toto/in-toto-golang` without language-ecosystem mismatch.
- GoReleaser, slsa-github-generator-go, and gitsign are Go-native, simplifying the release pipeline (ADR 0002).

### Negative consequences

- Go's type system is less expressive than Rust's; invariants (e.g. the frozen `Event` struct field order) are enforced by tests and review rather than by the compiler.
- Contributors who know only Python or TypeScript cannot immediately contribute to the reference implementation. Mitigation: the TypeScript verifier (commissioned by Day 42) is the second-language onramp.
- Some researchers run Go binaries through tools (race detector, sanitizers) whose output is more verbose than equivalent tools in other ecosystems.

## Pros and cons of the options

### Go

- Good: static binary, stdlib crypto, native to Sigstore tooling, mature cross-compilation
- Good: `go test -race` and `govulncheck` give a strong default CI surface
- Bad: no compile-time enforcement of bit-exact invariants (must be tested)

### Rust

- Good: strongest compile-time invariants of any mainstream language
- Good: static binary, no runtime needed
- Bad: cosign / SLSA / in-toto tooling is Go-first; Rust bindings are less mature
- Bad: slower iteration during v0.1 build phase when the design is still tightening

### Python

- Good: largest contributor base among security-adjacent developers
- Bad: `pip install` is an adversarial install surface (see THREAT_MODEL.md supply-chain section); incompatible with the submitter-as-adversary model
- Bad: single-binary packaging (pyinstaller, shiv) introduces a full dependency tree back into the artifact

### C

- Good: smallest runtime footprint
- Bad: mature crypto requires OpenSSL/libsodium (breaks stdlib-only), undefined-behavior risk in canonical serialization, no memory safety for a security-critical tool

## Validation

- Every v0.1 tagged release produces a Linux/macOS/Windows × amd64/arm64 matrix of single binaries, reproducibly (see ADR 0002 and `.goreleaser.yaml`).
- `go mod graph` at tag time lists only modules inside `github.com/Hybirdss/jesses/...` or the Go standard library for any `internal/` package; this is enforced by `.golangci.yml` `depguard` rules.
- The second-language verifier (TypeScript) passing the same test vectors is the cross-check that no Go-specific detail has leaked into the spec.

## Links

- `THREAT_MODEL.md` §2 (submitter-as-adversary)
- `ROADMAP.md` §Strategic bet
- ADR 0002 (in-toto ITE-6 envelope) — the chosen format is Go-native in Sigstore
