# Changelog

All notable changes to `jesses` are recorded here. This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

## [Unreleased]

### Added

- **Day 0 scaffold** — v0.1 architecture from in-house dream-team synthesis integrating Filippo Valsorda (language + ecosystem), Ben Laurie (transparency + pre-commitment), and Vitalik Buterin (on-chain minimization) voices
- `README.md` — hero doc with locked decisions summary
- `ARCHITECTURE.md` — module layout, import rules, 7 invariants, 5-day build order
- `THREAT_MODEL.md` — submitter-as-adversary premise, 7-attack matrix, defense mapping, v0.1 adversarial-economics defense, v0.3 TEE roadmap
- `SPEC.md` — v0.1 standard: predicate type URI, in-toto ITE-6 envelope, canonical event schema, 6 verify gates, test vector index
- `LICENSE` — MIT
- `.gitignore` — Go standard + jesses runtime files
- `Taskfile.yml` — cross-platform task runner with placeholder tasks
- `go.mod` — module `github.com/Hybirdss/jesses`, Go 1.22
- `SECURITY.md` — disclosure policy
- Module tree: `cmd/`, `internal/`, `pkg/`, `spec/`, `examples/`, `testdata/`, `.github/`, `tools/` (35 directories, 22 `.gitkeep` placeholders)

### Locked decisions
- Language: Go (not Python, not Rust) — single static binary, no `pip install`
- Format: in-toto ITE-6 envelope + new predicate type `https://jesses.dev/v0.1/action-envelope`
- Log structure: RFC 6962 Merkle tree (byte-exact with Certificate Transparency)
- Anchors: OpenTimestamps (Bitcoin) + Rekor (Sigstore). No other blockchain.
- Pre-commitment: session-start SCT analog, MANDATORY
- Key: software ed25519 (v0.1); TPM/TEE deferred to v0.3
- Adoption lever: HackerOne as platform enforcer
