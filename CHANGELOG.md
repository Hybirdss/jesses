# Changelog

All notable changes to `jesses` are recorded here. Format per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — first release

### Added

#### CLI

- `jesses verify <file.jes>` — six/seven-gate verification with `--offline`, `--json`, `--report <md>` flags.
- `jesses view [--follow] [--report <md>] <file.jes>` — local HTTP timeline viewer (60 s TTL, strict CSP). Side-by-side rendering when `--report` is provided: clickable `[^ev:N]` citations scroll the timeline and highlight the target event.
- `jesses run -- <cmd> [args]` — wraps a child process. Emits `jesses.wrap_start` / `jesses.wrap_end` events with `{argv, argv_sha256, cwd, parent_pid, exit_code, signal, duration_ms}`. Child stdout/stderr teed to `session.stdout.log` / `session.stderr.log`. Exit code propagated.
- `jesses hook` — stdin-driven agent-harness protocol: line-delimited JSON tool events, echoes per-event policy decision, finalizes envelope on `{"_action":"close"}`.
- `jesses stats <file.jes>` — one-screen hygiene dashboard (counts, top hosts, decisions). `--json` for machine consumption.
- `jesses cite <seq>` — emits the footnote definition line for one audit-log event.
- `jesses report --bind <md> <file.jes>` — hashes report, validates citations, writes timeline appendix, re-signs envelope with `DeliverableBinding`.
- `jesses init-scope` — writes a scope.txt template covering all five namespaces.

#### Core packages

- `internal/merkle` — RFC 6962 byte-exact with Certificate Transparency (leaf prefix `0x00`, node prefix `0x01`).
- `internal/audit` — append-only canonical log writer with flock + `sync.Mutex` + `O_APPEND` atomicity.
- `internal/policy` — scope.txt parser, 5-namespace matcher (host, path, mcp, contract, repo), exclusion-first evaluation.
- `internal/shellparse` — tokenizer + segment splitter with substitution recursion, wrapper unwrap (13 wrappers), shell re-entry (bash/sh/dash/zsh/ksh `-c` and eval), `/dev/tcp` detection.
- `internal/extractors/{bash, path, web, mcp, dispatch}` — per-tool destination extraction for 20+ tools plus a one-switch dispatch routing table.
- `internal/session` — Open / Append / Close lifecycle with mandatory Rekor pre-commitment at session start.
- `internal/precommit` — SCT-analog receipt with canonical serialization + local verification.
- `internal/rekor` — transparency-log client (`HTTPClient` + `FakeClient`).
- `internal/ots` — OpenTimestamps calendar client.
- `internal/attest` — in-toto ITE-6 envelope with predicate URI `https://jesses.dev/v0.1/action-envelope`, optional `DeliverableBinding` block.
- `internal/provenance` — markdown citation parsing, validation against the audit log, timeline appendix generation.
- `internal/verify` — seven gates (G1 signature, G2 Merkle root, G3 Rekor pre-commit, G4 scope hash, G5 policy compliance, G6 OTS anchor, G7 deliverable provenance).
- `pkg/jesses` — public Go API for external embedders: `Open` / `Process` / `Close` / `Finalize` / `Verify`.

#### Spec + conformance

- `spec/test-vectors/v0.1/` — three canonical vectors (`happy-path`, `policy-breach`, `tampered-log`); the vectors are the spec.
- `spec/freshness-nonce.md` — normative-once-implemented draft of the platform-issued freshness-nonce protocol (v0.1.1).
- `tools/specgen/` — deterministic vector generator (fixed ed25519 seeds, fixed timestamps, FakeClient).
- `verifier-js/` — JavaScript second implementation with zero external dependencies (Node 20+ built-ins only). Produces byte-identical `Report` JSON on every vector.

#### Documentation + examples

- `examples/demo-bounty/reproduce.sh` — one-click end-to-end demo covering seven tool events, verification, stats, report binding, cross-verification.
- `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `MAINTAINERS.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- `docs/adr/0001` through `docs/adr/0008` — architecture decision records for the locked technical choices.

#### CI + release

- `.github/workflows/ci.yml` — matrix `go test -race` across Linux / macOS / Windows × Go 1.22 / 1.23, govulncheck, golangci-lint with `depguard` enforcing zero external deps in `internal/`.
- `.github/workflows/codeql.yml`, `scorecard.yml`, `dco.yml`, `dependabot.yml`.
- `.github/workflows/release.yml` — GoReleaser + cosign keyless (Fulcio + Rekor) + SLSA Build Level 3 provenance + SBOMs (SPDX + CycloneDX via syft).

### Numbers

- 218 Go tests + 3 JavaScript conformance vectors
- Zero external dependencies in every production package
- Hook-path latency: 3 μs simple, 15 μs adversarial, 133 μs for 100-segment pipelines
- `FuzzSplit`: 1.2 M executions at 170 k/s over 10 s, zero panics
