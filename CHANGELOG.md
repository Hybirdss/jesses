# Changelog

All notable changes to `jesses` are recorded here. Format per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `internal/keyring/` — ed25519 key lifecycle extracted from `cmd/jesses/hook.go`. `Signer` interface (v0.3 TEE drop-in), `LoadOrCreate` with atomic tmp+rename write, permission-mode health check (warns on 0644+ key files with a `chmod 600` hint). Zero behavior change at the CLI default path; identity-stable `~/.jesses/key` available via `keyring.DefaultPath()` for callers that want cross-session identity.
- `internal/oplog/` — operational sidecar log for hook-level errors that cannot land in the signed audit log without invalidating the envelope. Append-only JSONL at `session/operational.log` with `{ts, level, phase, seq?, msg}`. Every hook error site (parse, append, close, build, write) writes a structured entry. Privacy-aware by construction: the logger refuses raw input bytes — only sanitized error messages. Explicitly NOT part of the trust envelope; a malicious submitter can delete it and verification still passes (the audit log is the integrity artifact). `Nop` logger drop-in for tests, `Writer` interface prevents `*os.File` leaks.
- `docs/adr/0009-custom-canonical-json-over-jcs.md` — records why v0.1 freezes Go `encoding/json` HTML-safe defaults as the canonical form rather than migrating mid-draft to RFC 8785 JCS. Forward path to JCS kept open via a future v0.2 predicate URI.
- `SECURITY.md` — new "Verifier trust model (Trust on First Use)" section. States plainly what v0.1 does not provide (no signer-identity registry, no key revocation cryptography) and what platforms / enterprise triage / researchers should each do about it. v0.3 TEE and v0.4 EAS are named as the closures.

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

- `internal/merkle` — RFC 6962 byte-exact with Certificate Transparency (leaf prefix `0x00`, node prefix `0x01`). Conformance tests run against official CT reference vectors.
- `internal/canonical` — canonical JSON encoder extracted as its own package with a byte-level spec at `spec/canonical.md`. Strict subset of Go `encoding/json` HTML-safe output; documented divergence from RFC 8785 JCS (see ADR 0009).
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
- `internal/verify` — seven gates (G1 signature, G2 Merkle root, G3 Rekor pre-commit, G4 scope hash, G5 policy compliance, G6 OTS anchor, G7 deliverable provenance). `VerifyError` struct with 21 frozen error codes (`merkle_root_mismatch`, `policy_breach`, `rekor_body_hash_mismatch`, ...) surfaces on every failed mandatory gate. `jesses verify --json` emits the code + typed fields (Expected / Got / LeafIdx / LogOffset / Count / Total / ProofPath) for H1 / Bugcrowd / Immunefi webhook integration. Code vocabulary frozen per major version; consumers pivot on `code`, not on `detail`.
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

#### Build + release hygiene

- `//go:build !production` tag gates the Rekor `FakeClient` and OTS fake so release binaries cannot silently bypass real transparency-log pre-commitment.
- Fuzz coverage on the three externally-reachable parsers: `FuzzJSON_Roundtrip` (canonical encoder), `FuzzRootHash_NoPanic` / `FuzzInclusionProof_RoundTrip` / `FuzzVerifyInclusion_NoPanic` (Merkle prove + verify), `FuzzParseEnvelope` / `FuzzReadEnvelope` (DSSE envelope parser). ~2 M cumulative executions, zero panics. Duplicate-leaf proof-interchangeability edge locked as a regression seed in `internal/merkle/testdata/fuzz/`.
- Three dedicated `errors_test.go` tests catch regressions that golden-vector refresh alone would hide: `PopulatedOnFailure` asserts the G1 code on a broken envelope, `JSONRoundTrip` locks the wire field names, `OmitEmptyZero` ensures zero-valued fields do not leak.

### Numbers

- 218 Go tests + 3 JavaScript conformance vectors + 6 fuzz targets
- Zero external dependencies in every production package
- Hook-path latency: 3 μs simple, 15 μs adversarial, 133 μs for 100-segment pipelines
- `FuzzSplit`: 1.2 M executions at 170 k/s over 10 s, zero panics
- Cumulative fuzz coverage at tag time: ~2 M execs across canonical / merkle / attest, zero panics
