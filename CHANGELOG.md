# Changelog

All notable changes to `jesses` are recorded here. This file follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

For the full narrative build log, see [`docs/BUILD_LOG.md`](./docs/BUILD_LOG.md).

## [Unreleased]

### Added

#### Documentation — build log

- `docs/BUILD_LOG.md` — canonical narrative per-phase record: scope, deliverables, test count, critical invariants, current state, next milestone, decision log, session-resume protocol.

#### Day 2.2a — shell tokenizer

- `internal/shellparse/tokenizer.go` — focused POSIX shell tokenizer. Handles five command separators (`;`, `|`, `||`, `&`, `&&`), newline, three quoting modes (single / double with POSIX escapes / backslash outside quotes with line continuation), adjacent-quoted-run concatenation (the `eval "cur""l evil.com"` pattern), subshell / backtick preservation as literal content.
- `internal/shellparse/tokenizer_test.go` — 29 tests, including five real-world adversarial scenarios (proxy override, wrapper command, env assignment, `bash -c "..."` re-entry payload, `/dev/tcp/host/port` raw TCP redirection).
- `internal/shellparse/doc.go` — package scope and list of deliberately unimplemented bash constructs.
- Zero external dependencies; stdlib only.

#### Day 2.1 — scope.txt parser + five-namespace matcher + exclusion-first precedence

- `internal/policy/parser.go` — line-oriented `scope.txt` parser with shape-based namespace classification (host / path / repo / contract / mcp); `mode:` directive; `in:` / `out:` rule lines; `#` comments (full-line and inline).
- `internal/policy/matcher.go` — five match modes: host exact + anchored wildcard; path glob with `*` / `**` / `?` / character-class support; repo exact; contract case-insensitive; MCP exact-or-prefix-with-colon.
- `internal/policy/precedence.go` — exclusion-first evaluation (every `out:` before any `in:`), first-match-wins within `in:`, mode-dependent unpoliced handling.
- 30 tests, including the critical regression `TestAnchoredSubdomain` (`*.target.com` does NOT match `evil-target.com`).

#### Day 1 — Merkle tree + audit writer

- `internal/merkle/tree.go` — RFC 6962 byte-exact hashing (`HashLeaf`, `HashChildren`, `RootHash`, `RootFromLeafHashes`).
- `internal/merkle/inclusion.go` — `InclusionProof` generation (PATH algorithm) and `VerifyInclusion` (iterative per §2.1.1.2).
- `internal/merkle/consistency.go` — `ConsistencyProof` generation (SUBPROOF algorithm) and `VerifyConsistency` (per §2.1.4.2).
- `internal/merkle/rfc6962_test.go` — 18 tests, including `TestInclusionAllIndices` (exhaustive over 16 tree sizes) and `TestConsistencyAllPairs` (every `(m, n)` pair for `n ≤ 12`).
- `internal/audit/record.go` — canonical `Event` struct with fixed field order.
- `internal/audit/canonical.go` — `CanonicalJSON` deterministic serialization.
- `internal/audit/writer.go` — append-only writer with per-`Append` flock.
- `internal/audit/writer_unix.go` — `syscall.Flock` wrapper, `!windows` build tag.
- `internal/audit/writer_test.go` — 6 tests including concurrent-append (8 workers × 50 events = 400 records, no interleaving, no loss).

#### Day 0 — scaffold

- Repository structure: 35 directories with `.gitkeep` placeholders.
- Core documents: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SPEC.md`, `ROADMAP.md`, `SECURITY.md`, `CHANGELOG.md`.
- Build tooling: `go.mod` (Go 1.22), `Taskfile.yml`, `.gitignore`, MIT `LICENSE`.

### Changed

- Documentation scrub (separate commit) — depersonalized design rationale; technical claims unchanged.

### Locked design decisions

- Language: Go — single static binary; the install-time surface of other language runtimes is itself an adversarial attack surface
- Format: in-toto ITE-6 envelope + new predicate type `https://jesses.dev/v0.1/action-envelope`
- Log structure: RFC 6962 Merkle tree (byte-exact with Certificate Transparency)
- Anchors: OpenTimestamps (Bitcoin) + Rekor (Sigstore transparency log). No other blockchain.
- Pre-commitment: session-start SCT analog, mandatory
- Signing key (v0.1): software ed25519; hardware attestation (TPM / Secure Enclave / TEE) deferred to v0.3
- Strategic adoption bet: platform-first — a single platform reference integration, followed by others
