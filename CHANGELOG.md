# Changelog

All notable changes to `jesses` are recorded here. This file follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

For the full narrative build log, see [`docs/BUILD_LOG.md`](./docs/BUILD_LOG.md).

## [Unreleased]

### Added

#### Day 2.2b — segment splitter + substitution recursion + wrapper unwrap + shell re-entry

- `internal/shellparse/splitter.go` — `Command` / `Redirect` / `Substitution` types (JSON shape frozen); `Split` and `SplitString`; six-stage `buildCommand`; `fuseSubstitutions` pre-pass that stitches tokens back together when tokenizer split a substitution body on whitespace or separators; `substOpenCount` respecting quoting and backtick toggling; `MaxDepth = 8` with `ErrMaxDepthExceeded` / `ErrUnbalancedSubst`.
- `internal/shellparse/wrapper.go` — frozen 13-entry `wrapperTable` covering sudo / env / time / nice / timeout / stdbuf / xargs / nohup / exec / setsid / ionice / chroot / unshare with per-wrapper `stopFn` for flag and positional consumption; stacked-wrapper support (`sudo env X=y timeout 30 curl` → three wrappers stripped in order).
- `internal/shellparse/redirect.go` — `extractRedirects` handling both spaced and unspaced operator forms, `2>&1`, `&>`, `&>>`, `<<<`; `IsDevTCP` helper recognizing `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` bash raw-socket paths; correct rejection of `<(` / `>(` (these are process substitutions, not redirects).
- `internal/shellparse/subst.go` — `$(...)`, `` `...` ``, `<(...)`, `>(...)` scanning with paren-depth tracking that respects quoting; argv joined with single spaces before scanning so bodies containing shell word splits survive intact; recursive re-invocation of `Tokenize` + `splitAt` at depth+1.
- `internal/shellparse/reentry.go` — `bash -c`, `sh -c`, `dash -c`, `zsh -c`, `ksh -c` detection (plus absolute-path variants like `/bin/bash` and merged short flags like `-xc`); `eval PAYLOAD` re-tokenization; Python / Ruby / Perl / Node `-e` deliberately NOT handled here (language payloads, not shell — deferred to per-language hint packages).
- `internal/shellparse/tokenizer.go` — context-sensitive `&` handling so `>&`, `<&`, `&>`, `&>>` are preserved as redirect-operator parts instead of being split as the background separator; `TokenType.MarshalJSON` emits symbolic names so golden fixtures survive `iota` reordering.
- `internal/shellparse/testdata/segments/` — 12 real-world adversarial fixtures with paired byte-exact `.json` expected output: simple curl baseline, proxy env override, sudo exfil, `bash -c` stage-two, `eval` concatenation hiding (`"cur""l"`), `$(whoami)` exfil via URL, `/dev/tcp` reverse shell, `<()` process-sub exfil, three-layer eval bomb, stacked wrappers, backtick legacy subst, pipeline with logical chain.
- `internal/shellparse/splitter_test.go` + `wrapper_test.go` + `redirect_test.go` + `subst_test.go` + `reentry_test.go` + `golden_test.go` (with `-update` flag) + `bench_test.go` (3 benchmarks + `FuzzSplit` with 11 seeded patterns).
- Test count: 94 unit + 12 golden-driven + 11 fuzz seeds, bringing cumulative to 177 (merkle 18 + audit 6 + policy 30 + shellparse 123). `go vet ./...` clean. Zero external dependencies.
- Performance on AMD Ryzen 5 5600 (hook-path budget): `SplitSimple` 3.1 μs, `SplitAdversarial` (eval + subshell + wrapper + redirect nested) 14.6 μs, `SplitLarge` (100-segment pipeline) 133 μs. Fuzz: 1.2 M executions at 170 k/s in 10 s, zero panics, 299 new-interesting inputs captured.

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
