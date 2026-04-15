# jesses — Build Log

A narrative per-phase record of how `jesses` v0.1 is built. Each entry captures scope, deliverables, test count, pass criteria, and commit references.

This file is the single place a new contributor (or a future maintainer returning after a hiatus) should look to reconstruct the project's development history without reading every commit message.

For the strategic plan see [`ROADMAP.md`](../ROADMAP.md). For architecture see [`ARCHITECTURE.md`](../ARCHITECTURE.md). For threat model see [`THREAT_MODEL.md`](../THREAT_MODEL.md). For the specification see [`SPEC.md`](../SPEC.md).

---

## Overview

`jesses` is a cryptographic attestation standard for security deliverables produced by autonomous LLM agents. When such an agent produces a bug bounty report, a penetration test finding, or a B2B security audit, `jesses` emits a tamper-evident `.jes` file alongside the deliverable. A third party — regulator, triage team, client security officer — can verify the file mathematically without accessing the underlying audit log.

The project is intentionally a **primitive**, not a product. The primitive (hook, attestation format, verifier, specification) is MIT-licensed and will remain so in perpetuity. See the Governance section in the README for the pre-launch commitment.

---

## Build phases

### Day 0 — scaffold

Scope: repository structure, architecture decision records, and specification skeletons. No executable code in this commit.

Deliverables:

- `README.md` — hero doc, locked decisions, governance pre-commit
- `ARCHITECTURE.md` — module layout, import rules, seven invariants, build order
- `THREAT_MODEL.md` — submitter-as-adversary premise, seven attacks, defense matrix, residual v0.1 gap, v0.3 TEE roadmap
- `SPEC.md` — v0.1 standard (predicate URI, in-toto ITE-6 envelope, canonical event schema, six verify gates, test vector index)
- `ROADMAP.md` — 90-day strategic plan
- `LICENSE` (MIT), `.gitignore`, `Taskfile.yml`, `go.mod` (module path, Go 1.22), `CHANGELOG.md`, `SECURITY.md`
- Directory tree: `cmd/`, `internal/`, `pkg/`, `spec/`, `examples/`, `testdata/`, `.github/`, `tools/` — 35 directories with `.gitkeep` placeholders

Tests: n/a (no executable code).

### Day 1 — Merkle tree + audit writer

Scope: implement `internal/merkle` (RFC 6962 byte-exact) and `internal/audit` (append-only canonical writer). Zero external dependencies beyond Go stdlib.

Deliverables:

- `internal/merkle/tree.go` — `HashLeaf`, `HashChildren`, `RootHash`, `RootFromLeafHashes`, `mth`, `largestPow2Less`
- `internal/merkle/inclusion.go` — `InclusionProof`, `VerifyInclusion` (iterative per RFC 6962 §2.1.1.2)
- `internal/merkle/consistency.go` — `ConsistencyProof` (SUBPROOF algorithm), `VerifyConsistency` (per RFC 6962 §2.1.4.2)
- `internal/merkle/rfc6962_test.go` — 18 tests
- `internal/audit/record.go` — canonical `Event` struct with stable field ordering
- `internal/audit/canonical.go` — `CanonicalJSON` (deterministic via Go `json.Marshal`; struct field declaration order fixed, map keys sorted since Go 1.12)
- `internal/audit/writer.go` — `Writer` with per-`Append` flock, `sync.Mutex` for in-process serialization, `O_APPEND` for cross-process atomicity below PIPE_BUF
- `internal/audit/writer_unix.go` — `syscall.Flock` wrapper with `!windows` build tag
- `internal/audit/writer_test.go` — 6 tests including concurrent-append fuzz (8 workers × 50 events = 400 records, no interleaving, no loss)

Tests: 24 (18 merkle + 6 audit), all green on first run.

Critical invariant: **Merkle leaf serialization must remain byte-exact forever.** The `Event` struct field order is frozen; reordering would invalidate every past `.jes` file.

Key tests to rely on for regression protection:

- `TestInclusionAllIndices` — every leaf index in trees of sizes `{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 17, 31, 32, 33}`; any path-generation or verification bug surfaces here.
- `TestConsistencyAllPairs` — every `(m, n)` pair for `n ≤ 12`; catches off-by-one errors in LSB-stripping and the `m=0` / `m=n` boundary cases.
- `TestInclusionRejectsTamperedProof`, `TestConsistencyRejectsTamperedProof` — flipping any byte of a proof must cause verification to fail.
- `TestCanonicalDeterministic`, `TestCanonicalMapOrderStable` — canonical serialization is byte-identical for semantically-equivalent events regardless of map key insertion order.
- `TestConcurrentAppend` — eight goroutines each running a fresh `Writer` on the same file produce exactly `N` newline-terminated records, each of which round-trips through `json.Unmarshal`.

### Day 2.1 — scope.txt parser + five-namespace matcher + exclusion-first precedence

Scope: implement `internal/policy` — parsing and evaluation of `scope.txt` files. Plain-text, line-oriented, grep-friendly.

Deliverables:

- `internal/policy/parser.go` — `bufio.Scanner`-based parser. Five-namespace shape-based classification: `path:` prefix → NSPath, `mcp:` prefix → NSMCP, `<chain>:0x<hex>` → NSContract, `<org>/<repo>` (no `.` and no `:`) → NSRepo, anything else → NSHost. Supports `mode: strict|advisory` directive, `in:` / `out:` rule lines, full-line and inline `#` comments.
- `internal/policy/matcher.go` — five match modes:
  - host exact + anchored wildcard (`*.target.com` matches `sub.target.com` but NOT `target.com` or `evil-target.com`)
  - path glob with `*` / `**` / `?` / character-class (multi-segment `**` via split-on-`/` + backtracking, single-segment via `path.Match`)
  - repo exact
  - contract case-insensitive (`strings.EqualFold`)
  - MCP exact-or-prefix-with-colon (pattern `mcp:srv` matches `mcp:srv` and `mcp:srv:tool` but NOT `mcp:srv-v2`)
- `internal/policy/precedence.go` — exclusion-first evaluation (every `out:` rule checked before any `in:` rule), first-match-wins within `in:` block, mode-dependent unpoliced handling (strict → `VerdictBlock`, advisory → `VerdictWarn`)
- `internal/policy/parser_test.go` — 12 parser tests
- `internal/policy/matcher_test.go` — 11 matcher tests including the critical `TestAnchoredSubdomain`
- `internal/policy/precedence_test.go` — 7 precedence tests

Tests: 30, bringing cumulative to 54.

Critical regression test: `TestAnchoredSubdomain` — pattern `*.target.com` must match `sub.target.com` and `Sub.TARGET.COM` (case-insensitive) but must NOT match `target.com` itself, `evil-target.com`, `notarget.com`, or `target.com.evil.com`. This is the subdomain-confusion class that naive suffix matching gets wrong.

### Documentation scrub — depersonalization

Scope: remove named-individual attributions from design rationale. Technical claims unchanged; only attribution style revised.

Files touched: `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `CHANGELOG.md`, `THREAT_MODEL.md`.

Technical claims unchanged: Go single-binary, in-toto ITE-6 envelope, RFC 6962 Merkle tree, OpenTimestamps + Rekor only, SCT-style session-start pre-commitment, exclusion-first policy, submitter-as-adversary threat model, five-day build order.

### Day 2.2a — shell tokenizer

Scope: first slice of the bash extractor. In-house focused POSIX shell tokenizer that produces only what `jesses` needs for destination extraction. Deliberately NOT a full bash grammar parser.

Deliverables:

- `internal/shellparse/doc.go` — package scope statement including the explicit list of constructs NOT implemented: arrays, here-documents, functions, control flow, arithmetic, parameter expansion beyond literal preservation, coprocesses.
- `internal/shellparse/tokenizer.go` — `Tokenize(input) ([]Token, error)` with exported types `TokenType`, `Token`; sentinel errors `ErrUnterminatedSingleQuote`, `ErrUnterminatedDoubleQuote`; `IsSeparator` helper. Handles five command separators (`;`, `|`, `||`, `&`, `&&`) plus newline; three quoting modes (single quotes literal, double quotes with POSIX escapes for `$` / `` ` `` / `"` / `\` / newline, backslash outside quotes with line continuation); adjacent-quoted-run concatenation (the `eval "cur""l evil.com"` hiding pattern); subshell / backtick preservation as literal word content for higher layers to recurse into.
- `internal/shellparse/tokenizer_test.go` — 29 tests covering:
  - empty / whitespace-only input
  - single and multi-word tokenization
  - all single-quote cases (literal body, empty body, special-char preservation)
  - all double-quote escape cases plus literal-other-backslash behavior
  - adjacent-quote concatenation
  - all backslash forms (space escape, operator escape, line continuation, trailing)
  - all five operators alone and chained without whitespace
  - quoted operators (must remain literal text inside WORD tokens)
  - `IsSeparator` helper correctness
  - unterminated-quote error paths
  - subshell / backtick preservation
  - five real-world adversarial scenarios: `curl --proxy`, `sudo curl`, `HTTPS_PROXY=` env assignment, `bash -c "..."` re-entry payload, `cat < /dev/tcp/host/port` raw TCP redirection
  - Start-offset tracking for diagnostics

Tests: 29, bringing cumulative to 83.

---

## Current state

- **6 commits** on `main`, pushed to public remote as linear fast-forward history
- **4 Go packages** implemented: `internal/merkle`, `internal/audit`, `internal/policy`, `internal/shellparse`
- **83 tests** passing across all packages
- **Zero external dependencies** beyond Go stdlib
- **`pkg/` public API** — not yet started (Day 4 scope)
- **`cmd/jesses/main.go` CLI entry** — not yet started (Day 5 scope)

---

## Next milestone — Day 2.2b

Segment splitter that consumes the `shellparse.Tokenize` output and produces a higher-level structured command representation.

Expected deliverables:

- Segment splitter that walks separators (`;`, `|`, `||`, `&`, `&&`, newline) and emits per-segment command runs
- Subshell recursion for `$(...)`, `<(...)`, and backticks — body extraction and re-invocation of `Tokenize` on the body
- Wrapper unwrap for `sudo`, `env`, `time`, `nice`, `timeout`, `stdbuf`, `xargs` — first non-wrapper token becomes the effective command
- `bash -c` and `eval` string payload re-entry — take the quoted payload's Value and tokenize it as fresh input
- `/dev/tcp/<host>/<port>` redirection destination detection

Test expectation: multi-segment golden-file fixtures covering subshell recursion depth, nested wrapper unwrap, three-level `eval` re-entry, and proxy-override destination pairs.

---

## Decision log

### Chosen

- **Go** as reference implementation language — single static binary, adversary-resistant to supply-chain injection via install-time runtime, mature cryptographic standard library, and the canonical language of the Sigstore ecosystem
- **in-toto ITE-6 envelope** with new predicate type `https://jesses.dev/v0.1/action-envelope` — reuses the Sigstore / cosign / Rekor / SLSA verifier infrastructure for free and avoids months of standalone-format work
- **RFC 6962 Merkle tree**, byte-exact with Certificate Transparency — enables O(log n) inclusion and consistency proofs; a hash-chain alternative cannot prove append-only extension at a mid-session checkpoint
- **OpenTimestamps (Bitcoin) and Rekor (Sigstore transparency log)** as the only external anchors — blockchains solve multi-party consensus; `jesses` faces a single-party integrity problem, so Bitcoin via OpenTimestamps (free via Merkle aggregation) plus Rekor (sufficient for public witness) is adequate
- **Session-start SCT analog** — mandatory pre-commitment. Without it, the fabricate-entire-session attack is undetectable. The SCT pattern borrowed from Certificate Transparency is what makes fabrication detectable, not merely prohibited.
- **Software ed25519 key for v0.1**; hardware attestation (TPM, Secure Enclave, Intel TDX, AWS Nitro Enclaves) deferred to v0.3 — the adversarial-economics defense (fabricating a convincing fake session costs more than doing the work honestly) is honest for the v0.1 bar
- **Dual privacy modes** — `privacy=off` stores raw input (bounty submission pattern), `privacy=on` stores only input hashes (enterprise compliance pattern). The same predicate type supports both; Merkle leaf structure is identical in both modes.
- **Exclusion-first policy evaluation** — every `out:` rule is checked before any `in:` rule, matching user intuition (e.g., `*.github.com` allow but `blog.github.com` out — exclusion should win even when listed later in the file)
- **Platform-first adoption bet** — pursue a single platform integration as the reference rather than chasing regulators or broadcasting to individual hunters. One integration is enough; others follow.

### Deferred

- **Second-language verifier (TypeScript)** — commissioned during v0.1 development, ships within 2 weeks of v0.1 reference. Two independent implementations passing the same test vectors is what signals the project is a standard, not one person's tool.
- **TEE attestation** — v0.3 milestone. Closes the residual interleave-fakes gap mathematically.
- **Zero-knowledge compliance proofs** — v0.3+. Regulated industries would use this; stack likely RiscZero (arbitrary Rust execution in a ZK VM) or Noir (simpler circuits). Verification key on-chain, proof generated and submitted off-chain.
- **Agent reputation primitive** — v0.4+. If cross-customer reputation portability becomes a real requirement, Ethereum Attestation Service on an L2 is the correct primitive. Not on the v0.1 / v0.2 path.
- **Neutral foundation governance** — pre-committed in the README; legal vehicle and bylaws targeted for v0.1 + 11 weeks.
- **Multi-operator transparency log federation** — v0.2 work. v0.1 accepts a single operator (Rekor) for launch; the trust model fully resolves only when a second independent operator exists.

### Rejected

- **Python reference implementation** — `pip install` is itself an adversarial attack surface; incompatible with the submitter-as-adversary threat model
- **Full shell grammar parser as a dependency** — ties canonical Merkle leaf hashes to an upstream parser's release cycle; unacceptable for a tool whose outputs must be bit-identical forever
- **Standalone attestation format** — would require writing a transparency-log client from scratch; roughly six months of negative-differentiation work
- **Additional blockchains beyond Bitcoin via OpenTimestamps** — the specific use case is single-party integrity, not multi-party consensus, so no additional chain adds useful properties at v0.1 scope
- **Dashboard, hosted service, or cloud offering in v0.1** — every such addition is a step toward "product" and away from "primitive"
- **Regex-based policy matcher** — too many edge cases; users expect glob semantics when they write `*.target.com`
- **Hash chain instead of Merkle tree for the audit log** — cannot produce O(log n) inclusion proofs, cannot prove append-only extension at a checkpoint

---

## Session resume protocol

When a fresh session picks up `jesses` development:

1. `cd` into the repository root.
2. `git pull origin main` to ensure local matches remote.
3. `go test ./...` — must show all packages passing before any new work.
4. Read this file (`docs/BUILD_LOG.md`) first; do not re-read every commit.
5. Consult `ROADMAP.md` for the current phase and the next-milestone definition.
6. Consult `ARCHITECTURE.md` for module boundaries and import rules before adding any file.
7. Do not re-litigate any decision in the "Chosen" section above without a strong new argument grounded in evidence.
8. Every new commit must leave `go test ./...` green.

When the session delivers a new build phase:

1. Add a new `###` entry to the Build phases section above with date, scope, deliverables, test count, and critical invariants.
2. Update the Current state section.
3. Update the Next milestone section.
4. If a decision is made or reversed, update the Decision log.

This file is maintained alongside the code and is part of the commit that ships each new build phase.
