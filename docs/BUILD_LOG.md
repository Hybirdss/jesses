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

### Day 2.2b — segment splitter + substitution recursion + wrapper unwrap + re-entry

Scope: consume the flat `shellparse.Tokenize` output and produce the structured `Command` tree that downstream extractors walk. This is the layer that turns "a shell string" into "every destination the command could touch, including ones hidden inside `eval`, `$(...)`, `bash -c`, proxy overrides, and `/dev/tcp` raw sockets."

Deliverables:

- `internal/shellparse/splitter.go` — `Command`, `Redirect`, `Substitution` types with frozen JSON shape; `Split([]Token)` and `SplitString(string)`; six-stage `buildCommand` (original capture → env split → redirect extract → wrapper unwrap → substitution scan → re-entry); `fuseSubstitutions` pre-pass that stitches tokens back together when the tokenizer split a substitution body on whitespace or separators; `substOpenCount` ignoring single-quoted regions and respecting backtick toggling; `MaxDepth=8`, `ErrMaxDepthExceeded`, `ErrUnbalancedSubst`.
- `internal/shellparse/wrapper.go` — frozen 13-entry `wrapperTable` (sudo, env, time, nice, timeout, stdbuf, xargs, nohup, exec, setsid, ionice, chroot, unshare); per-wrapper `stopFn` handling flag/positional consumption (sudo `-u`, env `-u`/`-S` and `NAME=VALUE` runs, timeout DURATION, chroot DIR); left-to-right peel with stacked-wrapper support.
- `internal/shellparse/redirect.go` — `extractRedirects` handling spaced and unspaced forms (`>out`, `> out`, `2>&1`, `&>out`, `&>>out`, `<<<`, etc.); correct rejection of `<(` / `>(` which are process substitutions not redirects; `IsDevTCP` recognizing `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` bash raw-socket paths.
- `internal/shellparse/subst.go` — `scanSubstitutions` walking env + argv + redirect targets (argv joined with spaces so bodies containing shell word splits survive); `findSubstitutions` for `$(...)`, `` `...` ``, `<(...)`, `>(...)` with paren-depth tracking that respects single and double quotes; `reparseBody` recursion into `Tokenize`+`splitAt` at depth+1.
- `internal/shellparse/reentry.go` — detect `bash -c`, `sh -c`, `dash -c`, `zsh -c`, `ksh -c` (plus absolute-path variants and merged short flags like `-xc`); detect `eval` and re-tokenize all remaining argv joined with spaces; Python / Ruby / Perl / Node `-e` deliberately NOT handled (language payloads, not shell — deferred to per-language hint packages in v0.2).
- `internal/shellparse/tokenizer.go` — two targeted additions: context-sensitive `&` handling so `>&`, `<&`, `&>`, and `&>>` are recognized as part of redirect operators rather than as the background separator; `TokenType.MarshalJSON` emitting symbolic names so golden fixtures are insulated from `iota` reordering.
- `internal/shellparse/testdata/segments/` — 12 real-world adversarial fixtures paired with byte-exact golden `.json` outputs covering: proxy env override, sudo exfil, `bash -c` stage-two payload, `eval` concatenation hiding, `$()` exfil, `/dev/tcp` reverse shell, `<()` process-substitution exfil, three-layer `eval` bomb, stacked wrappers, backtick legacy subst, and pipelines with logical chains.
- `internal/shellparse/splitter_test.go` (15) + `wrapper_test.go` (12) + `redirect_test.go` (17) + `subst_test.go` (12) + `reentry_test.go` (10) + `golden_test.go` (12 driven fixtures with `-update` regeneration flag) + `bench_test.go` (3 benchmarks + `FuzzSplit`).

Tests: 94 unit + 12 golden + 11 fuzz seeds = 117 new, bringing the shellparse package to 152 and the project to 177.

Critical invariants:

- `wrapperTable` contents are frozen. Adding or removing an entry changes `Argv` shape for matching commands and therefore changes the destinations downstream extractors emit into canonical Merkle-leaf hashes. Any edit requires a spec version bump.
- `reentryShells` contents are frozen for the same reason.
- `MaxDepth = 8` is a contract — inputs that exceed this fail with `ErrMaxDepthExceeded`, they never produce partial output. Without this, an adversarial eval bomb could exhaust goroutine stack before the hook could record anything.
- Canonical JSON output uses string-typed `TokenType` serialization so that golden fixtures survive additions to the `TokenType` enum.

Performance (AMD Ryzen 5 5600, Go 1.22, `-benchtime=5000x`):

- `SplitSimple` (one `curl` with flags): **3.1 μs/op**, 3.2 KB, 40 allocs
- `SplitAdversarial` (sudo + env + timeout + `bash -c` with nested subshells, redirects, and pipeline): **14.6 μs/op**, 12 KB, 187 allocs
- `SplitLarge` (100-segment pipeline): **133 μs/op**, 155 KB, 1428 allocs

The adversarial case — which covers every feature the parser handles — stays under 15 μs. A hook running at the far end of an agent loop emits hundreds of Bash calls per minute; this overhead is invisible to the agent.

Fuzzing:

- `FuzzSplit` with 11 real-world seeds: ran for 10 s at 170 k execs/s on 12 workers. 1.2 M total executions, zero panics, zero unexpected errors, 299 new interesting inputs captured to `testdata/fuzz/FuzzSplit/`. The parser's input contract (one of four sentinel errors or success) holds for arbitrary byte strings.

---

## Current state

- **7 commits** on `main`, pushed to public remote as linear fast-forward history
- **4 Go packages** implemented: `internal/merkle`, `internal/audit`, `internal/policy`, `internal/shellparse`
- **177 tests** passing across all packages (merkle 18 + audit 6 + policy 30 + shellparse 123)
- **Zero external dependencies** beyond Go stdlib
- **Hook-path latency** ≤ 15 μs for the adversarial case, 3 μs for the happy path
- **`pkg/` public API** — not yet started (Day 4 scope)
- **`cmd/jesses/main.go` CLI entry** — not yet started (Day 5 scope)

---

## Next milestone — Day 2.2c

Per-tool positional parsers for the network-relevant CLIs, layered on top of the `shellparse.Command` that Day 2.2b produces.

Expected deliverables:

- `internal/extractors/bash/` package with per-tool parsers for `curl`, `wget`, `nc` / `ncat`, `nmap`, `dig`, `host`, `nslookup`, `ssh`, `scp`, `rsync`, `ftp`, `sftp`, `telnet`, and the bug-bounty tooling set `httpx`, `nuclei`, `subfinder`, `amass`, `waybackurls`, `gau`, `katana`, `sqlmap`, `cast`, `anvil`, `forge`
- Proxy override detection that fires across: `curl -x` / `--proxy` / `--connect-to` / `--resolve`, environment `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` (captured from `Command.Env` and from `env` wrapper), and `ssh -o ProxyCommand=`
- Destination emission as `(kind, host, port, raw)` records so the policy layer gets a uniform shape regardless of which CLI produced it
- Golden fixtures for 40+ real-world command lines extracted from public bug-bounty writeups and CTF walkthroughs

Test expectation: per-tool fixture corpus with destination assertions (not just argv round-trip), plus adversarial proxy-override cases that a naive parser misses.

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
