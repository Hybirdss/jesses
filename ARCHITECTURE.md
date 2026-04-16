# jesses — Architecture v0.1

This document defines the module layout, import boundaries, canonical schemas, and invariants for `jesses` v0.1. It is the authoritative reference for every file added to this repository. Any code or document that contradicts this file must either update this file first, or be rejected.

---

## 1. Locked decisions (do not re-litigate)

| Axis | Decision | Rationale |
|---|---|---|
| Language | **Go** (reference + primary verifier) | `pip install` is an adversarial attack surface; single static binary required; Sigstore ecosystem is Go-native |
| Format | **in-toto ITE-6 envelope** + new predicate type `https://jesses.dev/v0.1/action-envelope` | Inherits cosign / Rekor / SLSA verifier infrastructure; a standalone format is 6 months of naval-gazing |
| Log structure | **RFC 6962 Merkle tree** (byte-exact with Certificate Transparency) | O(log n) inclusion and consistency proofs; a hash chain is O(n) and cannot prove append-only extension at a mid-session checkpoint |
| Anchors | **OpenTimestamps** (Bitcoin) + **Rekor** (Sigstore transparency log). No other blockchain | Blockchains solve multi-party consensus; this is a single-party integrity problem. Bitcoin via OTS is free via Merkle aggregation; Rekor is sufficient for public witness |
| Pre-commitment | **Session-start SCT analog**, MANDATORY | Without pre-commitment, the fabricate-entire-session attack is undetectable; SCT is CT's real secret sauce |
| Signing key (v0.1) | **Software ed25519** at `~/.jesses/key`; TPM/TEE deferred to v0.3 | Adversarial-economics defense is honest for v0.1; hardware attestation is the full answer but not a v0.1 blocker |
| Privacy modes | Dual — `privacy=off` (raw input stored, bounty submission) and `privacy=on` (hashes only, enterprise) | Dual-use requirement — the same predicate supports both |
| Adoption lever | **HackerOne** as platform enforcer (the "Chrome" for `.jes`) | CT succeeded because Chrome enforced log inclusion; `.jes` needs the same lever |

---

## 2. Directory layout

```
jesses/
├─ README.md                    hero doc (marketing face)
├─ SPEC.md                      RFC-style standard (v0.1)
├─ THREAT_MODEL.md              submitter-as-adversary + 7 attacks + defenses
├─ ARCHITECTURE.md              this file
├─ SECURITY.md                  disclosure policy
├─ LICENSE                      MIT
├─ CHANGELOG.md
├─ go.mod                       module github.com/yunsu/jesses
├─ go.sum
├─ Taskfile.yml                 cross-platform task runner
│
├─ cmd/
│  └─ jesses/                   CLI entry — subcommands: hook / session / verify / render / init / version
│
├─ internal/                    implementation detail (not importable)
│  ├─ hook/                     PreToolUse hook — reads stdin, appends one event, exits
│  │  ├─ hook.go                dispatcher (tool name → extractor)
│  │  ├─ stdin.go               Claude Code JSON envelope parser
│  │  └─ extractors/
│  │     ├─ bash.go             shell AST parser (Go port of scope-guard.sh)
│  │     ├─ read.go
│  │     ├─ write.go
│  │     ├─ edit.go
│  │     ├─ glob.go
│  │     ├─ grep.go
│  │     ├─ webfetch.go
│  │     ├─ websearch.go
│  │     ├─ agent.go
│  │     ├─ mcp.go
│  │     └─ nop.go
│  │
│  ├─ policy/                   scope.txt parser + matcher (4 namespaces)
│  │  ├─ parser.go
│  │  ├─ matcher.go
│  │  └─ testdata/
│  │
│  ├─ merkle/                   RFC 6962 byte-exact tree
│  │  ├─ tree.go                leaf = SHA256(0x00||data), inner = SHA256(0x01||L||R)
│  │  ├─ inclusion.go           inclusion proof
│  │  ├─ consistency.go         consistency proof
│  │  └─ rfc6962_test.go        official CT test vectors
│  │
│  ├─ precommit/                session-start SCT analog
│  │  ├─ commit.go              emit + Rekor publish
│  │  ├─ verify.go              Rekor inclusion proof predates first event
│  │  └─ schema.go
│  │
│  ├─ audit/                    append-only tool-event log
│  │  ├─ writer.go              flock + fsync(N) (crash-resilient)
│  │  ├─ reader.go
│  │  ├─ record.go              canonical event schema
│  │  └─ canonical.go           JCS RFC 8785 canonicalization
│  │
│  ├─ session/                  lifecycle — start, add, seal
│  │  ├─ session.go
│  │  ├─ id.go                  UUIDv7
│  │  └─ fs.go                  disk layout under ~/.jesses/sessions/<id>/
│  │
│  ├─ rekor/                    Sigstore Rekor client (wraps sigstore/rekor/pkg/client)
│  │  ├─ client.go
│  │  └─ upload.go
│  │
│  ├─ ots/                      OpenTimestamps client
│  │  └─ stamp.go
│  │
│  ├─ attest/                   final .jes bundle assembly
│  │  ├─ build.go               in-toto ITE-6 envelope
│  │  └─ sign.go                ed25519 (DSSE)
│  │
│  ├─ keyring/                  ed25519 key lifecycle
│  │  └─ keyring.go             load / create / perm-check (~/.jesses/key)
│  │
│  ├─ verify/                   verifier engine — 6 gate checks
│  │  ├─ verify.go              orchestrator
│  │  ├─ checks.go              individual gates
│  │  └─ report.go              JSON + human output
│  │
│  └─ render/                   .jes → HTML decision surface
│     ├─ render.go
│     └─ template/
│        └─ surface.html.tmpl
│
├─ pkg/                         public Go API — external projects import these
│  ├─ attestation/              in-toto envelope + predicate Go types
│  │  ├─ envelope.go
│  │  ├─ predicate.go           the standard body as Go types
│  │  └─ doc.go
│  │
│  └─ verify/                   public verifier library
│     └─ verify.go              stable API: Verify(jesBytes, policyBytes) (Result, error)
│
├─ spec/                        language-independent standard artifacts
│  └─ v0.1/
│     ├─ predicate.schema.json  JSON Schema (the real standard body)
│     ├─ attestation.example.json
│     ├─ policy.schema.txt      scope.txt format spec
│     └─ test-vectors/          golden tests other-language impls must pass
│        ├─ valid-tree.json
│        ├─ valid-precommit.json
│        ├─ invalid-tree-edit.json
│        ├─ invalid-consistency.json
│        ├─ invalid-precommit-order.json
│        └─ README.md
│
├─ examples/
│  ├─ claude-code/              reference Claude Code integration
│  │  ├─ install.sh
│  │  ├─ pretool.sh             shim that calls `jesses hook`
│  │  └─ README.md
│  └─ verify-demo/              3rd party receiving + verifying a .jes
│
├─ testdata/                    Go test fixtures
│  ├─ audit/
│  └─ policies/
│
├─ .github/
│  └─ workflows/
│     ├─ ci.yml                 test + lint + build
│     ├─ release.yml            GoReleaser + cosign sign + SLSA L3 generator
│     └─ dogfood.yml            jesses produces its own .jes for its own releases
│
└─ tools/
   ├─ migrate-legacy/           imports bb/ legacy audit.jsonl into new format
   └─ regen-testdata/
```

---

## 3. Import rules (Go module boundaries, compiler-enforced)

```
cmd/jesses      →  internal/* ∪ pkg/*
pkg/*           →  stdlib only  (NEVER internal/*)
internal/hook        →  internal/{policy, audit, session}
internal/session     →  internal/{audit, merkle, precommit}
internal/attest      →  internal/{merkle, precommit, rekor, ots}
internal/verify      →  internal/merkle  +  pkg/attestation   ← MUST stay minimal
internal/policy      →  stdlib only
internal/merkle      →  stdlib only   (RFC 6962 byte-exact, no external deps)
```

**Critical**: `internal/verify` must have the smallest possible dependency set. This is the code that H1, Bugcrowd, and Immunefi will eventually vendor into their platforms. Every additional import is a barrier to adoption. Stdlib + pure Sigstore types only.

**Critical**: `pkg/*` never imports `internal/*`. The public API is a thin layer over stable types. The compiler enforces this via Go's internal-package rules.

---

## 4. Canonical tool-event record

```go
// internal/audit/record.go
type Event struct {
    Seq          uint64         `json:"seq"`               // monotonic within session
    TS           string         `json:"ts"`                // RFC3339Nano UTC
    Tool         string         `json:"tool"`              // "Bash", "Read", "Edit", "mcp__foo__bar", ...
    InputHash    string         `json:"input_hash"`        // sha256 of canonical input (always present)
    InputFull    map[string]any `json:"input,omitempty"`   // raw input (privacy=off only)
    Destinations []string       `json:"destinations,omitempty"` // extracted hosts/paths/repos
    Decision     string         `json:"decision"`          // "allow" | "warn" | "block"
    Reason       string         `json:"reason"`            // matching rule or "unpoliced"
    PolicyRef    string         `json:"policy_ref"`        // sha256 of scope.txt at this moment
}
```

Two serialization modes, selected at session start, persist for the whole session:

- `privacy=off` (default, bounty submission): `InputFull` populated. Triage team sees exact commands.
- `privacy=on` (enterprise compliance): `InputFull` omitted, only `InputHash`. Proprietary commands are protected.

The Merkle tree structure is identical in both modes. The predicate records the mode.

---

## 5. `.jes` predicate schema (the standard body)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "report.md", "digest": {"sha256": "..."}}],
  "predicateType": "https://jesses.dev/v0.1/action-envelope",
  "predicate": {
    "spec_version": "0.1",
    "session_id": "01HQ8A7X...",
    "started_at": "2026-04-16T08:30:00Z",
    "ended_at":   "2026-04-16T16:45:00Z",
    "privacy_mode": "off",
    "policy": {
      "sha256": "abc...",
      "content_ref": "git+https://github.com/acme/policies#cc61-v3"
    },
    "precommit": {
      "rekor_log_index": 12345678,
      "rekor_entry_uuid": "...",
      "rekor_inclusion_proof": "base64...",
      "signed_at": "2026-04-16T08:30:00.123Z"
    },
    "audit": {
      "merkle_alg": "rfc6962-sha256",
      "tree_size": 4201,
      "tree_root_hash": "...",
      "counts_by_tool":     {"Bash": 2739, "Read": 891, "Grep": 342, "Edit": 142},
      "counts_by_decision": {"allow": 4151, "warn": 50, "block": 0}
    },
    "anchor": {
      "opentimestamps_proof": "base64..."
    },
    "signer": {
      "alg": "ed25519",
      "pubkey": "..."
    }
  }
}
```

The JSON Schema form of this predicate lives at `spec/v0.1/predicate.schema.json` and is the language-independent contract.

---

## 6. CLI subcommands

```
jesses init                          install hook into .claude/hooks/ and generate key
jesses session start --policy FILE   emit pre-commit, initialize session directory
jesses hook                          single-event append (called by Claude Code PreToolUse)
jesses session end                   build Merkle tree, sign .jes, stamp with OTS, publish to Rekor
jesses verify FILE.jes               run 6 gate checks, exit 0/1, JSON+human output
jesses render FILE.jes               emit HTML decision surface
jesses version                       --json supported
```

**Performance requirement**: `jesses hook` must exit in 5–10 ms per call. Claude Code invokes it once per tool use; thousands per session. The hook only appends one record (flock + write + fsync(N)). All heavy work (Merkle tree construction, signing, network anchoring) happens in `session end`.

---

## 7. Seven invariants (one per layer) — the definition of "correct"

| # | layer | invariant | enforcement |
|---|---|---|---|
| 1 | ENFORCE | the observer does not perturb the observed agent | hook reads stdin, writes disk, never touches agent context; zero tokens injected |
| 2 | PRE-COMMIT | the session has a lower time bound | Rekor inclusion proof for the pre-commit must predate the first event's timestamp; verifier enforces |
| 3 | MERKLE TREE | append-only is mathematically provable | RFC 6962 consistency proof — any mid-session checkpoint can be shown to be a strict prefix of the final tree |
| 4 | ANCHOR | the session has an upper time bound | OpenTimestamps Bitcoin anchor — session end cannot be back-dated |
| 5 | ATTEST | in-toto ecosystem compatibility | cosign can verify the envelope with zero jesses-specific code |
| 6 | VERIFY | deterministic, bit-exact reproducible | verifier does no network calls (Rekor + OTS proofs are embedded); same input → same output across environments |
| 7 | TEE | (v0.3) signing environment provably matches open-source binary | Nitro quote / TDX attestation / Secure Enclave counter — v0.1 ships adversarial-economics defense instead |

Breaking any invariant means the "honest observer" claim is retracted. All seven must hold for jesses to be called interpretability without borrowed prestige.

---

## 8. v0.1 build order (5 days, shippable at end)

| Day | Deliverable | Pass criterion |
|---|---|---|
| 1 | `internal/merkle` RFC 6962 complete + unit tests | All official CT test vectors pass |
| 1 | `internal/audit` writer + canonical JSON | flock fuzz test + concurrent append test |
| 2 | `internal/policy` 4-namespace parser + `internal/hook` dispatcher + 9 extractors | Each tool type has unit tests for input extraction |
| 3 | `internal/session` + `internal/precommit` + `internal/rekor` | Rekor testnet: publish pre-commit, fetch inclusion proof |
| 4 | `internal/ots` + `internal/attest` + ed25519 sign + in-toto envelope | Self-generated `.jes` is valid under `cosign verify-blob` |
| 4 | `internal/verify` 6-gate orchestrator | All 5 test vectors in `spec/v0.1/test-vectors/` classify correctly |
| 5 | `cmd/jesses/main.go` CLI + `examples/claude-code/` install script | End-to-end: real Claude Code session → .jes → verify PASS |
| 5 | GoReleaser + cosign release workflow + SLSA L3 generator | Released binary passes its own `jesses verify` on its own `.jes` (dogfood) |

Every day ends with a passing test. No Day with broken tests. No "I'll fix it tomorrow."

---

## 9. What explicitly does NOT belong in v0.1

- Go code or config that imports `github.com/ethereum/go-ethereum` or any Solidity tooling
- Any `contracts/` directory
- Python, JavaScript, or Rust code (other-language verifiers are v0.2+, except as documentation)
- Agent reputation tracking (v0.4)
- ZK compliance proofs (v0.3+)
- Between-session planner (derived from bb/notes/jesses-decision-surface.html — deprioritized)
- Platform integration SDKs beyond the reference Go `pkg/verify`
- A web UI other than the static HTML `render` command
- Any dependency on the bb/ harness — jesses is standalone from day 0

---

## 10. Prior art this architecture leans on

- **Sigstore / cosign / SLSA (Go ecosystem)** — language verdict (Go), format verdict (in-toto ITE-6), ecosystem reuse over reinvention, adversarial-economics stance for v0.1 keys
- **Certificate Transparency (RFC 6962)** — Merkle tree vs chain, pre-commitment as the CT secret sauce, multi-operator federation for v0.2+, HackerOne as the Chrome analog, log availability as a security property
- **OpenTimestamps + Ethereum Attestation Service precedents** — blockchain minimization, OpenTimestamps sufficient, ZK as v0.3 research, EAS-style primitives as the correct reputation direction if that feature ever ships

This architecture is a single in-house synthesis pass across those three bodies of prior art. It is not a compromise — it is the intersection of what each body of work treats as non-negotiable.

<!-- ARCHITECTURE-TRACKER:AUTO-START -->
# Architecture

> Auto-generated by architecture-tracker. Do not edit the section between AUTO-START and AUTO-END markers.

## Tech Stack
- **Languages**: Go

## Overview
- **89** source files, **14,307** lines of code
- **6** modules

## Entry Points
- `cmd/jesses/main.go`
- `tools/specgen/main.go`

## Modules

| Module | Files | Lines | Types |
|--------|-------|-------|-------|
| `internal` | 69 | 11,230 | .go |
| `cmd` | 13 | 2,118 | .go, .html |
| `pkg` | 5 | 546 | .go |
| `tools` | 1 | 275 | .go |
| `examples` | 1 | 138 | .py |
| `(root)` | 0 | 0 |  |

## Module Dependencies
```
  cmd -> internal
  internal -> cmd
  pkg -> internal
  tools -> internal
```

<!-- ARCHITECTURE-TRACKER:AUTO-END -->
