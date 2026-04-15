# jesses test vectors

Corpus of test vectors for cross-implementation conformance.

## Purpose

Two implementations of the jesses verifier, in any language, are conformant **if and only if** they produce byte-identical `Report` JSON for every vector under `v0.1/`.

That is the meaning of "standard" — same inputs, same output, across implementations. Not a claim; a test.

The Go reference implementation (`internal/verify` + `verifier-js/` harness) and the JavaScript second implementation (`verifier-js/verify.mjs`) both pass this corpus. A third implementation written in Rust, TypeScript proper, or any language with SHA-256 and ed25519 is welcome to join — open a pull request adding `verifier-<lang>/` with a conformance runner and CI hookup.

## Corpus layout

```
v0.1/
  <vector-name>/
    session.jes     — the attestation envelope under test
    session.log     — the append-only audit log (JSONL)
    scope.txt       — the policy used at session open
    vector.json     — metadata + expected_report
```

Current vectors:

| name | description |
|---|---|
| `happy-path` | Three allowed events, all six gates behave as expected (G1–G5 pass, G6 advisory). |
| `policy-breach` | One event was denied. G5 must fail even though G1–G4 pass. |
| `tampered-log` | Log rewritten after signing. G2 Merkle-root gate must fail. |

## vector.json shape

```json
{
  "name":            "happy-path",
  "description":     "Three allowed events, scope matches...",
  "schema_version":  "v0.1",
  "fixed_seed_hex":  "6a65737365732d73706563...",
  "fixed_start":     "2026-04-16T12:00:00Z",
  "expected_report": {
    "gates":       [ { "name": "G1", "title": "...", "pass": true, "detail": "...", "severity": "mandatory" }, ... ],
    "ok":          true,
    "session_id":  "6a65737365732d7665633a6861707079..."
  },
  "expected_summary": { "overall_ok": true, "g2_pass": true, "g5_pass": true, "g6_pass": false }
}
```

The `expected_report` field is the **canonical truth**: a conforming verifier serializes its own Report and must produce the exact same JSON when run against the vector's inputs.

## Conformance contract

Run your verifier with these inputs:

```
verify({
  envelopePath: "session.jes",
  auditLogPath: "session.log",
  scopePath:    "scope.txt",
  rekorClient:  null,          // offline — the corpus is offline-mode baseline
})
```

Then serialize the returned Report with:

- `gates` field first, containing an array of gate objects with fields `name`, `title`, `pass`, `detail`, `severity` in that order
- `ok` field second
- `session_id` field third
- No whitespace, no indentation
- Boolean `pass` is a literal `true`/`false`, not a string

Compare byte-for-byte against `expected_report` serialized the same way. Equal means conforming.

The Go harness is `internal/verify/spec_test.go`. The JavaScript harness is `verifier-js/test.mjs`. Both print `✓` per vector and exit 0 when every vector conforms.

## Regenerating the corpus

```bash
go run ./tools/specgen ./spec/test-vectors/v0.1
```

Any diff against the committed vectors signals a spec-breaking change. Review carefully; bump the schema version in `internal/attest.SchemaVersion` and the corpus path (`v0.1` → `v0.2`) if the diff is intentional. Never commit corpus changes silently.

## Additional vectors

Contributions welcome. A good new vector isolates one behavior:

- a specific cryptographic failure (bad signature bytes, truncated envelope, malformed precommit)
- a specific policy shape (advisory mode, multi-namespace scope, wildcard edge case)
- a specific Merkle-tree edge case (1 leaf, 2 leaves, 2^n leaves, 2^n+1 leaves)

Add the vector under `v0.1/` (or a new corpus path if it exercises behavior not yet specified) and re-run both conformance harnesses.
