# verifier-js — second-implementation jesses verifier

Pure JavaScript (ES modules) verifier for the jesses v0.1 attestation format. Zero external dependencies beyond Node 20+ built-ins (`node:crypto`, `node:fs`, `node:path`, `node:url`).

## Why this exists

A standard is defined by **two or more independent implementations producing identical output on the same inputs**. The Go reference under `internal/verify` is the primary; this JavaScript implementation is the second. When both pass the spec corpus at `spec/test-vectors/v0.1/` byte-exactly, jesses stops being "one person's tool" and becomes a protocol other people can safely adopt.

## Layout

```
canonical.mjs   — Event canonical JSON (mirrors Go's CanonicalJSON)
merkle.mjs      — RFC 6962 Merkle tree (byte-exact with Certificate Transparency)
precommit.mjs   — Rekor receipt canonical body (mirrors Go precommit.CanonicalBytes)
verify.mjs      — six-gate verifier
test.mjs        — spec-corpus conformance harness
```

## Conformance check

```bash
cd verifier-js
node test.mjs
```

Expected output:

```
  ✓  happy-path
  ✓  policy-breach
  ✓  tampered-log

3/3 vectors conform to Go reference implementation
```

Exit 0 means every vector's Report matched byte-exactly. Any mismatch prints the diff and exits 1.

## API

```js
import { verify } from "./verify.mjs";

const rpt = await verify({
  envelopePath: "session.jes",
  auditLogPath: "session.log",
  scopePath:    "scope.txt",
  // rekorClient: optional; when omitted G3 does local-hash verify only
});

// rpt.ok is true only when every mandatory gate passed.
// rpt.gates is the per-gate breakdown — same shape as the Go Report.
```

## What this implementation proves about the spec

- Canonical JSON serialization is precisely defined (field order + escaping rules match Go encoding/json with default settings).
- RFC 6962 Merkle tree is the exact byte-level protocol from Certificate Transparency.
- Ed25519 signatures are verifiable with stdlib alone on any modern language runtime.
- Rekor receipt canonical body is deterministic and re-hashable without the original Rekor server.
- Six-gate semantics (G1–G6) are implementation-independent.

## Non-goals

- **Not a hook**. This implementation verifies existing envelopes; it does not intercept agent tool calls or produce new envelopes. For the hook path use the Go binary at `cmd/jesses`.
- **Not Rekor-live**. An online Rekor fetch path is documented in `verify.mjs` but not wired into the harness. The spec corpus is offline baseline. Adding an HTTP Rekor client is ~30 lines of `fetch()` — left out at v0.1 so the second implementation ships with zero external surface.

## Extending

Adding a third implementation (Rust, Python, TypeScript proper, Swift, whatever) requires:

1. SHA-256, ed25519 verify primitives from the target language's crypto stdlib.
2. A faithful port of `canonical.mjs` matching Go's field order and escaping rules.
3. A port of `merkle.mjs` — straight transliteration of the RFC 6962 algorithm.
4. A 6-gate orchestrator matching `verify.mjs`.
5. A conformance harness that loads the spec corpus and asserts byte-identical Reports.

Open a pull request at `verifier-<lang>/` with the implementation and the conformance runner.
