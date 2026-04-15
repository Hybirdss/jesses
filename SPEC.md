# jesses v0.1 Specification

**Status**: draft, pre-launch. Normative for the v0.1 reference implementation.

**Predicate type URI**: `https://jesses.dev/v0.1/action-envelope`

**Companion files**:

- [`spec/v0.1/predicate.schema.json`](./spec/v0.1/predicate.schema.json) — JSON Schema for the predicate
- [`spec/v0.1/attestation.example.json`](./spec/v0.1/attestation.example.json) — a valid example attestation
- [`spec/v0.1/policy.schema.txt`](./spec/v0.1/policy.schema.txt) — `scope.txt` format spec
- [`spec/v0.1/test-vectors/`](./spec/v0.1/test-vectors/) — golden tests other-language verifiers must pass

---

## 1. Overview

`jesses` defines a standard attestation artifact for security deliverables produced by autonomous LLM agents. The artifact — hereafter "the `.jes` bundle" — is a signed in-toto ITE-6 envelope containing a new predicate type that describes the agent's action envelope during the session that produced the deliverable.

A `.jes` bundle is verified by any party holding:

1. the bundle itself
2. the policy file referenced by the bundle (content-addressed by SHA-256)
3. no other inputs

Verification is **deterministic**, **network-free** (all necessary transparency-log inclusion proofs are embedded), and **reproducible across environments**.

---

## 2. Why in-toto ITE-6

`jesses` does not reinvent the attestation envelope. It reuses the in-toto ITE-6 envelope standard (identical to what Sigstore, SLSA, and cosign all consume). Specifically:

- The outer envelope is a [DSSE signature wrapper](https://github.com/secure-systems-lab/dsse)
- The payload is an in-toto [v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- The `predicateType` field names a new URI owned by `jesses.dev`
- The `predicate` field carries the jesses-specific payload

This design means an existing `cosign verify-blob` command can verify the envelope's signature and structural validity without knowing anything about jesses. The jesses-specific checks (Merkle tree, pre-commitment, OpenTimestamps anchor) live in `jesses verify` on top.

---

## 3. Envelope shape

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload":     "<base64 DSSE payload>",
  "signatures": [
    {
      "keyid": "ed25519:0xFACE...",
      "sig":   "<base64 ed25519 signature>"
    }
  ]
}
```

The decoded `payload` is an in-toto v1 Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name":   "report.md",
      "digest": {"sha256": "..."}
    }
  ],
  "predicateType": "https://jesses.dev/v0.1/action-envelope",
  "predicate": { /* see §4 */ }
}
```

The `subject` array names the deliverable(s) that this `.jes` attests to. A typical bug bounty submission has one subject (the report markdown). A multi-artifact audit deliverable may list several.

---

## 4. Predicate schema

```json
{
  "spec_version": "0.1",
  "session_id":   "01HQ8A7X...",           // UUIDv7
  "started_at":   "2026-04-16T08:30:00Z",  // RFC 3339
  "ended_at":     "2026-04-16T16:45:00Z",
  "privacy_mode": "off",                   // "off" | "on"
  "policy": {
    "sha256":      "abc...",
    "content_ref": "git+https://github.com/acme/policies#cc61-v3"
  },
  "precommit": {
    "rekor_log_index":       12345678,
    "rekor_entry_uuid":      "...",
    "rekor_inclusion_proof": "base64...",
    "signed_at":             "2026-04-16T08:30:00.123Z"
  },
  "audit": {
    "merkle_alg":     "rfc6962-sha256",
    "tree_size":      4201,
    "tree_root_hash": "...",
    "counts_by_tool":     {"Bash": 2739, "Read": 891, "Grep": 342, "Edit": 142},
    "counts_by_decision": {"allow": 4151, "warn": 50, "block": 0}
  },
  "anchor": {
    "opentimestamps_proof": "base64..."
  },
  "signer": {
    "alg":    "ed25519",
    "pubkey": "..."
  }
}
```

Every field is **required** in v0.1. No optional fields. Extensions in future versions must increment `spec_version` and publish a new predicate URI.

---

## 5. Canonical tool-event record

Each tool invocation the agent performs produces one event record, appended to the session's `audit.log` file. The record shape:

```json
{
  "seq":          4201,
  "ts":           "2026-04-16T12:34:56.789Z",
  "tool":         "Bash",
  "input_hash":   "sha256:a3f2b1...",
  "input":        { "cmd": "curl https://api.target.com/users/octocat" },
  "destinations": ["api.target.com"],
  "decision":     "allow",
  "reason":       "host_in_scope",
  "policy_ref":   "sha256:abc..."
}
```

Fields:

- `seq` — monotonic unsigned integer, starts at 0 for the session's first event
- `ts` — RFC 3339 with nanosecond precision, UTC
- `tool` — the Claude Code tool name exactly as dispatched by the hook (`Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Agent`, `NotebookEdit`, or `mcp__<server>__<tool>`)
- `input_hash` — SHA-256 of the canonical JSON serialization (per RFC 8785) of the raw tool input
- `input` — present only if `privacy_mode=off`; the raw tool input as JSON
- `destinations` — tool-specific list of extracted destinations (hosts for Bash/WebFetch, paths for Read/Write/Edit, repos for Agent, etc.)
- `decision` — one of `allow`, `warn`, `block`
- `reason` — the matching rule identifier or `"unpoliced"` if no rule applied
- `policy_ref` — SHA-256 of the active `scope.txt` at the moment of the event

---

## 6. Merkle tree construction

The tree follows [RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1) byte-exactly. For n events, the tree is built by hashing each canonical event JSON as a leaf, then folding:

- leaf hash: `SHA-256(0x00 || canonical_event_bytes)`
- internal node hash: `SHA-256(0x01 || left_child_hash || right_child_hash)`

The root hash is written into the predicate as `audit.tree_root_hash`. Inclusion proofs for any individual event and consistency proofs between any two tree sizes are computable by the verifier from the stored leaves.

The Merkle hashing is deliberately byte-exact with Certificate Transparency so that existing CT verifier code can be adapted without modification.

---

## 7. Privacy modes

v0.1 defines two modes, both producing identical envelope structures but differing in how event records are serialized:

| Mode | `input` field | Use case |
|---|---|---|
| `off` | Full raw input stored | Bug bounty submission — triage needs to see exact commands |
| `on` | Omitted; only `input_hash` | Enterprise compliance — commands are proprietary |

The mode is fixed for the duration of a session; switching mid-session produces a broken session. The `privacy_mode` field in the predicate declares which mode was used.

Verifier behavior is identical in both modes: the Merkle tree uses the same canonical form, which includes or omits the `input` field based on the mode. The same verification steps apply.

---

## 8. Verification (6 gates)

`jesses verify FILE.jes` runs the following gates in order. All must pass; any failure aborts verification and returns `FAIL`.

1. **Envelope signature** — the ed25519 signature on the DSSE-wrapped payload verifies against the embedded `signer.pubkey`
2. **Predicate structure** — the decoded payload matches `spec/v0.1/predicate.schema.json`; required fields are present; types are correct
3. **Merkle root** — given the provided audit log, recompute the tree and compare the root hash against `audit.tree_root_hash`
4. **Pre-commit order** — the Rekor inclusion proof for the pre-commitment was issued before the first event's timestamp; the pre-commit's `policy_hash` matches the `SHA-256` of the policy file the verifier holds
5. **OpenTimestamps anchor** — the OTS proof verifies against the Bitcoin chain and establishes an upper bound on `ended_at`
6. **Policy conformance** — every event in the audit log matches the policy at `policy_ref` with the recorded `decision`; policy evaluations are deterministic and re-runnable

The verifier exits `0` on PASS and `1` on FAIL. Output is emitted in two forms:

- **JSON** (`--output json`) for machine integration with H1 / BC / Immunefi intake webhooks
- **Human** (default) for terminal display

---

## 9. Test vectors

`spec/v0.1/test-vectors/` contains golden cases that every conformant verifier implementation must classify correctly:

| File | Expected | Tests |
|---|---|---|
| `valid-tree.json`            | PASS | Baseline — well-formed session with 20 events |
| `valid-precommit.json`       | PASS | Baseline — pre-commit with valid Rekor proof |
| `invalid-tree-edit.json`     | FAIL | A1 — single leaf modified |
| `invalid-consistency.json`   | FAIL | A6 — mid-session checkpoint inconsistent with final tree |
| `invalid-precommit-order.json` | FAIL | A3 — pre-commit timestamp later than first event |

An implementation that accepts any `invalid-*` vector is non-conformant and not entitled to call itself a `jesses` verifier.

---

## 10. Versioning policy

The predicate URI is `https://jesses.dev/v0.1/action-envelope`. Every breaking change to the predicate shape, the canonical event record, the Merkle construction, or the verification gates requires a new URI — `v0.2`, `v1.0`, etc.

Non-breaking additions (new optional fields, additional allowed tool types) MAY extend v0.1 in place, but such additions are discouraged. Prefer a new minor version.

Verifiers MUST reject any predicate whose URI they do not recognize. Forward compatibility is explicitly not a goal.

---

## 11. Reserved / future extensions

- **v0.2** — multi-operator transparency log federation; streaming intermediate tree commitments; HackerOne platform integration SDK
- **v0.3** — TEE attestation on supported platforms (Intel TDX, AWS Nitro Enclaves, Apple Secure Enclave); zero-knowledge compliance proofs (Risc0 or Noir)
- **v0.4** — agent reputation via Ethereum Attestation Service (EAS); cross-session track record
- **v0.5** — post-quantum signature suite

None of these are promises. They are the direction.

---

## 12. Governance

v0.1 is authored by a single implementer with no formal governance structure. Any party adopting `jesses` for production use should understand this and factor it into their trust decisions. A foundation governance model will be evaluated after v0.1 demonstrates real adoption.

Changes to this specification prior to v1.0 do not require external consent.
