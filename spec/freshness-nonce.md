# jesses v0.1.1 — Freshness Nonce Protocol

Status: **draft**. Normative once a platform integration ships. Reference section only until then.

## Problem

Even with G7 (deliverable provenance binding), the v0.1 attestation cannot rule out "theater mode with prepared script": an attacker who built a bounty harness offline, recorded it, then runs jesses at submission time with a replay of a prepared timeline. Every cited event appears in the session; every hash matches; nothing catches the fact that the session was _prepared in advance_.

The Freshness Nonce closes this by requiring the session to include a **platform-signed random value** that the attacker cannot possess until the platform chooses to issue it. A prepared-in-advance session has no way to embed the nonce — so platforms can reject sessions that don't carry one.

This is the Certificate Transparency SCT pattern at a second layer: the session already commits to Rekor at start-time, but Rekor's precommit only proves "this session's declaration predates the submission." It does not prove "the session's declaration is bound to a specific platform's live authorization." Freshness Nonce adds that binding.

## Roles

- **Platform** — the bounty program operator (Immunefi, HackerOne, Bugcrowd, a B2B audit firm). The platform is the trust anchor whose signing key is pinned by the verifier.
- **Hunter** — runs a jesses-wrapped agent session against the platform's program.
- **Verifier** — a triage analyst, automated CI pipeline, or compliance reviewer who checks the submitted `.jes`.

## Protocol

### Step 1 — Platform issues a nonce

When a hunter opens a session intent on submitting to program `P`, the platform issues a nonce:

```json
{
  "program_id": "visma-bounty-2026",
  "hunter_id":  "h3dgehog@example.com",
  "issued_at":  "2026-04-16T12:34:56Z",
  "expires_at": "2026-04-16T14:34:56Z",
  "random":     "e8c04b29f7d34e10a91f1a6e5cb44c22",
  "platform_kid": "immunefi-2026-prod",
  "platform_sig": "<base64 ed25519 signature over the above fields in canonical JSON order>"
}
```

The platform's ed25519 public key is published at a well-known location the verifier trusts. The canonical JSON body uses the same rules as the rest of jesses (alphabetical map keys, fixed field order, Go encoding/json compatible).

### Step 2 — Hunter includes the nonce in session start

`jesses hook --platform-nonce <path/to/nonce.json>` or `jesses run --platform-nonce ...`. The nonce is inlined into the precommit body that jesses publishes to Rekor at session open:

```json
{
  "session_id":     "...",
  "scope_hash":     "...",
  "pub_key":        "...",
  "timestamp":      "2026-04-16T12:35:02.391Z",
  "version":        "v0.1",
  "platform_nonce": { …the platform-issued nonce… }
}
```

Because the precommit body is what Rekor signs, any modification to the nonce after Rekor acceptance invalidates G3.

### Step 3 — Verifier checks Platform Freshness (G8)

Gate G8 runs if and only if the envelope's precommit carries a `platform_nonce`:

1. Verify `platform_sig` with the pinned platform public key
2. Verify `issued_at <= precommit.timestamp <= expires_at`
3. Verify the precommit body (the hash Rekor signed) matches the embedded nonce byte-exactly
4. Verify `program_id` matches the program the submission claims to target

All four pass → G8 pass. Any failure → G8 fail, **mandatory**.

For sessions without a `platform_nonce`, G8 is advisory with detail "platform freshness not declared." Platforms that want to REQUIRE freshness publish their policy: "we accept only attestations where G8 is mandatory-pass."

## Why this closes theater-with-prepared-script

The attacker must either:

1. Present a fresh platform nonce — only available by talking to the platform in the hunter's name, which gives the platform an audit log of the nonce request
2. Forge the platform signature — requires the platform's private key
3. Skip the nonce entirely — platform rejects the submission

None of these are compatible with "prepared in advance, replayed at submission time."

## What this does NOT close

- **Pre-nonce evil actions.** The hunter can still do evil work before requesting the nonce. The nonce binds the session's START to a platform instant, but not the hunter's workstation state at that instant.
- **Hunter-platform collusion.** If the platform's signing key is leaked, the defense collapses. Mitigated by platform-side HSM and key rotation.
- **Memory-resident agent knowledge.** An agent that has cached an outside-session finding in its parameters can still output it in the bound session. v0.3 TEE memory-statelessness addresses this.

## Precommit predicate extension

The precommit schema adds one optional field:

```go
type Receipt struct {
    SessionID string `json:"session_id"`
    ScopeHash string `json:"scope_hash"`
    PubKey    string `json:"pub_key"`
    Timestamp string `json:"timestamp"`
    Version   string `json:"version"`

    // Optional: platform-issued freshness nonce. Present when the
    // session was initiated in response to a platform nonce grant;
    // otherwise omitted for backward compatibility with v0.1
    // attestations that had no platform integration.
    PlatformNonce *PlatformNonce `json:"platform_nonce,omitempty"`

    LogEntry rekor.Entry `json:"log_entry,omitempty"`
}

type PlatformNonce struct {
    ProgramID    string `json:"program_id"`
    HunterID     string `json:"hunter_id"`
    IssuedAt     string `json:"issued_at"`
    ExpiresAt    string `json:"expires_at"`
    Random       string `json:"random"`
    PlatformKID  string `json:"platform_kid"`
    PlatformSig  string `json:"platform_sig"`
}
```

The `omitempty` means existing v0.1 test vectors remain byte-identical when the field is absent.

## Reference implementation plan (v0.1.1)

- `internal/precommit/` gains the `PlatformNonce` type + canonical-bytes handling (field included in the signed body when present)
- `internal/session/` gains `Config.PlatformNonce` + passes it through to `precommit.Compute`
- `internal/verify/` gains gate G8 as described above
- `cmd/jesses/` adds `--platform-nonce <path>` to `hook` and `run`
- `verifier-js/` ports G8 behavior for cross-implementation conformance
- `spec/test-vectors/v0.1.1/` corpus adds vectors with nonce and without

## Implementation is stubbed but not wired

Shipping the implementation requires a live platform to issue nonces. Without a platform partner, the protocol is spec-only. The stub code lives behind the `nonce` build tag so v0.1 binaries do not carry unused code paths.

## Platform-facing contract

A platform that wants to integrate with jesses publishes:

1. A stable ed25519 public key at `https://<platform>.example/.well-known/jesses-platform-key.json`
2. A nonce-issuing endpoint conforming to the schema above
3. A submission policy stating which gates must pass (minimum: G1-G5 mandatory; recommended: G7 mandatory for reports, G8 mandatory for platform-issued nonces)

The platform operator is the only entity that can set G8 to mandatory for submissions accepted under their brand. jesses itself stays platform-neutral.
