# jesses — Threat Model v0.1

## 0. The single premise

**The submitter IS the adversary.**

This is the one property that distinguishes `jesses` from every prior attestation tool. Sigstore assumes a trusted build pipeline (GitHub Actions with OIDC identity). Certificate Transparency assumes trusted Certificate Authorities (licensed legal entities). Software supply-chain signing assumes the signer is not motivated to forge.

`jesses` assumes the opposite. The party who runs the tool has direct financial incentive to forge a clean `.jes` file so their deliverable gets paid. A bounty hunter whose AI agent accidentally touched an out-of-scope host will be tempted to delete that entry before submission. A security consultancy whose autonomous audit touched the wrong S3 bucket will be tempted to rewrite history before handing the client their evidence bundle.

Every defense in this document is evaluated against a single question:

> _Can the person running `jesses` on their own machine, with root access and full source code, produce a `.jes` file that verifies as valid but does not faithfully describe what the agent actually did?_

If the answer is "yes," the defense is insufficient.

---

## 1. Seven attacks, one submitter

These are the realistic attacks. Not hypothetical, not theoretical — the things a real submitter is motivated to try, listed in increasing difficulty for the attacker:

| # | Attack | Attacker motive |
|---|---|---|
| **A1** | Edit a single audit entry | Remove the one `/user/keys` touch that would be flagged as OOS |
| **A2** | Truncate from the end | Hide what happened in the last 30 minutes of the session |
| **A3** | Fabricate the entire log | Claim 100 hours of testing that never happened |
| **A4** | Swap the policy file post-hoc | Retroactively widen scope to legitimize past OOS touches |
| **A5** | Back-date the session | Claim a violation pre-dates a regulatory deadline |
| **A6** | Selective mid-log deletion | Remove the one failed scan attempt that reveals the real finding chain |
| **A7** | Interleave real + fake entries | Pad a real session with fabricated tool uses to inflate effort billing |

Each must be **mathematically defeated** — not "detectable with effort" or "discouraged by policy." Detection must be a trivial deterministic check inside `jesses verify`.

---

## 2. Defense matrix

Each attack maps to one or more defenses, all of which are v0.1 requirements.

| Attack | Primary defense | Mechanism | Residual risk (v0.1) |
|---|---|---|---|
| A1 edit entry | Merkle tree (RFC 6962) | Each leaf hash participates in the tree root; changing any byte of a leaf invalidates all sibling hashes on the path to the root | None. Deterministic. |
| A2 truncate end | OpenTimestamps anchor on session-end root | The final tree root + tree_size are anchored to Bitcoin; after the anchor, the tree cannot grow or shrink without producing a different anchor | None. |
| A3 fabricate entire log | **Session-start pre-commitment (SCT analog)** | Before the first tool event, `jesses session start` publishes `{session_id, ts, policy_hash, pubkey}` to Rekor. The Rekor inclusion proof's timestamp must be earlier than the first event's timestamp. A fabricated session cannot retroactively produce a Rekor inclusion proof in the past. | None — provided Rekor's own integrity holds. |
| A4 swap policy | `policy_sha256` inside the pre-commitment | The pre-commit blob includes the policy hash. The verifier requires the submitter to hand over the exact policy whose hash matches. Any divergent policy rejects verification. | None. |
| A5 back-date session | OpenTimestamps at session-end **and** at session-start (Rekor inclusion proof from A3) | Two-sided time pinning. The lower bound (Rekor) cannot be pushed forward; the upper bound (OTS) cannot be pushed back. | None. |
| A6 selective deletion | Merkle tree consistency proof | A mid-session monitor can checkpoint the tree state. Any later tree must be provably an append-only extension of the checkpointed state, otherwise consistency proof fails | Requires a monitor to actually take mid-session checkpoints. v0.1 ships the primitive; monitors exist in v0.2+. |
| A7 interleave fakes | **Streaming commitment** + adversarial economics (v0.1); TEE attestation (v0.3) | v0.1 relies on: (a) timestamp monotonicity inside the tree, (b) wall-clock consistency with Rekor and OTS anchors, (c) the economic argument below. v0.3 closes this fully via TEE. | **This is the single residual v0.1 gap.** See §4. |

---

## 3. The pre-commitment is the single most important mechanism

The principle CT leans on, paraphrased: *CT's security is not "public logs." It's the Signed Certificate Timestamp — a promise the log makes before inclusion, redeemable later. Without a pre-commitment, a submitter can fabricate the entire session log post-hoc and submit it. The SCT pattern is what makes fabrication detectable, not merely prohibited.*

`jesses` v0.1 ships this pattern as a hard requirement. The pre-commitment is emitted at `jesses session start` and contains:

```
{
  "session_id":  "01HQ8A7X...",
  "ts":          "2026-04-16T08:30:00.123Z",
  "policy_hash": "sha256:abc...",
  "pubkey":      "ed25519:0xFACE..."
}
```

This blob is signed (ed25519) and published to Rekor immediately. Rekor's inclusion proof is stored alongside the session. At `jesses verify` time, the verifier requires:

1. the pre-commitment's Rekor inclusion proof is valid
2. the Rekor log index places the proof before the first event's `ts` in the audit log
3. the policy hash in the pre-commit matches the hash of the policy file the submitter is handing to the verifier
4. the pubkey in the pre-commit matches the pubkey that signed the final `.jes` bundle

All four must pass. Any single failure rejects verification. Together they close A3, A4, A5, and half of A7.

---

## 4. The v0.1 residual gap — A7 interleave

The one attack that is not _mathematically_ closed in v0.1 is A7: the attacker records real events plus fake events, in real-time order, during the session. The hash chain is consistent, the timestamps are monotonic, the pre-commit and OTS anchors are valid. Only the _content_ of some events is fabricated.

v0.1 defends against this with **adversarial economics**, not cryptography. The argument:

> _Fabricating a convincing fake session costs more than doing the work honestly._

Concretely: to pass `jesses verify` with interleaved fakes, the attacker must produce:

- a hash-chained audit log with hundreds to thousands of real entries
- real wall-clock timestamps spanning the claimed session duration (no compressing 8 hours of work into 5 minutes)
- inputs that match real tool-output shapes (a fake `Read` of a file that does not exist on disk is a weak forgery)
- destinations that match what a real agent would produce under the stated prompt
- a session that is internally consistent with the claimed deliverable

For most bounty scenarios, the cost of fabricating all of this in a way that survives human review by a triage team exceeds the cost of simply running the agent honestly. For the subset of cases where the expected bounty is large enough to justify the forgery effort, v0.1 is insufficient and the submitter should not rely on `jesses` as their sole trust anchor.

**v0.3 closes A7 mathematically** via TEE attestation (Intel TDX, AWS Nitro Enclaves, Apple Secure Enclave): the signing environment produces an attestation quote proving the running binary is the published open-source `jesses` release, not a modified fork that writes fake entries. Once TEE lands, the attacker cannot inject fakes without compromising hardware root of trust.

Users who require A7-level guarantees in 2026 should wait for v0.3. v0.1 is honest about this.

---

## 5. Out of scope (v0.1)

Threats explicitly not addressed:

- **Local privilege escalation on the submitter's machine** — if the attacker has root on their own machine, they can do whatever they want to their own filesystem; jesses only claims to produce artifacts that are verifiable across parties
- **Physical attacks on the signing device** — v0.1 software keys are extractable; v0.3 TEE attestation addresses this
- **Attacks on Rekor itself** — jesses inherits Rekor's trust assumptions; if Rekor is compromised, jesses's pre-commit integrity degrades
- **Attacks on Bitcoin** — jesses inherits OpenTimestamps's assumptions; if Bitcoin is compromised at the consensus layer, all bets are off
- **Side-channel leakage of raw commands** — in `privacy=off` mode, commands are in the log; readers of the log can see proprietary data. `privacy=on` mode is the mitigation.
- **Supply chain attacks on jesses itself** — addressed by signed releases (cosign) and reproducible builds, not by the threat model of individual sessions

---

## 6. Non-threats (paranoia we rejected)

Things a paranoid reader might demand, and why v0.1 does not address them:

- **"What if the attacker replaces `jesses` with a modified binary on their own machine?"** → v0.1 uses adversarial economics. v0.3 uses TEE attestation. Either way, there is no purely-software answer on a machine you do not control.
- **"What if two colluding submitters share a key?"** → Keys are not identities; the trust model is about each individual session's internal consistency, not about who holds which key.
- **"What if the receiver of the `.jes` is compromised?"** → Out of scope. jesses produces an artifact; what the receiver does with it is their responsibility. The artifact is verifiable by any third party.
- **"What if a quantum computer breaks ed25519 in 2035?"** → Out of scope for v0.1. Post-quantum signature schemes will be a v0.5+ consideration when the standards settle.

---

## 7. Test vectors for the threat model

Each attack maps to a test vector in `spec/v0.1/test-vectors/`:

| Test vector | Attack | Expected result |
|---|---|---|
| `valid-tree.json` | — (control) | `jesses verify` → PASS |
| `valid-precommit.json` | — (control) | `jesses verify` → PASS |
| `invalid-tree-edit.json` | A1 | `jesses verify` → FAIL (merkle root mismatch) |
| `invalid-consistency.json` | A6 | `jesses verify` → FAIL (consistency proof fails) |
| `invalid-precommit-order.json` | A3 | `jesses verify` → FAIL (pre-commit timestamp after first event) |

Other-language verifier implementations must reproduce all five classifications. A verifier that accepts any invalid vector is non-conformant and not `jesses`-compatible.

---

## 8. What a hostile review should ask

Reviewers of this threat model are invited to answer:

1. Is there an 8th attack we haven't listed that a motivated submitter would try?
2. Is the adversarial-economics defense for A7 honest enough to ship, or is v0.1 fundamentally broken without TEE from day one?
3. Is Rekor the right transparency log, or should v0.1 operate its own from the start?
4. Are OTS-only anchors sufficient, or does v0.1 need a second independent timestamp service (Google Trusted Time, Certificate Transparency SCT)?

Answers to these questions should be proposed as PRs against this document, with the corresponding test vector added to `spec/v0.1/test-vectors/`.
