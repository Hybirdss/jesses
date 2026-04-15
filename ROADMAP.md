# jesses — 90-day roadmap

_Authored 2026-04-16. Covers Day 0 (scaffold) through Day 90 (foundation + v0.2 branch)._

This document is the strategic companion to `ARCHITECTURE.md`. Where ARCHITECTURE explains _what_ is built, ROADMAP explains _when_ and _why_, and locks in the political / adoption decisions that separate a working tool from a widely-used standard.

---

## Strategic bet — committed

**Bet C: Platform-first, via Immunefi.**

Three strategic paths were considered:

| Bet | Target | Horizon | Why rejected |
|---|---|---|---|
| A — Regulator-first | EU AI Act Article 12 / ENISA | 12–18 months | Too slow for a 4-month window; high prestige but low near-term adoption |
| B — Hunter-first | Top 10 bounty hunters | 3–6 months | High noise-to-signal; doesn't compel platforms to integrate |
| **C — Platform-first** | **Immunefi integration** | **6–9 months** | **Needs only one "yes"; Immunefi is the softest target (crypto-native, small team, already hurting from AI-submission validity problems); one reference integration unlocks copies** |

Rationale: the central insight from Ben Laurie (Certificate Transparency) is that standards become standards when a platform _enforces_ them. CT succeeded because Chrome made log inclusion mandatory. `jesses` needs the same lever. Chasing regulators (Bet A) is orthogonal to whether the thing gets used day-to-day. Chasing hunters (Bet B) amplifies but does not compel. Chasing a platform directly is the shortest path to forced adoption.

Immunefi is the chosen platform because:

1. Crypto-native — comfortable with cryptographic attestation as a primitive
2. Smaller engineering team than HackerOne — faster integration decisions
3. Currently suffering from AI-assisted submission quality crisis (Lido-scale programs flooded with low-quality reports) — `jesses` directly addresses their pain
4. Single integration = reference story other platforms copy

Bet B (hunter cohort) runs in parallel as a _secondary_ channel — top 10 hunters receive personal outreach in Week 5, but no deep investment. Bet A (regulator) is a _tertiary_ channel — one formal ENISA submission in Week 8, no ongoing engagement.

---

## Locked decisions from direction meeting

Integrated voices: Katie Moussouris (security standards politics), Patrick Collison (developer experience compounding), Solomon Hykes (primitive-vs-product discipline).

| # | Decision | Source |
|---|---|---|
| 1 | **Primitive forever, never a product**. Pre-commitment in README and this document. | Hykes — Docker Inc.'s monetization of Docker Hub was the single mistake that created the 2015 fork; `jesses` pre-empts this before launch |
| 2 | **Neutral foundation governance pre-committed** before v1.0, drafted in Week 11 of this roadmap | Hykes — post-hoc governance is always late; Moussouris — community trust requires visible neutrality |
| 3 | **Developer experience is table stakes**. `curl \| sh` install must produce a working `.jes` in <10 seconds. | Collison — Stripe's advantage was never better technology; it was shorter distance from intent to effect |
| 4 | **Three audience-specific docs landing pages**: hunter, program operator, compliance officer. Zero security jargon on each. | Collison — one README cannot serve three buyers |
| 5 | **80% of v0.1 engineering effort on the verifier**, not the hook | Collison — the verifier is what determines whether a `.jes` is accepted or rejected; it must be boring, deterministic, well-tested |
| 6 | **Second language verifier (TypeScript) commissioned during v0.1 development**, ships within 2 weeks of v0.1 | Hykes — two independent implementations is the signal that a project is a standard, not one person's tool |
| 7 | **Hunter cohort outreach is personal, not broadcast** | Moussouris — the CVD community was built on relationships; broadcast launches die |
| 8 | **Do not compete with platforms or regulators** — position as an amplifier of their existing trust mechanisms | Moussouris — the single highest-return move for a new security standard is becoming "the thing regulators reference" |
| 9 | **No dashboard, no hosted service, no SaaS component in v0.1** | Hykes — every such addition is a step toward product and away from primitive |

---

## The 90-day plan

### Week 1–4 (Days 1–30): build v0.1

Per `ARCHITECTURE.md §8`:

| Days | Deliverable | Pass criterion |
|---|---|---|
| 1–7 | `internal/merkle` RFC 6962 byte-exact + `internal/audit` canonical writer | All RFC 6962 test vectors pass; concurrent append fuzz test green |
| 8–14 | `internal/policy` 4-namespace parser + `internal/hook` dispatcher + 9 tool extractors | Per-tool unit tests green; extractor coverage matches SPEC.md §5 |
| 15–21 | `internal/session` + `internal/precommit` + `internal/rekor` client | Rekor testnet: publish pre-commit, fetch inclusion proof, round-trip verification |
| 22–28 | `internal/ots` + `internal/attest` + `internal/verify` six-gate orchestrator + `cmd/jesses` CLI + `examples/claude-code/` install script | End-to-end: real Claude Code session → `.jes` → `jesses verify` PASS; `cosign verify-blob` accepts envelope |
| 29–30 | **Docs week** — three audience pages, GoReleaser + cosign signed release, self-dogfood `.jes` alongside binary | Released binary passes its own `jesses verify` on its own `.jes` |

**Day 30 deliverable**: `github.com/yunsu/jesses` v0.1.0 tagged, signed, released. Public but unannounced.

### Week 5–8 (Days 31–60): first-user cohort + second verifier

**Week 5 — cohort activation**
- Day 31–33: personal email to 10 top bounty hunters (Rhynorater, NahamSec, InsiderPhD, and 7 others). Content: "I'm testing a new attestation standard for AI-assisted submissions. Here's a signed binary, here's a 1-page guide, here's my phone number. No pressure — just curious if you'd attach a `.jes` to your next submission and tell me what the triage team says."
- Day 31–33: personal contact with Immunefi trust team, HackerOne trust team, Bugcrowd trust team. **Specifically not asking for a mandate.** Asking one question: "What's the technical integration surface that would let your platform verify `.jes` attachments on intake?" This is intake engineering, not standards lobbying.
- Day 34–35: Immunefi deep dive. Aim for a specific engineer, not a product manager. Crypto engagement matters.

**Week 6 — second verifier commissioned**
- Day 36–42: commission TypeScript verifier implementation. Budget $5K–10K. Scope: spec-conformant reference implementation passing all test vectors in `spec/v0.1/test-vectors/`. Deliverable: `@jesses/verify` npm package. Commissioning party: a small security-focused consultancy (Trail of Bits, Security Innovation, Code Shield, etc.) or a known independent.
- Why TypeScript: platform intake webhooks at H1/BC/Immunefi are JS-heavy; TypeScript is the adoption-friendliest second language.

**Week 7 — public launch**
- Day 43–49: "Show HN: jesses, a tamper-evident attestation standard for AI-authored security deliverables." Title tested with a trusted first reader. Pre-reviewed by Filippo Valsorda if contact possible.
- Day 43–49: Simon Willison blog cross-post pre-arranged. His audience is the AI-agent-safety crowd `jesses` targets.
- Day 43–49: `/r/LocalLLaMA` cross-post, `lobste.rs` post, focused Mastodon thread (no broadcast spam).

**Week 8 — regulatory submission**
- Day 50–56: formal submission to ENISA as a reference implementation for Article 12 machine-readable AI disclosure in security-deliverable contexts. Submission is via ENISA's AI Act stakeholder channels.
- Intent: create a paper trail, not spend ongoing effort. The submission establishes `jesses` as "an available reference" even if no immediate regulatory action follows.

### Week 9–12 (Days 61–90): governance + infrastructure

**Week 9–10 — TypeScript verifier ships**
- Day 57–70: commissioned TypeScript implementation lands. Merged into `jesses.dev/verify-ts` as v0.1.0. All 5 test vectors pass. npm publish.
- **Moment of becoming a standard**: two independent verifiers, both passing the same golden tests. The project is no longer "one person's tool."

**Week 11 — foundation governance**
- Day 71–77: **jesses Foundation** publicly announced.
  - 3 board seats:
    - 1 × maintainer
    - 1 × bounty hunter community representative (nomination from Week 5 cohort)
    - 1 × program operator (HackerOne or Immunefi, whichever accepts first)
  - Bylaws: primitive-only mandate, no monetization, no competitive services, MIT license is irrevocable.
  - Legal vehicle: Delaware nonprofit or Swiss foundation, TBD in Week 11.

**Week 12 — v0.2 roadmap + dev branch**
- Day 78–84: v0.2 scope published.
- Day 85–90: v0.2 branch opens. Initial work: streaming intermediate tree commitments (lays groundwork for multi-operator federation).

### Day 90 (2026-07-16) — success criteria

`jesses` is on track to become a standard **if and only if** all five of these hold at Day 90:

1. ☐ Referenced in at least one EU regulatory implementing-guidance draft (ENISA, national CERT, or equivalent)
2. ☐ Minimum of 10 voluntary `.jes` attachments on public bounty platforms, authored by real hunters
3. ☐ Second-language verifier (TypeScript) in production use by at least one platform or consultancy
4. ☐ jesses Foundation governance structure committed and pre-launch bylaws published
5. ☐ v0.2 dev branch has working streaming intermediate commitments

Miss any one → re-evaluate the strategic bet. Miss two or more → pivot or sunset.

---

## What this roadmap explicitly does NOT include

- No blockchain work beyond OpenTimestamps + Rekor (locked decision)
- No ZK proofs, no EAS, no on-chain reputation, no smart contracts (v0.3+)
- No TEE attestation (v0.3 — adversarial-economics defense covers v0.1/v0.2)
- No monetization, no pricing page, no free-tier/paid split (never)
- No hosted service, no dashboard SaaS, no cloud offering (Hykes rule)
- No competition with HackerOne / Immunefi / Bugcrowd as platforms (Moussouris rule)
- No third or fourth language verifier until after v0.2 (focus)
- No attempt to "enter" the C2PA standard (adjacent, different problem space)

---

## Risks & contingencies

| Risk | Probability | Mitigation |
|---|---|---|
| Anthropic / OpenAI ships in-house attestation for their agent SDKs | Medium | Get `jesses` adopted by them first; offer free support; make it better than in-house alternative |
| Immunefi passes on integration | Medium | Fall back to Bugcrowd as second-choice platform; HackerOne as third (larger but slower) |
| Rekor outage during live session | Low | Document graceful degradation; session continues with local log; Rekor publish retries on next run |
| OpenTimestamps service outage | Low | Multiple public OTS calendar servers; client fails over automatically |
| EU AI Act Article 12 enforcement delayed | Medium | Bet C doesn't depend on regulatory timing — platform-first is independent |
| TypeScript verifier commission produces non-conformant impl | Low | Test vectors are the contract; payment conditional on passing all vectors |
| Maintainer bandwidth exhaustion | High | Foundation governance in Week 11 is designed to distribute load; no single-maintainer sustainability at v1.0 |

---

## What the maintainer will say no to

Non-exhaustive list of requests that will be refused, in advance, to save everyone time:

- "Can you add a cloud dashboard?" → No. See Hykes rule.
- "Can we pay you for priority support?" → No for the primitive. Enterprise services belong to a separate entity.
- "Can we add a commercial license tier?" → No. MIT is irrevocable.
- "Can we strip the pre-commitment to reduce latency?" → No. Pre-commitment is mandatory per THREAT_MODEL.md §3.
- "Can we make the verifier skip checks for performance?" → No. All 6 gates must pass.
- "Can we use a different transparency log?" → Yes, but it must be Rekor-compatible and v0.2+.
- "Can we support a different hash function?" → No in v0.1. SHA-256 is the RFC 6962 baseline. Post-quantum is v0.5+.
- "Can you maintain a hosted Rekor mirror?" → No. The foundation may operate one; the maintainer alone will not.

The discipline of saying no is what lets the primitive stay small enough to become a standard.
