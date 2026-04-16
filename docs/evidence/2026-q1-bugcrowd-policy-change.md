# 2026 Q1 — Bugcrowd policy changes re: AI slop submissions

## Source

- **Original**: [bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/)
- **Author**: Bugcrowd policy team (byline to be confirmed on the live page)
- **Adjacent**: [CybernNews coverage](https://cybernews.com/ai-news/ai-break-bug-bounty-programs/), [AI CERTs News](https://www.aicerts.ai/news/curl-ends-bounty-citing-ai-generated-slop-surge/), [Penligent.ai state-of-bug-bounty](https://www.penligent.ai/hackinglabs/how-to-use-ai-for-bug-bounty-in-2026/)

## Summary (our words)

Bugcrowd published updated submission policies, rate controls, and automated-detection mechanisms during Q1 2026, framed as prioritizing "validated research and high-signal findings" while discouraging "speculative and automated spam." The language used — "automated or unverified outputs are not accepted" — mirrors HackerOne's 2026-02-18 update, suggesting either an industry conversation converging on common phrasing, or independent parallel drafting driven by the same pressure.

The policy has three operational components:
1. **Submission policy changes** — updated rules of engagement for researchers using AI assistance.
2. **Rate controls** — technical throttling on submission volume from individual accounts.
3. **Detection mechanisms** — platform-side ML or heuristic flagging of likely AI-slop submissions.

As with HackerOne, the policy does not define "verified" in a cryptographic, file-level, third-party-replicable sense. The detection mechanisms are Bugcrowd-internal and non-auditable by researchers or by other platforms.

## Key excerpts (fair-use)

> *"automated or unverified outputs are not accepted as valid submissions"* — Bugcrowd policy language.

> *"prioritize validated research and high-signal findings while discouraging speculative and automated spam"* — Bugcrowd blog framing.

## How this supports jesses's thesis

- **Cross-platform convergence** — having three platforms (HackerOne, Bugcrowd, Intigriti) land similar language in an 8-week window is evidence that the pressure is category-wide, not a single-platform PR moment. A file format that becomes a lingua franca across platforms has clear standing.
- **Rate controls + detection mechanisms are the platform's internal patch.** They reduce the fire but don't close it. A researcher with a legitimate finding still cannot pre-prove legitimacy; they get caught in the same filter as the slop. jesses inverts this: a positive, cryptographic proof of legitimacy that jumps the submission above detection noise.
- **Useful wedge for jesses**: platforms will publicly struggle with false positives from their own detection mechanisms. Every false-positive incident creates a moment where "why not a standardized verified-submission format that the researcher controls?" is the natural next question.

## How to read Bugcrowd specifically

Bugcrowd is founder-led (Casey Ellis retains public profile) and historically more researcher-friendly than HackerOne on policy issues. This makes Bugcrowd the **most likely first platform partner** — the community is more responsive, the decision cycle is tighter, and Ellis personally engages with OSS tooling more than HackerOne's comms team does.

Outreach path: see [`docs/yc/outreach/platforms.md`](../yc/outreach/platforms.md). Casey Ellis on X is the single best entry point.

## What would weaken this evidence

- If Bugcrowd quietly rolls back the policy after volume subsides, this becomes a point-in-time reaction rather than a structural change.
- If the detection mechanisms turn out to be effective enough (false-positive rate acceptably low), the "platform's internal patch works" counter-narrative gains ground and jesses's value proposition weakens.

## Archive status

- Bugcrowd blog posts are generally durable; no urgent archiving need. Wayback quarterly as part of routine.
