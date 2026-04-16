# 2026-02-18 — HackerOne updates AI policy

## Source

- **Original reporting**: [theregister.com/2026/02/18/hackerone_ai_policy/](https://www.theregister.com/2026/02/18/hackerone_ai_policy/)
- **Related HackerOne material**: [HackerOne Hai docs](https://docs.hackerone.com/en/articles/8887510-hai-ai-security-agent), [Beyond the Noise blog](https://www.hackerone.com/blog/beyond-the-noise-hai-triage-insight-agent), [AI + Human Validation](https://www.hackerone.com/blog/ai-triage-code-validation-security)
- **Adjacent coverage**: [Dark Reading on the pause](https://www.darkreading.com/application-security/ai-led-remediation-crisis-prompts-hackerone-pause-bug-bounties), [TechTarget on triage critique](https://www.techtarget.com/searchsecurity/news/252526562/Researchers-criticize-HackerOne-over-triage-mediation-woes)

## Summary (our words)

HackerOne updated its platform AI policy on 2026-02-18 following sustained researcher complaints that earlier wording was ambiguous about what constituted acceptable AI-assisted submissions. The revised policy states that "automated or unverified outputs are not accepted" as valid submissions.

Contextually, this lands alongside HackerOne's expansion of the "Hai" AI triage agent, which applies AI-based filtering to reports on the platform side. HackerOne has publicly cited 210% growth in valid AI-assisted vulnerability reports year-over-year while simultaneously reporting that the valid-submission rate fell from approximately 15% to below 5% as AI-generated low-effort reports surged.

The policy update is significant because it creates a **rule with no enforcement mechanism**: "unverified" is not defined, so triagers must decide case-by-case, and submitters have no file-level way to pre-demonstrate verification.

## Key excerpts (fair-use, short quotation)

> *"automated or unverified outputs are not accepted"* — HackerOne policy update language, quoted via The Register.

> *"We are evolving our AI capabilities to help researchers bring value faster and to ensure our team triages them with higher speed and accuracy"* — HackerOne spokesperson.

HackerOne's own published metrics, as of the 2026 update cycle:
- Valid AI-assisted vulnerability reports: up 210% YoY.
- Valid-submission rate (any category): ~15% → <5%.

## How this supports jesses's thesis

- **Policy written; enforcement mechanism absent.** This is the exact gap jesses fills: the verifier-side mechanism that lets a platform enforce the policy without taking a case-by-case labor hit.
- **Platform admission that the problem is structural.** HackerOne is not claiming the problem is solvable by better intake moderation alone; they are simultaneously investing in AI-triage tooling (Hai). A third-party-verifiable file format is complementary to Hai, not competitive — Hai can score `.jes`-bearing submissions differently.
- **Quantitative support for Wedge B (consultancies).** If valid-submission rate dropped from 15% to 5%, the triage labor per valid report tripled. Consultancies billing hourly on AI audits feel the same pressure at their clients' side.

## The HackerOne-specific nuance

HackerOne occupies an awkward position: they are simultaneously the platform that most needs jesses (largest volume, highest slop pressure) *and* the platform most likely to build a walled-garden alternative inside Hai (largest in-house AI team, most capital). This informs the outreach sequencing in [`docs/yc/outreach/platforms.md`](../yc/outreach/platforms.md) — HackerOne is approached via community, not exec, to avoid triggering a "build internally" reaction before the open spec has adoption elsewhere.

## What would weaken this evidence

- If HackerOne's next quarterly report shows valid-submission rate recovering above 10% without any new format requirement, this implies internal tooling alone was sufficient.
- If HackerOne publicly open-sources a competing attestation format before jesses has outside adopters, the window closes faster than the YC distribution thesis can operate.
- If the 2026-02-18 policy is quietly walked back after researcher pushback (as has happened with prior HackerOne AI policies, per TechTarget coverage), the policy-layer signal softens.

## Archive status

- Wayback: save against The Register URL quarterly.
- HackerOne's own blog posts are more permanent than the news coverage; use those as cross-reference.
