# 2026 Q1 — Intigriti code of conduct update

## Source

- **Original**: [kb.intigriti.com/en/articles/5247238-community-code-of-conduct](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct)
- **Intigriti AI policy context**: [Bug Bytes #234 (March 2026)](https://www.intigriti.com/researchers/blog/bug-bytes/intigriti-bug-bytes-234-march-2026)
- **Intigriti platform overview**: [intigriti.com](https://www.intigriti.com)

## Summary (our words)

Intigriti updated its community code of conduct in Q1 2026 to explicitly address AI-assisted submissions. The policy permits AI use "when used responsibly as a force multiplier for learning, analysis, and improving report quality" but draws a hard line against certain failure modes:

- Submitting unvalidated proofs of concept
- Including hallucinated payloads
- Generic responses to feedback requests

Most significantly, Intigriti commits to a procedural consequence: reports that "appear to be unverified AI output, contain fabricated elements, or demonstrate a lack of technical understanding may be closed without response, subject to longer validation times, and could lead to removal from the platform."

"Closed without response" is a meaningful escalation. Most platform AI policies at the time offered the researcher at least one round of feedback before closure; Intigriti's language removes that feedback loop for reports flagged as likely AI-slop.

## Key excerpts (fair-use)

> *"the use of AI tools is permitted and encouraged when used responsibly as a force multiplier for learning, analysis, and improving report quality"*

> *"reports that appear to be unverified AI output, contain fabricated elements, or demonstrate a lack of technical understanding may be closed without response, subject to longer validation times, and could lead to removal from the platform"*

## How this supports jesses's thesis

- **Hardest policy of the three platforms**. HackerOne says "not accepted." Bugcrowd says "discouraged and detected." Intigriti says "closed without response and potentially removed from platform." This makes Intigriti's policy the one that creates the strongest **researcher demand** for a pre-emptive verification mechanism, because the consequence to the researcher is most severe.
- **Founder-led, researcher-friendly**. Inti De Ceukelaire (Chief Hacker) is publicly accessible and historically engages with community tooling proposals. This makes Intigriti the highest-likelihood first-platform-conversation target.
- **"Closed without response" asymmetry creates a market for signaling**. A researcher who has spent hours on a real finding has a massive incentive to demonstrate legitimacy up front, rather than submit and pray. `.jes` is that demonstration.

## Researcher-side pain point

The Intigriti policy puts legitimate researchers using AI assistance (which is almost all of them, productively, in 2026) in an asymmetric-risk position:

- Upside: finding is real, gets paid, standard outcome.
- Downside: finding is real but *looks* AI-slop to a triager — gets closed without feedback, reputation damage, potential removal from platform.

This asymmetry is the strongest researcher-side wedge for jesses: "attach this file and you move from the AI-default-suspicious bucket to the verifiable-default-trusted bucket." Researchers who've been on the receiving end of a legitimate-report-closed-as-slop incident are most ready to adopt.

## Outreach implication

Researcher outreach ([`docs/yc/outreach/researchers-dm.md`](../yc/outreach/researchers-dm.md)) should explicitly reference the Intigriti policy asymmetry for researchers who are active on Intigriti. The message resonates: "your legitimate submission got closed without response — here's the format that would have prevented that."

## What would weaken this evidence

- If Intigriti publishes a public follow-up softening the "closed without response" language due to researcher pushback, the asymmetry weakens.
- If an independent study shows the closed-without-response rate is low in practice (e.g., <2% of all submissions), the pain is more theoretical than felt.

## Archive status

- Intigriti's KB articles are living documents; they are more likely than blog posts to be edited in place. Archive this one via Wayback on a shorter cadence (monthly) until the YC pilot or v0.2 lands.
