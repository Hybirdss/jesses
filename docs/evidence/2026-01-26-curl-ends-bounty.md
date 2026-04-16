# 2026-01-26 — curl ends HackerOne bug bounty

## Source

- **Original**: [daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)
- **Author**: Daniel Stenberg (curl founder and lead maintainer)
- **Venue**: personal blog
- **Also covered**: [BleepingComputer](https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/), [The Register (2026-01-21)](https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/), [The New Stack](https://thenewstack.io/drowning-in-ai-slop-reports-curl-ends-bug-bounties/), [Hackaday](https://hackaday.com/2026/01/26/the-curl-project-drops-bug-bounties-due-to-ai-slop/), [itsfoss.com](https://itsfoss.com/news/curl-closes-bug-bounty-program/), [HN discussion](https://news.ycombinator.com/item?id=46678710)

## Summary (our words)

Stenberg announced curl's HackerOne bug-bounty program would stop accepting new submissions on 2026-02-01, citing an unsustainable ratio of AI-generated low-quality reports to real findings. He characterized the submission flood as "AI DDoS on open source." In-progress submissions at the cutoff would continue; thereafter curl would route security issues directly through GitHub.

The post is significant for two reasons beyond the shutdown itself:

1. **Quantitative baseline**: Stenberg cited specific numbers on how the signal-to-noise ratio degraded. Historical rate was about 1 valid per 6 reports in early 2025; by late 2025 it had dropped to 1 per 20–30.
2. **Program size**: curl's program had paid **over $100,000 across 87 confirmed vulnerabilities** over its operational life. This is not a marginal program; it is one of the most productive OSS bounty programs ever operated.

## Key excerpts (fair-use, short quotation, for commentary)

> *"The amount of low-effort and invalid reports, many of which appear to be AI-generated slop, has grown to an unsustainable level."* — Stenberg

> *"Until early 2025, roughly one in six security reports to curl were real. By late 2025, the rate has gone up to now it's more like one in 20 or one in 30, that is accurate."*

> *"The program resulted in 87 confirmed vulnerabilities and over 100,000 USD paid as rewards to researchers."*

> *"The main goal with shutting down the bounty is to remove the incentive for people to submit crap and non-well researched reports to us."*

## How this supports jesses's thesis

- **It names the problem jesses solves**: valid-rate collapse driven by AI-generated reports that triagers cannot distinguish from real findings without manual replay.
- **It establishes that "just define better policy" is not a sufficient response**. Stenberg shut the program down entirely rather than tighten the policy, which is the most extreme "the policy doesn't help" signal possible.
- **It names the mechanism missing**: there is no file-level way for a submitter to cryptographically distinguish real findings from AI-generated slop. jesses is a candidate for that file-level mechanism.
- **It identifies a warm first prospect**. Stenberg is the most clearly affected named person in the OSS world, and his post is the canonical reference everyone else cites. See [`docs/yc/outreach/stenberg-curl.md`](../yc/outreach/stenberg-curl.md) for the Day 1 approach. (Note: `docs/yc/` is locally excluded from git.)

## What would weaken this evidence

- If curl reopens the program on the same terms within 6 months, the underlying pressure clearly wasn't sustained.
- If Stenberg later clarifies the valid-rate numbers were off or methodology-flawed, the quantitative anchor weakens.
- If the broader category of OSS maintainers does *not* follow curl's lead (i.e., OpenSSL / Kubernetes / nginx continue business-as-usual), this is a curl-specific datum rather than a category signal.

None of these have happened as of the date of this file's creation (2026-04-17). Revisit quarterly.

## Archive status

- Wayback Machine: save yourself via [web.archive.org/save](https://web.archive.org/save) against the original URL. Running this locally is suggested at least once per quarter until the CHANGELOG notes a formal archive arrangement.
- Secondary sources (BleepingComputer, The Register, The New Stack, itsfoss, Hackaday) provide redundancy even if the primary blog goes dark.
