---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: [open-source-governance drafting meeting 2026-04-16]
informed: []
supersedes: []
superseded_by: []
---

# 0010 — Commonhaus Foundation over a self-founded legal entity

## Context and problem statement

An earlier draft of `ROADMAP.md` and `README.md` described forming a bespoke legal entity — "jesses Foundation" — to hold the project's IP, trademarks, and funds post v1.0, as a mechanism for neutral stewardship.

Standing up a new 501(c)(3) Delaware nonprofit or a Swiss Verein is expensive (USD 20,000–50,000 in legal fees and annual administrative overhead) and slow (6–12 months to full operational readiness). For a single-maintainer project at v0.1 scale this overhead either crowds out code work or drains the project's first year of sponsorship before the second-language verifier has even shipped.

In 2024–2026 a purpose-built alternative matured: the Commonhaus Foundation, designed as a fiscal and governance sponsor for established open-source projects that need a neutral home for IP, trademarks, and funds without being forced into a heavyweight process model (as Apache would impose) or a vendor-neutrality-requires-multi-org-maintainers posture (as CNCF graduation requires). Pi4J joined Commonhaus as a single-maintainer project in February 2026; Quarkus, Micronaut, and other established projects are transitioning.

Which neutral home should `jesses` target?

## Decision drivers

- Cost and overhead at v0.1 scale (single maintainer, no paid staff).
- Ability to start now rather than after months of legal work.
- Neutrality signal to integration partners and downstream consumers.
- Compatibility with the project's existing governance (`GOVERNANCE.md`) without forced process replacement.
- Reversibility if the match is wrong — can we leave without a destructive fork?

## Considered options

- Commonhaus Foundation
- Self-founded Delaware 501(c)(3) nonprofit
- Self-founded Swiss Verein or Stiftung
- Apache Software Foundation (incubator path)
- CNCF (sandbox → incubation → graduated)
- No foundation; maintainer-held IP in perpetuity

## Decision outcome

**Chosen: Commonhaus Foundation.** It is the only option that matches the project's scale (single-maintainer feasible), timeline (weeks-not-months to membership), neutrality signal (purpose-built as a neutral home), and governance flexibility (bring-your-own governance within Commonhaus bylaws). The revised transition plan is: sponsorship opened at Day 60, membership application at Day 75, transfer complete at Day 90 (`GOVERNANCE.md` §Transition timeline).

The earlier "jesses Foundation" plan is withdrawn. `README.md`, `ROADMAP.md`, and `GOVERNANCE.md` are updated to reflect Commonhaus as the target home.

### Positive consequences

- Foundation path becomes achievable within the v0.1 + 90-day window rather than 6–12 months.
- Legal and administrative overhead is shared with Commonhaus; the project's sponsorship funds code and verifiers, not legal fees.
- Neutrality is signaled by a recognized fiscal sponsor rather than a self-formed entity (which necessarily starts under the maintainer's sole control).
- Trademark, domain, IP assignment pathway is well-trodden by Commonhaus; we follow their template.

### Negative consequences

- Commonhaus is newer than Apache or CNCF; some integration partners may not recognize the name at first contact. Mitigation: link Pi4J / Quarkus / Micronaut as precedents.
- Governance flexibility cuts both ways — Commonhaus does less process enforcement than Apache, so the project's own governance discipline must hold up independently.
- If Commonhaus itself dissolves or pivots (low probability but non-zero), the project must re-home. Mitigation: IP and trademarks remain transferable; the foundation's bylaws provide for project departure.

## Pros and cons of the options

### Commonhaus

- Good: purpose-built for established small/medium projects
- Good: BYO governance; existing `GOVERNANCE.md` survives transition
- Good: fast path to membership (weeks)
- Bad: younger ecosystem; recognition still growing

### Self-founded 501(c)(3)

- Good: maximum governance control
- Bad: USD 20–50k setup cost; 6–12 months to operational; ongoing annual administrative burden
- Bad: self-formation undermines the very neutrality signal that motivated the effort

### Self-founded Swiss Verein / Stiftung

- Good: Switzerland has a respected nonprofit tradition
- Bad: all the downsides of 501(c)(3) plus geographic complication
- Bad: tax and filing situation is project-dependent; requires local legal counsel

### Apache Software Foundation

- Good: premier open-source neutrality signal
- Bad: incubation process is heavyweight; "Apache Way" process may not fit a spec-heavy primitive
- Bad: multi-org maintainer expectations conflict with single-maintainer v0.1 reality

### CNCF

- Good: strong cloud-native ecosystem adjacency
- Bad: sandbox → graduated requires multi-org maintainers
- Bad: cloud-native orientation is slightly off-target; jesses is security-adjacent rather than cloud-orchestration-adjacent

### No foundation

- Good: simplest
- Bad: maintainer-held IP in perpetuity is precisely the failure mode documented in the project's pre-commitment; the long-run neutrality promise requires an actual exit

## Validation

- `GOVERNANCE.md` §Transition timeline is binding on the maintainer.
- Sponsorship is opened via Open Collective at Day 60 as the first observable milestone.
- Commonhaus membership application is submitted at Day 75; public URL is linked in `GOVERNANCE.md` once filed.
- Transfer of IP, trademark, and domain ownership completes at Day 90; this ADR is updated with the transfer date and the `GOVERNANCE.md` post-transition section replaces the v0.1 BDFL section.

## Links

- [Commonhaus Foundation](https://www.commonhaus.org/)
- [Pi4J joins Commonhaus (2026-02)](https://www.pi4j.com/blog/2026/20260227-pi4j-commonhaus/)
- [Micronaut joining Commonhaus (2026-01)](https://micronaut.io/2026/01/12/micronaut-announces-plans-to-join-the-commonhaus-foundation/)
- [Comparing Apache, CNCF, and Commonhaus](https://cnr.sh/posts/comparing-apache-cncf-commonhaus/)
- `GOVERNANCE.md` §Transition
- `ROADMAP.md` §Week 11 (foundation governance)
- `TRADEMARK.md` §Ownership
