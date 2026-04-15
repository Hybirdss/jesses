---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0009 — Platform-first adoption via Immunefi

## Context and problem statement

A new standard requires adoption to become a standard. Three candidate adoption paths:

- **Regulator-first**: pursue EU AI Act Article 12 or ENISA reference status. High prestige, low near-term adoption, 12–18 month horizon.
- **Hunter-first**: evangelize to individual bug bounty researchers. High enthusiasm, but individual adoption does not compel platforms to integrate; low conversion from "some hunters attach `.jes`" to "platforms enforce `.jes`".
- **Platform-first**: persuade one bounty platform to integrate intake verification. Needs only one "yes"; the integration becomes the reference story other platforms copy.

The central insight from Certificate Transparency: standards become standards when a platform enforces them. CT succeeded because Chrome made log inclusion mandatory for certificates. `jesses` needs an equivalent lever.

Which path should absorb the bulk of non-engineering effort during Weeks 5–9?

## Decision drivers

- Shortest time to forced (not voluntary) adoption.
- Number of organizations that must say yes for the strategy to work.
- Alignment between `jesses`'s specific benefit and the candidate organization's current pain.
- Resilience if the chosen partner declines.

## Considered options

- Platform-first via Immunefi
- Platform-first via HackerOne
- Platform-first via Bugcrowd
- Regulator-first (ENISA or national CERT)
- Hunter-first (top-10 leaderboard evangelism)

## Decision outcome

**Chosen: platform-first via Immunefi.** Immunefi has the smallest engineering team among the major bounty platforms, is crypto-native and comfortable with cryptographic attestation as a primitive, and is currently experiencing an acute quality crisis from AI-assisted submissions flooding their triage queue. `jesses` directly addresses that pain. A single integration becomes the reference other platforms can copy.

HackerOne and Bugcrowd are parallel secondary approaches with no deep investment at v0.1. Regulator engagement is tertiary — one formal ENISA submission at Week 8 to create a paper trail; no ongoing effort. Hunter outreach is a secondary amplifier via personal contact with roughly ten top researchers.

### Positive consequences

- One organization to persuade. If Immunefi accepts, `.jes` becomes a visible, enforced thing on a live platform within v0.1 + 60 days, far faster than regulatory or individual-adoption paths.
- Immunefi's crypto-native engineering culture shortens the "what is attestation?" ramp.
- Strategic clarity: every effort in Weeks 5–9 has a single success metric (Immunefi integration progress).

### Negative consequences

- Concentration risk: if Immunefi declines, we need an immediate fallback (Bugcrowd is the pre-identified second target; HackerOne is third, larger but slower).
- Immunefi's scope is predominantly crypto bounties; adoption there does not automatically carry to web-app bounty triage on H1/BC. The path from Immunefi to the others is a copy-of-reference, not direct.
- Platform partnerships are relationships; a single bad interaction can close the door for years. Requires careful engagement cadence.

## Pros and cons of the options

### Platform-first via Immunefi

- Good: smallest engineering team, fastest integration decisions
- Good: current pain aligns with jesses value proposition
- Good: crypto-native, comfortable with cryptographic attestation
- Bad: concentration risk; scope limited to crypto at first

### Platform-first via HackerOne

- Good: widest reach if integrated
- Bad: large engineering org, slower decisions
- Bad: diversified surface; jesses is one of many priorities competing for their roadmap

### Platform-first via Bugcrowd

- Good: midway between H1 and Immunefi on team size
- Neutral: current AI-submission pain similar to H1
- Bad: less crypto-native; slightly more explaining to do

### Regulator-first

- Good: highest prestige if achieved; structural adoption
- Bad: 12–18 month horizon far exceeds the v0.1 window
- Bad: regulatory adoption without platform adoption can produce compliance theater without real use

### Hunter-first

- Good: high enthusiasm from early adopters
- Bad: individual adoption does not compel platforms to integrate
- Bad: high noise in broadcast channels; personal outreach is the only useful form

## Validation

- Success metric at Day 90: at least one integration conversation with Immunefi has reached "architecture review with engineering" stage, per `ROADMAP.md` Day 90 success criteria point 1.
- Secondary metric: 10+ voluntary `.jes` attachments from real hunters on any platform's public bounty pages.
- Failure signal: at Day 90, no platform has engaged beyond acknowledgment. Response: re-evaluate the strategic bet (pivot to hunter-first with direct user pull, or sunset).

## Links

- `ROADMAP.md` §Strategic bet — full rationale and fallback ordering
- `ROADMAP.md` §Risks & contingencies (Immunefi passes)
- ADR 0002 (envelope) — integration surface for platform intake
