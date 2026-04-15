# Governance

This document describes how decisions are made in the `jesses` project, who makes them, and the pre-committed transition plan for moving from a single-maintainer start to neutral foundation stewardship.

This document is one of three that together define the project's social contract. Read alongside:

- `CONTRIBUTING.md` — how patches are accepted
- `CODE_OF_CONDUCT.md` — behavior in project spaces
- `MAINTAINERS.md` — who the humans are and their response commitments

---

## Current model: BDFL with pre-committed exit

During the v0.1 build phase (Day 0 through v0.1 release), `jesses` operates under a Benevolent-Dictator-For-Life model with a single maintainer. This is the honest characterization of a project with bus factor 1. The maintainer holds final authority on:

- Merges to `main`
- Tag creation and release
- Spec changes (predicate URI, canonical serialization schema, verify gate set)
- Scope decisions (what gets built, what gets rejected as out-of-scope)
- Threat-model additions or reclassifications

A BDFL model is appropriate at project inception. It is not appropriate for a primitive that others depend on. The goal is therefore to transition out of it on a pre-committed timeline.

## The transition: Commonhaus, not a bespoke foundation

An earlier revision of the project's documentation described forming a bespoke legal entity (Delaware nonprofit or Swiss foundation) to hold the project. That plan has been withdrawn. The rationale:

- Standing up a new 501(c)(3) or Swiss Verein costs USD 20,000–50,000 in legal and ongoing administrative overhead.
- A single-maintainer project cannot sustain that overhead while also shipping code.
- The [Commonhaus Foundation](https://www.commonhaus.org/) is a purpose-built fiscal and governance sponsor for exactly this case: established open-source projects that need a neutral home for IP, trademarks, and funds, without being forced into a heavyweight process model.
- Commonhaus permits "bring your own governance" within its bylaws, so the project-specific governance below remains in force after transition.

Reference precedent within Commonhaus: Pi4J joined as a single-maintainer project in February 2026; Quarkus, Micronaut, and others are in progress.

### Transition timeline

| Milestone | Target | Actions |
|---|---|---|
| v0.1 release | Day 30 | `GOVERNANCE.md`, `TRADEMARK.md`, `MAINTAINERS.md` in place; sustainability plan published |
| First external maintainer invitation | v0.1 + 30 days | Second committer proposed based on contribution record |
| Commonhaus sponsorship opened | Day 60 | Open Collective account established; sponsorship via GitHub Sponsors enabled |
| Commonhaus membership application | Day 75 | Formal application submitted; bylaws adaptation prepared |
| Trademark assignment | at application | `jesses` word mark (US + Madrid System) filed by maintainer, assignment to foundation prepared |
| Foundation transfer complete | Day 90 | IP, trademark, domain, and repository ownership transferred; this section rewritten to reflect the post-transition state |

At the moment of transfer, final-authority decisions migrate from the individual maintainer to the project's Technical Committee (see below), with dispute escalation to the Commonhaus Council per foundation bylaws.

## Post-transition model: Technical Committee

Target structure, effective upon Commonhaus membership confirmation:

- **Technical Committee (TC)**: 3 seats, odd number for tiebreaks.
  - 1 seat: founding maintainer (time-limited to 4 years to prevent entrenchment)
  - 1 seat: active contributor elected annually by contributors with 5+ merged PRs
  - 1 seat: downstream integrator representative (nominated by an integration partner — initially a bounty platform)
- **Decisions by rough consensus** on the `governance@` mailing list or a GitHub Discussions thread; formal vote when consensus is not reached within 14 days.
- **Recall**: any TC seat can be recalled by a supermajority (2 of the other 2) for extended absence (>90 days) or conduct violation.
- **Spec changes** (predicate URI, canonical serialization, verify gates): require unanimous TC approval + 30-day public comment period before merge.
- **Non-spec code changes**: single TC member approval (functionally identical to PR review today).

## Decision classes

| Class | Examples | Authority (v0.1) | Authority (post-transition) |
|---|---|---|---|
| Spec-breaking | predicate URI bump, canonical format change, gate-set change | maintainer + 30-day public comment | TC unanimous + 30-day public comment |
| Spec-stable feature | new tool extractor, new privacy mode | maintainer | 1 TC member |
| Policy / process | governance changes, contributor licensing | maintainer | TC majority + 14-day comment |
| Release tag | version bump, binary publish | maintainer | 1 TC member + CI green |
| Incident response | security disclosure, coordinated release | maintainer per `SECURITY.md` | TC + security committee per bylaws |

## Sustainability

The durable risk to this project is not that someone will try to take it over. The risk is that the maintainer will stop. The sustainability commitments:

1. **Honest bus-factor disclosure.** `MAINTAINERS.md` records bus factor 1 during v0.1. Hiding it is worse than stating it.
2. **Second-language verifier by Day 42.** A TypeScript reference implementation commissioned from an independent consultancy (Trail of Bits, NCC Group, or Code Shield tier) ensures the spec remains implementable by others even if the primary maintainer disappears. Budget: USD 5,000–10,000; funded from initial sponsorship + Commonhaus fiscal sponsorship.
3. **Test vectors are the contract.** `spec/v0.1/test-vectors/` is the authoritative specification of correct behavior. Any verifier that passes them is a conforming verifier, regardless of who maintains it.
4. **Funding: Open Collective + GitHub Sponsors.** Activated at v0.1 release. Funds allocated to (a) maintainer time, (b) CI and infrastructure, (c) second-verifier commission, (d) annual security audit of the verifier from v0.2 onward.
5. **Open Source Pledge alignment.** Downstream commercial users — bounty platforms, compliance vendors — are asked to pledge annual support proportional to their use. Not required, publicly listed.

## Non-monetization commitment

- The primitive — hook, log format, attestation envelope, verifier, specification — is MIT-licensed in perpetuity. MIT is structurally irrevocable; this statement is a reminder, not a contractual add-on.
- Funds raised via sponsorship, fiscal sponsorship, or grants fund project operations (maintainer time, CI, security audits, second-language verifiers). They do not change the license, the feature set available to non-funders, or the governance rights of any party.
- No paid tier, no enterprise edition, no hosted service, no priority support channel. Every such addition is a step toward product and away from primitive.
- Enterprise services built on top of `jesses` — hosted verification, compliance dashboards, managed transparency log operators — may be sold by any third party. The project itself does not build or endorse them.

## Dispute escalation

During v0.1, disputes between contributors and the maintainer escalate to a public issue in the repository with the `governance-escalation` label. Resolution is documented in the issue thread. Post-transition, escalation path is Contributor → TC → Commonhaus Council per foundation bylaws.

## Amendment

Changes to this document during v0.1 require: a PR from the maintainer, 14-day public comment period in a GitHub Discussion, and a signed-off commit that references the discussion URL. Post-transition, amendment follows the TC-majority-plus-comment-period process described in §Decision classes.

---

_This document is binding on the maintainer(s). Its existence is what separates "a useful primitive" from "a primitive whose continued neutrality you can bet on."_
