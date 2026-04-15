# Maintainers

This file lists the humans responsible for the `jesses` project and the response commitments they make to contributors.

## Current maintainers

| Name | GitHub | Role | PGP / Sigstore identity |
|---|---|---|---|
| yunsu (Hybirdss) | [@Hybirdss](https://github.com/Hybirdss) | BDFL (v0.1), security contact | `gitsign` keyless via GitHub OIDC (`narukys@gmail.com`); PGP key published at v0.1 release |

**Bus factor: 1.**

This is recorded honestly because pretending otherwise undermines the trust property the project exists to provide. The sustainability plan for reducing bus factor to ≥2 is documented in `GOVERNANCE.md` §Sustainability and tracked against `ROADMAP.md` Week 8.

## Response commitments

These are targets, not contractual SLAs. They apply during the v0.1 build phase (Day 0 through v0.1 release).

| Request type | Initial response | Resolution or plan |
|---|---|---|
| Security report (via GitHub Security Advisory) | 72 hours | 30 days for High / Critical per `SECURITY.md` |
| Bug report (non-security) | 7 days | triage label within 14 days |
| Pull request | 7 days | review within 14 days or explicit deferral |
| Spec clarification | 14 days | ADR added to `docs/adr/` or issue closed with rationale |
| New extractor proposal | 14 days | accept / defer / reject with reason |

If the maintainer cannot respond within these windows (travel, illness, parallel release crunch), a comment is posted on the issue or PR stating the expected delay. Silence is a bug.

## Decision authority during v0.1

Per `GOVERNANCE.md`, the maintainer holds final decision authority on:

- Merges to `main`
- Tag creation and release
- Spec changes (predicate URI, canonical serialization, verify gates)
- `THREAT_MODEL.md` additions or reclassifications
- Foundation transition timeline

The maintainer's authority is pre-committed to transfer to the Commonhaus Foundation by v0.2; see `GOVERNANCE.md` §Transition.

## Past maintainers

None yet. Departures and transitions will be recorded here with date and reason.

## How to become a maintainer

The first co-maintainer will be invited within 30 days after v0.1 release. Selection criteria, in priority order:

1. Substantive technical contribution to the codebase or test vectors (at least one non-trivial merged PR)
2. Demonstrated understanding of the threat model and bit-exact invariants
3. Willingness to accept the response commitments above
4. Independence from the founding maintainer's employer and personal network, to establish genuine governance plurality

The invitation is public (GitHub issue), reviewed by existing maintainers, and the candidate has 14 days to accept or decline.
