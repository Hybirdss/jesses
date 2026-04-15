# Trademark Policy

_Draft policy for the `jesses` word mark. Binding on the project maintainer(s)._

## Why this file exists

The MIT License covers copyright. It does not cover the project name. Without a trademark policy, a third party can ship a closed-source fork named `jesses Pro`, confuse users about which implementation is the standard, and the project has no standing to object.

This policy records the project's intent to defend the name, and the narrow uses that require no permission.

## The mark

- Word mark: **`jesses`** (lowercase, five characters)
- Canonical domain: `jesses.dev`
- Logo: none at the time of this draft. A logo, when adopted, is added to this document and treated as a combined mark.

## Ownership

During the v0.1 build phase the mark is held by the project maintainer under common-law trademark in the United States. A USPTO application is filed before v0.1 release; the Madrid System international extension follows within 60 days. At the Commonhaus Foundation transition (per `GOVERNANCE.md`), ownership and all rights under the mark are assigned to the foundation.

## Permitted uses without permission

The following uses are permitted without asking. Please do not ask; the answer is yes.

- **Nominative fair use.** Describing compatibility, integration, or support: "our platform verifies `jesses` attestations", "this SDK produces `.jes` files per the `jesses` specification", "a `jesses`-compatible verifier".
- **Factual statements.** Press and analysis may identify `jesses` by name when reporting on it.
- **Academic and research use.** Papers, security research, blog posts, and conference talks may name the project and quote from its documentation.
- **Community events.** Meetups, hackathons, and educational events may reference the name in titles and materials, provided the event does not imply official project endorsement without prior written agreement.

## Permitted uses with simple written agreement

The following require a short written exchange — an email, no lawyer needed. Contact the maintainer listed in `MAINTAINERS.md`.

- Using the `jesses` name in a product name alongside a company name (e.g. `AcmeSec jesses Integration`). The key word is "integration" — we want to make clear the product integrates with `jesses` and is not the project itself.
- Using the `jesses` name in a service offering (e.g. a managed verifier hosting service).
- Merchandise featuring the name (t-shirts, stickers) for non-commercial distribution.

## Uses that require permission and will generally be declined

- Product or service names where `jesses` is the dominant element and the producer is not the project (e.g. `jesses Pro`, `jesses Cloud`, `jesses Enterprise`).
- Domain registrations that could be confused with the project's canonical domain. `jesses-*.com` or `*-jesses.com` should be discussed in advance.
- Representations that imply official endorsement when none exists. In particular: claiming a service, product, or individual is "certified by `jesses`" or "official `jesses` implementation" without the project's agreement.
- Modified versions of the specification or verifier distributed under the `jesses` name without disclosing the modifications.

## Conformance claims for verifiers

A verifier may be described as a "`jesses` verifier" or "`jesses`-conformant" if, and only if, it passes every test vector under `spec/v0.1/test-vectors/` (or the vectors for the spec version it claims to implement). Passing the vectors is the contract. No certification mark or paid process gates this claim.

## Enforcement posture

The project defends the mark only in cases that cause actual user confusion about what is and is not the standard implementation. The project does not pursue incidental uses, informal references, or derivative works that are clearly distinguishable from the project. The explicit non-goals:

- The project does not use trademark to restrict forks. Forks under different names are welcomed and supported.
- The project does not use trademark to extract licensing fees. There is no licensing program and none is planned.
- The project does not pursue defensive filings in jurisdictions where it has no presence beyond the two mentioned above, because aggressive filing costs more than it protects.

## Reporting misuse

Reports of misuse to the maintainer listed in `MAINTAINERS.md`. A public filing is a last resort after written contact has failed.

## Amendment

This policy is amended via the process in `GOVERNANCE.md` §Amendment. At foundation transition, the policy is re-ratified by the Commonhaus Council alongside the IP transfer; edits after transition follow foundation trademark-policy amendment procedures.

---

_Template inspiration: [FOSSmarks](https://fossmarks.org/), [Matrix.org trademark policy](https://matrix.org/blog/2026/03/2026-03-trademark-policy/), and OSI trademark guidance._
