# Governance

## Current model

Single maintainer, BDFL. The maintainer holds final authority on merges to `main`, tag creation, releases, spec changes, scope decisions, and threat-model revisions.

This is accurate for a project at inception. As contributors accumulate, the model will evolve — likely toward a Technical Committee once more than one person is regularly shipping code.

## Spec stability

The wire format (envelope, predicate URI, canonical serialization) is treated as an invariant once `v0.1.0` ships. Schema changes require a coordinated version bump (`v0.1` → `v0.2` predicate URI) and regeneration of the spec test corpus in `spec/test-vectors/`.

Implementations passing the test vectors are conformant. Implementations that diverge are not, regardless of what they claim.

## How decisions get made

- **Code changes** — pull request, passes CI, reviewed by maintainer.
- **Spec changes** — proposal issue first, discussion in public, only then a PR. Any spec change that breaks byte-exact conformance requires a version bump.
- **Threat-model changes** — same as spec.
- **New verifier gates** — same as spec.

## See also

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to send a PR
- [`MAINTAINERS.md`](./MAINTAINERS.md) — who the humans are
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — behavior expectations
- [`SECURITY.md`](./SECURITY.md) — reporting vulnerabilities

## License

The code is MIT. See [`LICENSE`](./LICENSE).
