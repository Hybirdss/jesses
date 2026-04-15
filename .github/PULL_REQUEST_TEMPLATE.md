<!--
Thanks for contributing to jesses.

Before submitting, please:
  1. Read CONTRIBUTING.md.
  2. Ensure every commit in this PR has `Signed-off-by:` (git commit -s).
  3. Confirm `go test ./...` is green locally.
  4. Confirm `task lint` (golangci-lint) is green locally.

If this PR touches canonical serialization, Merkle leaf hashing, the Event
struct field order, the verify gate set, or the predicate URI, STOP. Open a
spec clarification issue first. Changes to frozen surfaces without a
corresponding spec version bump will be rejected.
-->

## Summary

<!-- One-paragraph description of what changes and why. -->

## Type of change

<!-- Tick exactly one. -->

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking; adds capability without changing existing output)
- [ ] Breaking change (requires spec version bump — `SPEC.md` edited in same PR)
- [ ] Documentation only
- [ ] Tooling / CI / governance

## Tests

<!-- What tests were added or changed? Prefer test-vector references over ad-hoc assertions. -->

- [ ] Added unit tests in affected package
- [ ] Added / updated test vectors under `spec/v0.1/test-vectors/` (breaking changes only)
- [ ] Ran `go test -race -count=3 ./...` locally and all packages pass
- [ ] Ran `govulncheck ./...` locally with no new findings

## Bit-exact invariant check

- [ ] This PR does not change canonical JSON serialization output for any existing `Event`
- [ ] This PR does not change Merkle leaf hash output for any existing leaf
- [ ] This PR does not reorder fields in the `Event` struct or any type marshalled into the attestation
- [ ] If any of the above boxes is unchecked, the PR also bumps the predicate URI in `SPEC.md` and adds migration notes in `CHANGELOG.md`

## DCO sign-off

- [ ] Every commit in this PR includes `Signed-off-by:` (`git commit -s`)

## Related issues

<!-- Link issues this PR closes or references. Use `Closes #N` for auto-close. -->

## Reviewer checklist

<!-- For the reviewer; leave unchecked when opening the PR. -->

- [ ] Change is in scope per CONTRIBUTING.md §"What you will not find a quick yes for"
- [ ] Test coverage is proportional to the behavior added
- [ ] No new third-party dependency introduced in `internal/`
- [ ] If touching threat-model assumptions, `THREAT_MODEL.md` is updated in same PR
