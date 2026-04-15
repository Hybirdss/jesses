# Contributing to jesses

Thanks for your interest. The project is small enough that a short guide covers everything.

## Sign your commits

We use the [Developer Certificate of Origin](https://developercertificate.org). Every commit needs a `Signed-off-by:` line. Set once:

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Then commit with `-s`:

```bash
git commit -s -m "your message"
```

The `dco` GitHub workflow enforces this on pull requests.

## Pull-request checklist

- [ ] `go test ./...` passes
- [ ] `go vet ./...` clean
- [ ] `(cd verifier-js && node test.mjs)` reports 3/3 conformance
- [ ] `go fmt` and the existing style conventions are followed
- [ ] New code has unit tests; bug fixes have regression tests
- [ ] Public API changes (`pkg/jesses/*`) include a CHANGELOG entry

## Byte-exactness matters

Several things in this repo are intentionally frozen because changing them breaks every past `.jes` file:

- The audit `Event` struct field order in `internal/audit/record.go`
- The canonical JSON serialization rules (see `verifier-js/canonical.mjs` for the spec-level description)
- The RFC 6962 Merkle leaf/node prefix bytes (`0x00` / `0x01`)
- The ITE-6 envelope predicate URI (`https://jesses.dev/v0.1/action-envelope`)
- The wrapper command table in `internal/shellparse/wrapper.go`
- The shell-re-entry program list in `internal/shellparse/reentry.go`

If your change touches any of those, open an issue first to discuss the version-bump path before sending a PR.

## Where to propose new things

- Small bug fixes or test additions: direct PR.
- Medium changes (new extractor, new flag, new verifier behavior): open an issue first, discuss, then PR.
- Spec changes (new gate, new field in the envelope, new predicate URI): open an issue, get agreement, coordinate a spec version bump, update the test vectors.

## Running the test suite

```bash
go test ./...                  # Go tests (218 currently passing)
go vet ./...                   # Go vet
(cd verifier-js && node test.mjs)  # Cross-implementation conformance
```

## Local demo end-to-end

```bash
cd examples/demo-bounty && ./reproduce.sh
```

That script builds the CLI, runs a 7-event session, verifies, binds a report, cross-verifies with the JavaScript implementation.

## Code of conduct

See [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
