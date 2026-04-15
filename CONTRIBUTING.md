# Contributing to `jesses`

`jesses` is an attestation primitive. The entire value of the project is that `.jes` files produced by one version verify identically a decade from now. That constraint shapes every rule below.

Before you send a patch, please read this file in full. The rules exist because mistakes are expensive to undo.

---

## Ground rules

1. **Bit-exact is forever.** Canonical serialization (`internal/audit/canonical.go`), Merkle leaf hashing (`internal/merkle/tree.go`), and the `Event` struct field order are frozen. A PR that changes any of these invalidates every past `.jes` file and will be rejected without discussion unless it also proposes a new predicate URI (`jesses.dev/vN.Y/...`) and ships a test-vector migration.
2. **Tests before code.** Every public behavior has a test vector in `spec/v0.1/test-vectors/` or a unit test in the package that implements it. New code without new tests is not reviewed.
3. **Zero external dependencies beyond Go stdlib in `internal/`.** The adversary model is supply-chain poisoning. A transitive dependency in `internal/merkle` or `internal/audit` is a security bug.
4. **Scope discipline.** `jesses` is a primitive — hook, log, attestation, verifier. It is not a dashboard, not a SaaS, not a policy library, not a scanner. Patches that extend scope are redirected to downstream projects.

---

## Developer Certificate of Origin (DCO)

`jesses` uses the [Developer Certificate of Origin](https://developercertificate.org/) rather than a Contributor License Agreement. Every commit must be signed off.

Add the sign-off automatically with `git commit -s`:

```
git commit -s -m "day N: <what changed>"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>` line to the commit message. The line asserts the following:

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

Commits without `Signed-off-by` are blocked in CI by `.github/workflows/dco.yml`. Use `git rebase --signoff` to add sign-offs to existing commits.

Signed commits themselves (GPG / S/MIME / `gitsign`) are encouraged but not required. If you use [`gitsign`](https://github.com/sigstore/gitsign), your commits will show as "Verified" via Sigstore's keyless flow.

---

## Workflow

### 1. Before you start

- For any change larger than a typo: open an issue first and describe the problem.
- For changes that touch canonical serialization, Merkle construction, policy evaluation, or the verify gate set: open a **spec clarification** issue; code changes follow spec changes, never lead them.
- For new tool extractors: use the `new_extractor` issue template; the extractor inventory is coordinated in `SPEC.md §5`.

### 2. Branch and build

```
git clone https://github.com/Hybirdss/jesses.git
cd jesses
go test ./...            # all tests must be green before you start
git checkout -b day-N.M-<what>
```

Branch naming: `day-<phase>-<short-slug>` for build-log-tracked work (e.g. `day-2.2b-segment-splitter`); `fix/<slug>` or `docs/<slug>` for everything else.

### 3. Local checks before pushing

```
task test         # go test ./...
task lint         # golangci-lint run --timeout 3m
go test -race ./... # flaky-test detection
govulncheck ./... # known-CVE check
```

Every check must pass locally. CI is a safety net, not a substitute.

### 4. Pull request

- Title: imperative mood, no conventional-commit prefix (`day 2.2b: segment splitter` not `feat: add segment splitter`).
- Description: what changed, why, what tests were added, which test vectors were updated. Use `.github/PULL_REQUEST_TEMPLATE.md`.
- One logical change per PR. No drive-by refactors mixed with feature work.
- Sign off every commit. DCO CI will block unsigned commits.

### 5. Review

- Single reviewer (maintainer) during v0.1. After co-maintainer onboarding (post v0.1), two reviewers for changes to frozen surfaces.
- Reviewer focus order: (1) correctness against the spec, (2) test coverage, (3) adversarial-model impact, (4) style. Style is last because `gofmt` and `golangci-lint` handle it.
- No force-push to a PR branch during active review. After changes requested, push additional commits; the reviewer will squash at merge time.

---

## What you will not find a quick `yes` for

- "Replace the stdlib JSON canonicalizer with a faster third-party library." The whole project depends on byte-exact determinism. The stdlib is the only library stable enough to bet a decade on.
- "Add a hash-function option." v0.1 is SHA-256, fixed by RFC 6962. Post-quantum migration is a v0.5+ conversation with its own predicate URI.
- "Skip verification gates for performance." All six gates are mandatory. A verifier that skips any gate is not a `jesses` verifier.
- "Add a Python reference implementation." The install surface of a language runtime is itself an adversarial attack surface; see `ROADMAP.md` rationale.
- "Strip the session-start pre-commitment to reduce latency." Without pre-commitment, the fabricate-entire-session attack is undetectable. See `THREAT_MODEL.md §3`.

---

## What we actively want help with

- **Second-language verifiers.** TypeScript verifier is commissioned for v0.1 + 2 weeks. Rust and Python verifiers are welcomed after v0.1 ships, coordinated through `spec/v0.1/test-vectors/`.
- **Tool extractors.** The set of CLI tools from which `jesses` extracts destinations needs to grow. See `SPEC.md §5` for the contract and the `new_extractor` issue template.
- **Adversarial test cases.** If you find a pattern that slips past an extractor — a shell one-liner that hides a destination, a proxy-override form, an obfuscated curl — file it as a failing test case and we will treat it like a security bug.
- **Platform integration contributions.** Intake webhooks, verifier SDKs in JS/TS, triage UIs that display `.jes` status. See `examples/`.
- **Documentation for the three audiences.** Hunter quickstart, program-operator integration, compliance-officer guide. Plain language, no jargon.

---

## Reporting security issues

**Do not file public issues for security bugs.** See `SECURITY.md` for the disclosure channel. The seven attacks in `THREAT_MODEL.md` are the ones we have already considered; if you find an eighth, that is exactly the report we are built to hear.

---

## Code of Conduct

This project adopts the Contributor Covenant 2.1 verbatim. See `CODE_OF_CONDUCT.md`. Enforcement contact is in `MAINTAINERS.md`.

---

## License

By contributing, you agree that your contribution will be licensed under the MIT License (see `LICENSE`). No copyright assignment is required — you keep your copyright, you grant the project the MIT permissions, the DCO sign-off records that grant.
