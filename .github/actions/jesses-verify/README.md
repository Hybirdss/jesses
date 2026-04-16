# jesses-verify action

Offline six-gate verification of a `.jes` session envelope on GitHub Actions. If you pass a `report` input, gate 7 (deliverable-provenance binding) is enforced as well.

Zero network calls at verification time. Rekor inclusion proofs and OpenTimestamps Bitcoin proofs are embedded in the envelope and checked against their own embedded data.

## Usage

The most common case — a CI job that rejects pull requests whose attached `session.jes` does not pass verification:

```yaml
name: verify jesses attestation
on:
  pull_request:
    paths:
      - 'artifacts/session.jes'
      - 'artifacts/report.md'

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Hybirdss/jesses/.github/actions/jesses-verify@main
        with:
          session: artifacts/session.jes
          report:  artifacts/report.md
          bare-policy: strict      # every factual claim in report.md must cite an event
          fail-on-warn: "true"     # WARN becomes a merge blocker
```

## Minimum invocation (no report binding, default policy)

```yaml
      - uses: Hybirdss/jesses/.github/actions/jesses-verify@main
        with:
          session: path/to/session.jes
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `session` | yes | — | Path to the `.jes` envelope to verify. |
| `report` | no | *(unset)* | Path to a deliverable markdown report. When supplied, gate 7 (deliverable-provenance binding) is enforced. |
| `bare-policy` | no | `warn` | Handling for uncited factual claims when a report is bound: `allow`, `warn`, or `strict`. Ignored when `report` is unset. |
| `version` | no | `latest` | jesses version to install (release tag like `v0.1.0`, `latest`, or a Go module pseudo-version). Pin this in production repos. |
| `fail-on-warn` | no | `"false"` | When `"true"`, the step fails if any gate emits WARN. Useful for CI gates that refuse merge on any policy-breach warning. |

## Outputs

| Name | Description |
|---|---|
| `report-path` | Absolute path to the JSON verification report written during the step. |
| `verdict` | Top-level verdict: `PASS`, `FAIL`, or `WARN`. |

## Recipe — upload the JSON verdict as an artifact

```yaml
      - id: verify
        uses: Hybirdss/jesses/.github/actions/jesses-verify@main
        with:
          session: artifacts/session.jes

      - uses: actions/upload-artifact@v4
        with:
          name: jesses-verification-report
          path: ${{ steps.verify.outputs.report-path }}
          retention-days: 30
```

## Recipe — comment the verdict on a PR

```yaml
      - id: verify
        uses: Hybirdss/jesses/.github/actions/jesses-verify@main
        with:
          session: artifacts/session.jes
          report: artifacts/report.md

      - uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: jesses-verdict
          message: |
            ## jesses verification

            **Verdict:** `${{ steps.verify.outputs.verdict }}`

            Full JSON report is attached as a workflow artifact.
```

## Versioning

Pin a release tag in production repos:

```yaml
      - uses: Hybirdss/jesses/.github/actions/jesses-verify@v0.1.0
        with:
          session: artifacts/session.jes
          version: v0.1.0
```

Both the action reference and the `version` input should match to avoid subtle version skew between the action's expected CLI flags and the installed binary.

## Security

- The action uses `actions/setup-go@v5` and `go install` from the jesses module path declared in the repo README. Compile-from-source is the only install path today; signed release binaries arrive with v0.2.
- No network calls are made **during verification** itself. The initial `go install` step does require network access to `proxy.golang.org`.
- The action does not request `write` permissions to the repo. Callers should follow the principle of least privilege and pass `permissions: contents: read` at the workflow level.

## Limitations

- Requires a Linux or macOS runner. Windows is not supported while `internal/audit/writer_unix.go` carries the `!windows` build tag (see `ROADMAP.md` for the Windows writer timeline).
- Requires Go 1.22 or newer. Older toolchains will fail at the install step.
- The action does not fetch the policy file separately; the envelope's embedded `policy.content_ref` + `policy.sha256` is what the verifier checks against whatever policy file lives alongside the session.

## Reporting issues

File issues at [github.com/Hybirdss/jesses/issues](https://github.com/Hybirdss/jesses/issues) with the `area/ci-action` label.
