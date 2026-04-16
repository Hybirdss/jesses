# Why jesses, and why now

This is the one-page version of the argument. If you're deciding whether to spend more time on the repo, start here.

## The gap that opened in eight weeks

Between January 26 and March 2026, four independent decisions landed in public:

| Date | Actor | Decision | Public source |
|---|---|---|---|
| 2026-01-26 | curl (Daniel Stenberg) | Ends HackerOne bug-bounty program effective 2026-02-01 | [daniel.haxx.se](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/) |
| 2026-02-01 | curl | HackerOne submissions actually close; GitHub-only disclosures from here | same |
| 2026-02-18 | HackerOne | AI policy update: "automated or unverified outputs are not accepted" | [The Register](https://www.theregister.com/2026/02/18/hackerone_ai_policy/) |
| 2026 Q1 | Bugcrowd | Submission policy, rate controls, and detection changes targeting AI slop | [bugcrowd.com/blog](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/) |
| 2026 Q1 | Intigriti | Code of conduct: unverified AI output "may be closed without response" | [kb.intigriti.com](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct) |

Stenberg's numbers from the closing post: valid-report rate at curl fell from roughly **one in six in early 2025 to one in twenty or thirty by late 2025**. curl had paid **$100k+ across 87 valid reports** over the program's life. He called the flood "AI DDoS on open source."

Platforms and maintainers wrote the policy. **None of them defined what "verified" means.** The enforcement layer is open.

## Why the gap is hard to close without a new file format

Three tools already exist adjacent to this problem:

- **Sigstore / in-toto / cosign** assume a trusted build pipeline. The signer is trusted by assumption.
- **Platform-internal AI triage** (HackerOne's Hai, Bugcrowd detection) is a walled garden. A triager at Intigriti cannot verify a Hai-scored submission, and vice versa.
- **Research systems like Aegis** ([arxiv:2603.16938](https://arxiv.org/html/2603.16938v1)) enforce runtime policy inside a trusted SDK; the paper explicitly excludes "direct database manipulation by root-privileged adversary" from its threat model.

All three fail the one adversarial condition that actually matters in bounty and audit work: **the person running the tool is the person being checked.** A bounty hunter whose agent touched an out-of-scope host has a direct financial incentive to delete that log entry before submission. A consultancy whose autonomous audit touched the wrong S3 bucket has a direct client-relationship incentive to rewrite history.

`jesses` is built around the opposite assumption. The full premise is in [`THREAT_MODEL.md`](./THREAT_MODEL.md) — eight enumerated attacks a motivated submitter would try, six closed mathematically in v0.1 (Merkle tree + Rekor pre-commit + OpenTimestamps anchor + policy-hash binding + G7 deliverable provenance), one closed via adversarial economics, one deferred to TEE attestation in v0.3.

## Why this window closes

Certificate Transparency is the reference case. CT spec finalized in 2013. Logs ran for five years with adoption near zero. Then in **April 2018**, Chrome began enforcing CT log inclusion for every certificate, and within months every public CA had to log. The spec had been ready; the enforcer decided when.

Today, `.jes` is the spec. Two conformant verifiers exist (Go reference + JavaScript second implementation, byte-identical on [`spec/test-vectors/v0.1/`](./spec/test-vectors/)). Zero bug-bounty platforms currently enforce its presence. The window for one open standard to become the enforcer's tool is probably 12–18 months; after that, a proprietary walled-garden format inside one platform is the likely default, and migrating off of it costs more than adopting now costs.

## What "correct" looks like at the file level

A third party — a triager at HackerOne, an auditor at Trail of Bits, a lawyer at curl — receives a report and a `.jes` file. They run:

```
jesses verify --offline session.jes
```

No network. No platform account. No vendor dependency. The exit code is 0 or 1. If 0, six cryptographic properties hold simultaneously:

1. The DSSE signature on the in-toto envelope verifies.
2. The predicate conforms to [`spec/v0.1/predicate.schema.json`](./spec/v0.1/predicate.schema.json).
3. The RFC 6962 Merkle root over the audit log recomputes to the claimed value.
4. The Rekor inclusion proof for the session-start pre-commitment was logged **before** the first event's timestamp, and the policy hash inside the pre-commit matches the policy file on hand.
5. The OpenTimestamps proof anchors the session's end time to a Bitcoin block.
6. Every event in the audit log evaluates to its recorded `allow / warn / block` decision under the stated policy, deterministically and re-runnably.

Add `--report report.md` and gate 7 binds every `[^ev:N]` footnote in the report to a specific audit-log event. A claim citing data the agent obtained outside the session produces no valid event to cite — gate 7 fails.

## What's shipping today

- Go reference implementation, 14k LOC, 218 tests, zero external dependencies in every production package
- JavaScript second implementation in [`verifier-js/`](./verifier-js/), Node 20+ built-ins only
- Spec [`SPEC.md`](./SPEC.md) + test vectors [`spec/test-vectors/v0.1/`](./spec/test-vectors/) that both implementations must pass byte-for-byte
- Reference Claude Code integration via stdin hook; same shape works for Cursor, Cline, and custom harnesses
- Signed releases (cosign keyless via Fulcio + Rekor, SLSA Build L3 provenance, SBOM)
- Fuzz-tested: 1.2M executions at 170k/s over 10s, zero panics

All MIT-licensed. The commercial layer, if and when it exists, sits above the CLI. The CLI stays free.

## What's honest about the current state

- Zero external paying users as of 2026-04-17.
- Zero platforms currently require or prioritize `.jes`-bearing submissions.
- A7 (interleave) and A8 (theater) attacks are closed in v0.1 via adversarial economics and G7 respectively, not TEE attestation. v0.3 is the cryptographic closure.
- Governance is a single maintainer. Foundation-level governance is a v1.0 question, not a v0.1 promise.

If you're a bounty platform community manager, an OSS security maintainer, or an AI-audit practice lead and any of this matches a problem on your desk, a 10-minute demo is the shortest useful contact: clone the repo, run [`examples/demo-bounty/reproduce.sh`](./examples/demo-bounty/reproduce.sh), then open an issue or email with the question that broke your mental model. Adversarial feedback is worth more than confirmation.

---

Further reading inside this repo: [`THREAT_MODEL.md`](./THREAT_MODEL.md) (the adversary), [`SPEC.md`](./SPEC.md) (the standard), [`ARCHITECTURE.md`](./ARCHITECTURE.md) (the boundaries), [`FAQ.md`](./FAQ.md) (the adversarial questions).
