# Roadmap

## v0.1 (current)

Six-gate verifier (G1–G6) + G7 deliverable provenance + process-bound `jesses run` + spec test vectors + JavaScript second implementation. Go reference and JS verifier produce byte-identical `Report` JSON on the spec corpus.

What's in: verify, view (with --follow and --report), run (process-bound), hook, stats, cite, report, init-scope. 218 Go tests + 3 JS conformance vectors. Zero external dependencies.

See [`CHANGELOG.md`](./CHANGELOG.md) for the shipped entries, [`README.md`](./README.md) for quick start, [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the attack/gate matrix.

## v0.1.1

Follow-ups that naturally land a few weeks after v0.1:

- OTS upgrade polling (pending → confirmed) — the calendar returns a confirmed Bitcoin proof typically 10–60 minutes after submission; the CLI should fetch and replace the pending receipt.
- Real-Rekor CI integration test — exercises the `HTTPClient` path against `rekor.sigstore.dev` in a scheduled GitHub Action.
- TypeScript-proper port of `verifier-js` — same semantics, tsc-compiled, published as an npm package.
- Freshness nonce wire-up — implementation of the protocol speced in [`spec/freshness-nonce.md`](./spec/freshness-nonce.md), ready to integrate with a platform partner.

## v0.2

- Sigstore cosign PAE compatibility so DSSE-aware tooling can consume jesses envelopes natively.
- Multi-operator Rekor federation once a second independent Rekor deployment exists.
- Rust third implementation of the verifier.
- WASM build of the JS verifier for browser-side verification.

## v0.3

- Hardware attestation (Intel TDX / AWS Nitro / Apple Secure Enclave) — closes the A7 interleave and A8 theater-mode gaps mathematically. The design question is how much trust to place in the TEE manufacturer's root CA; options are documented in the ADR record when work starts.
- ZK compliance proofs for regulated-industry deployments that cannot publish raw audit bytes.

## What's explicitly out of scope (v0.1)

- In-TEE measurement loops — v0.3.
- ZK recursive proof aggregation — v0.3+.
- Blockchain anchors other than Bitcoin via OpenTimestamps — adds trust assumptions without closing a threat.
- A hosted SaaS — the CLI and libraries are enough.
- Dashboards, policy consoles, SSO integrations — possible in commercial layers on top but not in the core.
