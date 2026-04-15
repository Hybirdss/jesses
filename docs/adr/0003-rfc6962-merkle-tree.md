---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: [CT / RFC 6962 reference implementations]
informed: []
supersedes: []
superseded_by: []
---

# 0003 — RFC 6962 Merkle tree (byte-exact with Certificate Transparency)

## Context and problem statement

A `.jes` attests to a sequence of tool invocations during an agent session. The attestation must allow a verifier to:

1. Prove any single invocation was part of the session.
2. Prove the log was append-only between two checkpoints (no retroactive edit, no reordering, no entries dropped).
3. Do both of the above without replaying the entire session.

The choice of log data structure determines whether (2) is cryptographically possible at all, and whether (1) and (3) are O(log n) or O(n).

## Decision drivers

- O(log n) inclusion proofs for individual events.
- Ability to prove append-only extension between any two historical checkpoints (consistency proof).
- Byte-exact compatibility with an existing, widely-reviewed standard, so that third-party verifiers (including the commissioned TypeScript one) can be written against a neutral specification rather than against our implementation.
- No licensing or patent surface surprises.
- Zero external dependencies for the merkle package (consequence of ADR 0001).

## Considered options

- RFC 6962 Merkle tree (Certificate Transparency)
- Simple hash chain (each record hashes the previous)
- Merkle Mountain Range (MMR) as used by OpenTimestamps internals
- Sparse Merkle Tree (as used by some blockchain state commitments)

## Decision outcome

**Chosen: RFC 6962 Merkle tree, byte-exact.** Certificate Transparency has the most reviewed and deployed tree construction in the industry, inclusion and consistency proofs are defined in the RFC itself, and `internal/merkle` can be written stdlib-only by following the RFC verbatim.

### Positive consequences

- `internal/merkle/tree.go` uses only `crypto/sha256` and arithmetic; no external dependencies.
- Inclusion proofs are O(log n). Consistency proofs are O(log n) in the distance between checkpoints.
- The data structure is identical to the one running in every major certificate transparency log; a TypeScript, Rust, or Python reimplementation has a reference source.
- The RFC 6962 test vectors give us a conformance bar that an alternative implementation either passes byte-exactly or fails visibly.

### Negative consequences

- RFC 6962's leaf and interior prefix bytes (`0x00`, `0x01`) cannot be changed without breaking every past `.jes`. The `HashLeaf` and `HashChildren` functions are frozen forever.
- The consistency-proof algorithm is non-trivial (SUBPROOF with LSB stripping); the implementation must be exhaustively tested to catch off-by-one bugs.
- Appending a single event still requires log-depth hash computations, which is marginally more work than a hash chain.

## Pros and cons of the options

### RFC 6962 Merkle tree

- Good: most-reviewed Merkle construction in the security ecosystem
- Good: O(log n) inclusion + consistency proofs, both defined in the RFC
- Good: implementable stdlib-only
- Bad: frozen leaf/interior prefix bytes; any deviation invalidates every past attestation

### Simple hash chain

- Good: trivial to implement, O(1) append
- Bad: cannot produce O(log n) inclusion proofs — verifier must hash every preceding event
- Bad: cannot prove append-only extension at an intermediate checkpoint without replaying; the whole-session replay requirement defeats pre-commitment
- Bad: offers no advantage over a naive "just publish the full log" baseline

### Merkle Mountain Range

- Good: append-only by construction; stable roots as tree grows
- Good: used by OpenTimestamps internally; natural fit for anchoring
- Bad: proofs are less standardized across implementations
- Bad: no direct byte-exact reference in an RFC; consistency-proof semantics are not as well-specified

### Sparse Merkle Tree

- Good: suitable for key/value state commitments
- Bad: the session log is a sequence, not a keyed state; SMT is the wrong shape for this problem
- Bad: larger proof sizes for the insert-only use case

## Validation

- `internal/merkle/rfc6962_test.go` includes the RFC 6962 Appendix A test vectors (SHA-256 hashes of known inputs).
- `TestInclusionAllIndices` covers every leaf index in trees of sizes {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 17, 31, 32, 33}.
- `TestConsistencyAllPairs` covers every (m, n) pair for n ≤ 12.
- `TestInclusionRejectsTamperedProof` and `TestConsistencyRejectsTamperedProof` verify that flipping any byte of a proof causes rejection.
- The TypeScript verifier (commissioned) must produce identical roots for the same leaf set; any divergence is a conformance failure and blocks acceptance of the TS implementation.

## Links

- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) §2.1
- `internal/merkle/tree.go`, `internal/merkle/inclusion.go`, `internal/merkle/consistency.go`
- `SPEC.md` §Merkle construction
- ADR 0002 (envelope) — the merkle root lives inside the predicate
- ADR 0004 (anchors) — the root is what gets anchored externally
