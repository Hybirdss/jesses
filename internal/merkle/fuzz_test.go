package merkle_test

import (
	"encoding/binary"
	"testing"

	"github.com/Hybirdss/jesses/internal/merkle"
)

// FuzzRootHash_NoPanic drives RootHash with arbitrary leaf-count and
// per-leaf byte content derived from a single fuzz-seed blob.
//
// Decoding strategy: the first 2 bytes choose the leaf count (mod 256
// to bound memory), each subsequent leaf's size is taken as the next
// byte, and that many bytes are consumed as the leaf. If the seed is
// too short for the declared shape we truncate the leaves list — the
// tree must still build.
//
// Invariants:
//   - No panic for any seed shape. RootHash is called on every
//     untrusted audit log at verify time; a crash is a DoS.
//   - Determinism: the same seed always produces the same root.
func FuzzRootHash_NoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 3, 0, 1, 0x41, 2, 0x42, 0x43})
	// Degenerate: very high leaf count, tiny leaves.
	f.Add([]byte{0, 100,
		1, 0x01, 1, 0x02, 1, 0x03, 1, 0x04, 1, 0x05,
		1, 0x06, 1, 0x07, 1, 0x08, 1, 0x09, 1, 0x0a,
	})

	f.Fuzz(func(t *testing.T, seed []byte) {
		leaves := decodeLeaves(seed)
		r1 := merkle.RootHash(leaves)
		r2 := merkle.RootHash(leaves)
		if r1 != r2 {
			t.Fatalf("RootHash non-deterministic on seed %x", seed)
		}
	})
}

// FuzzInclusionProof_RoundTrip asserts the full prove→verify loop is
// self-consistent for every shape the fuzzer can construct:
//
//  1. InclusionProof(m, leaves) succeeds iff 0 <= m < len(leaves).
//  2. The returned proof verifies against the tree root.
//  3. A single-bit flip in any proof element causes rejection.
//  4. Claiming the wrong index m' != m causes rejection.
//
// These four together cover the inclusion-proof invariants that
// RFC 6962 §2.1.1 requires a conformant verifier to hold. A fuzzer
// that finds a seed where any invariant breaks has found either a
// prove bug, a verify bug, or a crypto drift against the RFC — all
// block-release severity.
func FuzzInclusionProof_RoundTrip(f *testing.F) {
	f.Add([]byte{0, 1, 1, 0x41})          // size-1
	f.Add([]byte{1, 2, 1, 0x41, 1, 0x42}) // size-2, m=1
	f.Add([]byte{0, 3, 1, 0x41, 1, 0x42, 1, 0x43})
	f.Add([]byte{4, 8,
		1, 0x40, 1, 0x41, 1, 0x42, 1, 0x43,
		1, 0x44, 1, 0x45, 1, 0x46, 1, 0x47,
	})

	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) < 2 {
			return
		}
		mRaw := int(seed[0])
		leaves := decodeLeaves(seed[1:])
		n := len(leaves)
		if n == 0 {
			return
		}
		m := mRaw % n

		proof, err := merkle.InclusionProof(m, leaves)
		if err != nil {
			// Should only error when m is out of range; we bounded m.
			t.Fatalf("InclusionProof err with m=%d n=%d: %v", m, n, err)
		}

		root := merkle.RootHash(leaves)
		leafHash := merkle.HashLeaf(leaves[m])

		if !merkle.VerifyInclusion(m, n, leafHash, proof, root) {
			t.Fatalf("prove→verify round trip failed: m=%d n=%d", m, n)
		}

		// Tamper: flip one bit in the first proof hash.
		if len(proof) > 0 {
			tampered := make([]merkle.Hash, len(proof))
			copy(tampered, proof)
			tampered[0][0] ^= 0x01
			if merkle.VerifyInclusion(m, n, leafHash, tampered, root) {
				t.Fatalf("tampered proof accepted: m=%d n=%d", m, n)
			}
		}

		// Tamper: claim a different m. This invariant only holds when
		// the leaf at the wrong index is byte-distinct from the leaf
		// at m. If leaves[m] == leaves[wrongM] the leafHash applies
		// to both positions; and if duplication propagates into a
		// shared ancestor subtree the audit path itself is shared.
		// Such seeds are legitimate RFC 6962 behavior, not a bug —
		// skip them rather than over-assert.
		if n > 1 {
			wrongM := (m + 1) % n
			if !bytesEqual(leaves[m], leaves[wrongM]) {
				if merkle.VerifyInclusion(wrongM, n, leafHash, proof, root) {
					t.Fatalf("proof accepted at wrong index: claimed m=%d but proof is for m=%d",
						wrongM, m)
				}
			}
		}
	})
}

// FuzzVerifyInclusion_NoPanic feeds structured-but-arbitrary data
// straight into VerifyInclusion. This is the CRASH-RESISTANCE fuzz:
// given any m, n, proof, root, leaf_hash the verifier must return
// true or false without panicking. Real-world attack: a hostile .jes
// envelope carries a malformed proof designed to index out of bounds
// or trigger an infinite loop. VerifyInclusion is called on every
// provenance citation (G7 path) — a crash blocks verification for
// legit submissions alongside the attacker's.
func FuzzVerifyInclusion_NoPanic(f *testing.F) {
	f.Add(0, 1, []byte{}, []byte{}, []byte{})
	f.Add(1, 8, []byte{0xaa}, []byte{0xbb, 0xcc, 0xdd}, []byte{0xee})
	f.Add(-1, 0, []byte{}, []byte{}, []byte{})
	f.Add(1<<30, 1<<30, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, m, n int, leafHashSeed, proofSeed, rootSeed []byte) {
		// Bound n so the fuzzer cannot make a stray massive allocation
		// via a 2^30 n inside merkle. The invariant we care about is
		// "no panic on malformed input", not "performs well for large
		// n" — the latter is a well-tested path via the conformance
		// suite.
		if n < 0 || n > 1<<16 {
			// Still call it — negative / huge n is a valid probe.
			defer catchPanic(t, "VerifyInclusion", m, n)
			_ = merkle.VerifyInclusion(m, n, hashFromSeed(leafHashSeed),
				proofFromSeed(proofSeed), hashFromSeed(rootSeed))
			return
		}
		defer catchPanic(t, "VerifyInclusion", m, n)
		_ = merkle.VerifyInclusion(m, n, hashFromSeed(leafHashSeed),
			proofFromSeed(proofSeed), hashFromSeed(rootSeed))
	})
}

// catchPanic is a deferred helper that turns a panic in the fuzzed
// call into a test failure with the inputs that triggered it. Without
// it, a panic in a goroutine spawned by the fuzzer is harder to trace
// back to the specific seed.
func catchPanic(t *testing.T, fn string, args ...any) {
	if r := recover(); r != nil {
		t.Fatalf("%s panicked with args %v: %v", fn, args, r)
	}
}

// hashFromSeed derives a merkle.Hash from arbitrary seed bytes by
// zero-padding or truncating to 32 bytes. This is the fuzz-side
// equivalent of "treat whatever bytes came in as a hash" — the
// verifier must not care how the bytes were generated.
func hashFromSeed(seed []byte) merkle.Hash {
	var h merkle.Hash
	copy(h[:], seed)
	return h
}

// proofFromSeed splits the seed into 32-byte chunks, up to 40 levels
// deep (enough to cover any realistic tree; a tree of 2^40 leaves
// is 1e12 entries, two orders past every realistic audit log).
func proofFromSeed(seed []byte) []merkle.Hash {
	const maxLevels = 40
	var out []merkle.Hash
	for i := 0; i+32 <= len(seed) && len(out) < maxLevels; i += 32 {
		var h merkle.Hash
		copy(h[:], seed[i:i+32])
		out = append(out, h)
	}
	return out
}

// bytesEqual is the standard slice comparison, written out to avoid
// pulling "bytes" into the fuzz test for one function.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// decodeLeaves parses seed bytes into a [][]byte suitable for
// RootHash/InclusionProof. Layout:
//
//	bytes 0..1 — uint16 leaf count (capped at 64 to bound memory)
//	then for each leaf:
//	  1 byte  — length L (0..255)
//	  L bytes — leaf data
//
// If the seed runs short, decoding stops and we return the partial
// list. An empty list is legal (RootHash handles n=0).
func decodeLeaves(seed []byte) [][]byte {
	const maxLeaves = 64
	if len(seed) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(seed[:2])) % (maxLeaves + 1)
	offset := 2
	leaves := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if offset >= len(seed) {
			break
		}
		leafLen := int(seed[offset])
		offset++
		if offset+leafLen > len(seed) {
			leafLen = len(seed) - offset
		}
		leaves = append(leaves, append([]byte(nil), seed[offset:offset+leafLen]...))
		offset += leafLen
	}
	return leaves
}
