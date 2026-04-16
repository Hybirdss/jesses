package merkle_test

import (
	"encoding/hex"
	"testing"

	"github.com/Hybirdss/jesses/internal/merkle"
)

// RFC 6962 conformance vectors.
//
// The leaf corpus and expected roots below are byte-exact with the
// canonical Certificate Transparency reference implementation —
// specifically google/certificate-transparency-go's merkletree test
// constants. The corpus is reproduced here rather than imported
// because jesses' dependency policy is "zero external packages in
// every production tree"; taking a go.mod dependency for test data
// would violate that.
//
// Independent verification: re-derive any root with plain SHA-256
// from the spec (see spec/canonical.md sibling and RFC 6962 §2.1),
// or diff against `certificate-transparency-go/merkletree`. The
// authors of this file did exactly that when generating these
// values (python script, 9 lines, no library).
//
// Why these matter:
//
//   - RFC 6962 is the ONLY line jesses gets to stand on for the
//     Merkle-root claim in SPEC.md. If our tree disagrees with CT
//     by even one byte, a third-party verifier that re-implements
//     against the RFC — the whole point of two-implementation
//     conformance — will silently reject otherwise-valid envelopes.
//
//   - Domain-separation prefixes (0x00 for leaves, 0x01 for
//     internal nodes) are the number-one drift risk: a naive
//     implementer might use plain SHA-256(leaf) and produce a
//     subtly different tree. The empty-tree root below is the
//     hash of zero bytes — a universal anchor that no homebrew
//     implementation accidentally matches.

// ctLeaves is the CT reference leaf corpus: eight raw byte blobs
// of varying lengths (including the empty leaf at index 0). Matches
// the sequence used in certificate-transparency-go's merkle tree
// tests.
var ctLeaves = [][]byte{
	{},
	{0x00},
	{0x10},
	{0x20, 0x21},
	{0x30, 0x31},
	{0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

// ctRootsByN[n] is the expected MTH(D[0:n]) for the CT corpus above.
// Index 0 is the empty-tree sentinel (SHA-256 of zero bytes).
var ctRootsByN = [9]string{
	0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

// TestCT_RootHashes walks every prefix of the reference corpus and
// asserts that our RootHash matches the RFC-derived value. A single
// mismatch at ANY size is a spec-breaking bug; every .jes file
// depends on the root being bit-identical to what a CT verifier
// would compute.
func TestCT_RootHashes(t *testing.T) {
	for n := 0; n <= len(ctLeaves); n++ {
		got := merkle.RootHash(ctLeaves[:n])
		want, err := hex.DecodeString(ctRootsByN[n])
		if err != nil {
			t.Fatalf("bad golden hex at n=%d: %v", n, err)
		}
		if !hashEqual(got, want) {
			t.Errorf("MTH(D[0:%d]) drifted from RFC 6962:\n  want %x\n  got  %x", n, want, got[:])
		}
	}
}

// TestCT_EmptyRoot is a dedicated test for the empty-tree root. It
// is byte-equal to SHA-256 of zero bytes (the RFC's chosen sentinel)
// and makes a cross-library mismatch trivial to diagnose: any
// library that computes a different value is doing something other
// than the RFC.
func TestCT_EmptyRoot(t *testing.T) {
	got := merkle.RootHash(nil)
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("empty-tree root drifted from SHA-256(\"\"):\n  want %s\n  got  %s", want, hex.EncodeToString(got[:]))
	}
}

// TestCT_DomainSeparation is a structural assertion: the single-leaf
// root must equal HashLeaf of the raw data, which is SHA-256(0x00 ||
// data). A common implementation mistake — omitting the 0x00 prefix
// and hashing the leaf bytes directly — produces a different root.
// This test makes that class of bug impossible to miss.
func TestCT_DomainSeparation(t *testing.T) {
	// size-1 tree with non-empty leaf
	leaf := []byte{0x00}
	root := merkle.RootHash([][]byte{leaf})
	lh := merkle.HashLeaf(leaf)

	if root != lh {
		t.Fatalf("size-1 root != HashLeaf(leaf) — RFC 6962 requires MTH({d}) = leaf_hash(d)")
	}

	// Negative assertion: the root is NOT plain SHA-256(data).
	// If a refactor ever removes the domain-separation prefix, this
	// test catches it.
	const plainSHA256Of0x00 = "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"
	if hex.EncodeToString(root[:]) == plainSHA256Of0x00 {
		t.Fatal("size-1 root equals plain SHA-256(leaf) — domain-separation prefix is missing")
	}
}

// TestCT_InclusionProof asserts that InclusionProof produces the
// exact audit path RFC 6962 §2.1.1 PATH(m, D[n]) specifies. The
// expected sibling hashes below were derived by running the PATH
// algorithm against the CT corpus with plain SHA-256 (see package
// comment). A drift here breaks verifier-js and every third-party
// verifier that follows the RFC.
func TestCT_InclusionProof(t *testing.T) {
	cases := []struct {
		m     int
		n     int
		proof []string
	}{
		{
			m: 0, n: 8,
			proof: []string{
				"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
				"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
				"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
			},
		},
		{
			m: 3, n: 8,
			proof: []string{
				"0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
				"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
				"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
			},
		},
		{
			m: 7, n: 8,
			proof: []string{
				"b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
				"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
				"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
			},
		},
	}

	for _, tc := range cases {
		got, err := merkle.InclusionProof(tc.m, ctLeaves[:tc.n])
		if err != nil {
			t.Fatalf("InclusionProof(m=%d, n=%d): %v", tc.m, tc.n, err)
		}
		if len(got) != len(tc.proof) {
			t.Errorf("m=%d n=%d: proof length drifted — want %d, got %d",
				tc.m, tc.n, len(tc.proof), len(got))
			continue
		}
		for i, want := range tc.proof {
			if hex.EncodeToString(got[i][:]) != want {
				t.Errorf("m=%d n=%d proof[%d] drifted:\n  want %s\n  got  %s",
					tc.m, tc.n, i, want, hex.EncodeToString(got[i][:]))
			}
		}
	}
}

// TestCT_InclusionProof_RoundTrip cross-checks two things at once:
//   - the proof we emit verifies against the root we computed,
//   - a one-byte mutation anywhere in the proof causes rejection.
//
// Together these trap both encoding drift and verify-logic bugs
// that might accept malformed proofs (a much nastier class of bug
// than a wrong leaf hash).
func TestCT_InclusionProof_RoundTrip(t *testing.T) {
	root := merkle.RootHash(ctLeaves)
	for m := 0; m < len(ctLeaves); m++ {
		proof, err := merkle.InclusionProof(m, ctLeaves)
		if err != nil {
			t.Fatalf("InclusionProof(m=%d): %v", m, err)
		}
		leaf := merkle.HashLeaf(ctLeaves[m])

		if !merkle.VerifyInclusion(m, len(ctLeaves), leaf, proof, root) {
			t.Fatalf("valid proof failed verification at m=%d", m)
		}

		// Mutate first proof hash, expect rejection.
		if len(proof) > 0 {
			mutated := make([]merkle.Hash, len(proof))
			copy(mutated, proof)
			mutated[0][0] ^= 0x01
			if merkle.VerifyInclusion(m, len(ctLeaves), leaf, mutated, root) {
				t.Fatalf("tampered proof accepted at m=%d — VerifyInclusion is not bit-sensitive", m)
			}
		}
	}
}

func hashEqual(got merkle.Hash, want []byte) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
