package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// mustHex parses a hex string into a Hash; fails the test on error.
func mustHex(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var h Hash
	copy(h[:], b)
	return h
}

// ----------------------------------------------------------------------------
// Tree hash tests
// ----------------------------------------------------------------------------

// TestEmptyTree verifies that MTH(∅) = SHA-256("") per RFC 6962 §2.1.
func TestEmptyTree(t *testing.T) {
	got := RootHash(nil)
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	want := mustHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if got != want {
		t.Errorf("RootHash(nil) = %x, want %x", got, want)
	}
}

// TestHashLeafEmpty verifies HashLeaf(nil) = SHA-256("\x00").
func TestHashLeafEmpty(t *testing.T) {
	got := HashLeaf(nil)
	// SHA-256("\x00") = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
	want := mustHex(t, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
	if got != want {
		t.Errorf("HashLeaf(nil) = %x, want %x", got, want)
	}
}

// TestHashLeafStructural verifies HashLeaf matches an independent SHA-256
// computation with the 0x00 domain-separation prefix.
func TestHashLeafStructural(t *testing.T) {
	data := []byte("the quick brown fox")
	got := HashLeaf(data)

	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var want Hash
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Errorf("HashLeaf mismatch")
	}
}

// TestHashChildrenStructural verifies HashChildren matches an independent
// SHA-256 computation with the 0x01 domain-separation prefix.
func TestHashChildrenStructural(t *testing.T) {
	left := HashLeaf([]byte("a"))
	right := HashLeaf([]byte("b"))
	got := HashChildren(left, right)

	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var want Hash
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Errorf("HashChildren mismatch")
	}
}

// TestRootTwoLeaves verifies MTH for a 2-leaf tree matches the expected
// structural computation.
func TestRootTwoLeaves(t *testing.T) {
	a := []byte("alpha")
	b := []byte("beta")
	got := RootHash([][]byte{a, b})

	want := HashChildren(HashLeaf(a), HashLeaf(b))
	if got != want {
		t.Errorf("RootHash([a,b]) mismatch")
	}
}

// TestRootThreeLeaves verifies the 3-leaf structure: H(H(h0,h1), h2).
func TestRootThreeLeaves(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	c := []byte("c")
	got := RootHash([][]byte{a, b, c})

	h01 := HashChildren(HashLeaf(a), HashLeaf(b))
	want := HashChildren(h01, HashLeaf(c))
	if got != want {
		t.Errorf("RootHash([a,b,c]) mismatch")
	}
}

// TestRootFourLeaves verifies the 4-leaf balanced structure.
func TestRootFourLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	got := RootHash(leaves)

	h01 := HashChildren(HashLeaf(leaves[0]), HashLeaf(leaves[1]))
	h23 := HashChildren(HashLeaf(leaves[2]), HashLeaf(leaves[3]))
	want := HashChildren(h01, h23)
	if got != want {
		t.Errorf("RootHash 4-leaf mismatch")
	}
}

// TestRootFiveLeaves verifies k=4 split for n=5: H(H(H(h0,h1),H(h2,h3)), h4).
func TestRootFiveLeaves(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	got := RootHash(leaves)

	h01 := HashChildren(HashLeaf(leaves[0]), HashLeaf(leaves[1]))
	h23 := HashChildren(HashLeaf(leaves[2]), HashLeaf(leaves[3]))
	h0123 := HashChildren(h01, h23)
	want := HashChildren(h0123, HashLeaf(leaves[4]))
	if got != want {
		t.Errorf("RootHash 5-leaf mismatch")
	}
}

// TestLargestPow2Less verifies the split-point function for representative
// tree sizes including boundary cases.
func TestLargestPow2Less(t *testing.T) {
	cases := []struct {
		n, want int
	}{
		{2, 1}, {3, 2}, {4, 2}, {5, 4}, {6, 4}, {7, 4},
		{8, 4}, {9, 8}, {15, 8}, {16, 8}, {17, 16},
		{31, 16}, {32, 16}, {33, 32}, {1024, 512}, {1025, 1024},
	}
	for _, c := range cases {
		got := largestPow2Less(c.n)
		if got != c.want {
			t.Errorf("largestPow2Less(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

// ----------------------------------------------------------------------------
// Inclusion proof tests
// ----------------------------------------------------------------------------

// TestInclusionAllIndices generates an inclusion proof for every leaf in a
// variety of tree sizes and verifies it against the tree root. Any bug in
// path generation or verification is caught by this exhaustive pass.
func TestInclusionAllIndices(t *testing.T) {
	sizes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 17, 31, 32, 33}
	for _, n := range sizes {
		leaves := makeLeaves(n)
		root := RootHash(leaves)
		for m := 0; m < n; m++ {
			proof, err := InclusionProof(m, leaves)
			if err != nil {
				t.Errorf("n=%d m=%d: InclusionProof error: %v", n, m, err)
				continue
			}
			leafHash := HashLeaf(leaves[m])
			if !VerifyInclusion(m, n, leafHash, proof, root) {
				t.Errorf("n=%d m=%d: VerifyInclusion returned false", n, m)
			}
		}
	}
}

// TestInclusionRejectsWrongLeaf ensures verification fails when the leaf
// hash does not match.
func TestInclusionRejectsWrongLeaf(t *testing.T) {
	leaves := makeLeaves(8)
	root := RootHash(leaves)
	proof, err := InclusionProof(3, leaves)
	if err != nil {
		t.Fatal(err)
	}
	wrong := HashLeaf([]byte("not a real leaf"))
	if VerifyInclusion(3, 8, wrong, proof, root) {
		t.Error("VerifyInclusion accepted a wrong leaf hash")
	}
}

// TestInclusionRejectsWrongIndex ensures verification fails when the index
// does not match.
func TestInclusionRejectsWrongIndex(t *testing.T) {
	leaves := makeLeaves(8)
	root := RootHash(leaves)
	proof, err := InclusionProof(3, leaves)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := HashLeaf(leaves[3])
	if VerifyInclusion(4, 8, leafHash, proof, root) {
		t.Error("VerifyInclusion accepted wrong index")
	}
}

// TestInclusionRejectsTamperedProof ensures any single-byte change in the
// proof path invalidates verification.
func TestInclusionRejectsTamperedProof(t *testing.T) {
	leaves := makeLeaves(8)
	root := RootHash(leaves)
	proof, err := InclusionProof(3, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof")
	}
	proof[0][0] ^= 0xff
	leafHash := HashLeaf(leaves[3])
	if VerifyInclusion(3, 8, leafHash, proof, root) {
		t.Error("VerifyInclusion accepted a tampered proof")
	}
}

// ----------------------------------------------------------------------------
// Consistency proof tests
// ----------------------------------------------------------------------------

// TestConsistencyAllPairs exercises every (m, n) pair for small tree sizes.
// Any regression in either proof generation or verification is caught here.
func TestConsistencyAllPairs(t *testing.T) {
	maxN := 12
	for n := 1; n <= maxN; n++ {
		leaves := makeLeaves(n)
		secondRoot := RootHash(leaves)
		for m := 0; m <= n; m++ {
			firstRoot := RootHash(leaves[:m])
			proof, err := ConsistencyProof(m, n, leaves)
			if err != nil {
				t.Errorf("m=%d n=%d: ConsistencyProof error: %v", m, n, err)
				continue
			}
			if !VerifyConsistency(m, n, firstRoot, secondRoot, proof) {
				t.Errorf("m=%d n=%d: VerifyConsistency returned false", m, n)
			}
		}
	}
}

// TestConsistencyRejectsWrongSecondRoot ensures a forged second root fails
// verification.
func TestConsistencyRejectsWrongSecondRoot(t *testing.T) {
	leaves := makeLeaves(10)
	firstRoot := RootHash(leaves[:4])
	proof, err := ConsistencyProof(4, 10, leaves)
	if err != nil {
		t.Fatal(err)
	}
	var wrong Hash
	for i := range wrong {
		wrong[i] = 0xaa
	}
	if VerifyConsistency(4, 10, firstRoot, wrong, proof) {
		t.Error("VerifyConsistency accepted wrong second root")
	}
}

// TestConsistencyRejectsTamperedProof ensures any single-byte change in the
// proof invalidates verification.
func TestConsistencyRejectsTamperedProof(t *testing.T) {
	leaves := makeLeaves(10)
	firstRoot := RootHash(leaves[:4])
	secondRoot := RootHash(leaves)
	proof, err := ConsistencyProof(4, 10, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof")
	}
	proof[0][0] ^= 0xff
	if VerifyConsistency(4, 10, firstRoot, secondRoot, proof) {
		t.Error("VerifyConsistency accepted a tampered proof")
	}
}

// TestConsistencyEmptyFirstTree verifies m == 0 edge case.
func TestConsistencyEmptyFirstTree(t *testing.T) {
	leaves := makeLeaves(5)
	firstRoot := Hash(sha256.Sum256(nil))
	secondRoot := RootHash(leaves)
	proof, err := ConsistencyProof(0, 5, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Errorf("proof for m=0 should be empty, got %d entries", len(proof))
	}
	if !VerifyConsistency(0, 5, firstRoot, secondRoot, proof) {
		t.Error("VerifyConsistency m=0 rejected empty proof")
	}
}

// TestConsistencyEqualSizes verifies m == n returns an empty proof that
// passes verification only when the roots match.
func TestConsistencyEqualSizes(t *testing.T) {
	leaves := makeLeaves(7)
	root := RootHash(leaves)
	proof, err := ConsistencyProof(7, 7, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Errorf("proof for m=n should be empty")
	}
	if !VerifyConsistency(7, 7, root, root, proof) {
		t.Error("VerifyConsistency m=n rejected identical roots")
	}
	var bogus Hash
	for i := range bogus {
		bogus[i] = 0x11
	}
	if VerifyConsistency(7, 7, root, bogus, proof) {
		t.Error("VerifyConsistency m=n accepted mismatched roots")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func makeLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = []byte{byte(i), byte(i * 3), byte(i * 7)}
	}
	return out
}
