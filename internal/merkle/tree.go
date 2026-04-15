package merkle

import "crypto/sha256"

// RFC 6962 §2.1 domain-separation prefixes.
const (
	// LeafPrefix is prepended to leaf data before hashing.
	LeafPrefix byte = 0x00
	// NodePrefix is prepended to the concatenation of two child hashes.
	NodePrefix byte = 0x01
)

// Hash is a 32-byte SHA-256 digest.
type Hash [32]byte

// HashLeaf computes the RFC 6962 leaf hash for a single entry:
//
//	SHA-256(0x00 || data)
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashChildren computes the RFC 6962 internal-node hash for two child hashes:
//
//	SHA-256(0x01 || left || right)
func HashChildren(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{NodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// RootHash computes MTH(D[n]), the Merkle tree root over a sequence of raw
// leaf data blobs. Per RFC 6962 §2.1, the hash of an empty list is SHA-256("").
func RootHash(leaves [][]byte) Hash {
	if len(leaves) == 0 {
		return Hash(sha256.Sum256(nil))
	}
	hashes := make([]Hash, len(leaves))
	for i, leaf := range leaves {
		hashes[i] = HashLeaf(leaf)
	}
	return mth(hashes)
}

// RootFromLeafHashes computes MTH over already-hashed leaves. Callers use this
// when they already have leaf hashes and want to avoid re-hashing.
func RootFromLeafHashes(hashes []Hash) Hash {
	if len(hashes) == 0 {
		return Hash(sha256.Sum256(nil))
	}
	// Copy to avoid mutating caller's slice (mth operates on a slice but does
	// not mutate in current form; still, defensive).
	cp := make([]Hash, len(hashes))
	copy(cp, hashes)
	return mth(cp)
}

// mth recursively computes MTH(D[n]) from pre-hashed leaves.
//
// Per RFC 6962 §2.1:
//
//	MTH({d(0)})       = leaf hash
//	MTH(D[n]), n > 1  = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//
// where k is the largest power of 2 strictly less than n. This ensures the
// left subtree is always a complete perfect binary tree.
func mth(hashes []Hash) Hash {
	if len(hashes) == 1 {
		return hashes[0]
	}
	k := largestPow2Less(len(hashes))
	return HashChildren(mth(hashes[:k]), mth(hashes[k:]))
}

// largestPow2Less returns the largest power of 2 strictly less than n.
// Precondition: n >= 2. For n == 2 the result is 1.
func largestPow2Less(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
