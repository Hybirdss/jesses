package merkle

import "errors"

// ErrIndexOutOfRange is returned when a leaf index is outside the tree.
var ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")

// InclusionProof returns the audit path for the leaf at index m in a tree
// built from the given leaf data, per RFC 6962 §2.1.1 (PATH algorithm).
//
// The returned path is ordered from leaf-adjacent to root-adjacent. Empty path
// means the leaf is the only entry in a size-1 tree.
func InclusionProof(m int, leaves [][]byte) ([]Hash, error) {
	n := len(leaves)
	if n == 0 {
		return nil, ErrIndexOutOfRange
	}
	if m < 0 || m >= n {
		return nil, ErrIndexOutOfRange
	}
	hashes := make([]Hash, n)
	for i, leaf := range leaves {
		hashes[i] = HashLeaf(leaf)
	}
	return path(m, hashes), nil
}

// path implements PATH(m, D[n]) from RFC 6962 §2.1.1.
//
//	PATH(0, {d(0)}) = {}
//	For n > 1:
//	  if m < k:  PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
//	  else:      PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])
//
// where k = largest power of 2 less than n.
func path(m int, hashes []Hash) []Hash {
	n := len(hashes)
	if n == 1 {
		return nil
	}
	k := largestPow2Less(n)
	if m < k {
		return append(path(m, hashes[:k]), mth(hashes[k:]))
	}
	return append(path(m-k, hashes[k:]), mth(hashes[:k]))
}

// VerifyInclusion verifies that leafHash is at index m in a tree of size n
// with the given root, using the provided audit path.
//
// Implements the iterative verification procedure from RFC 6962 §2.1.1.2.
func VerifyInclusion(m, n int, leafHash Hash, proof []Hash, root Hash) bool {
	if n <= 0 || m < 0 || m >= n {
		return false
	}
	if n == 1 {
		return len(proof) == 0 && leafHash == root
	}

	fn := m
	sn := n - 1
	r := leafHash

	for _, c := range proof {
		if sn == 0 {
			// Proof has more entries than the tree accommodates.
			return false
		}
		if fn&1 == 1 || fn == sn {
			// Current position is a right child, or we are on the right-most
			// path at this level: combine with c as the LEFT sibling.
			r = HashChildren(c, r)
			// Strip trailing "always-left" positions.
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			// Current position is a left child: combine with c as the RIGHT
			// sibling.
			r = HashChildren(r, c)
		}
		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && r == root
}
