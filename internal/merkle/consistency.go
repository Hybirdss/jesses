package merkle

import "errors"

// ErrInvalidConsistencyRange is returned when consistency-proof inputs are
// inconsistent (for example, m > n, or a negative tree size).
var ErrInvalidConsistencyRange = errors.New("merkle: invalid consistency proof range")

// ConsistencyProof returns the RFC 6962 §2.1.2 consistency proof between a
// first tree of size m and a second tree of size n (where m <= n), using the
// leaves of the larger tree.
//
// For m == 0 or m == n the proof is the empty slice.
func ConsistencyProof(m, n int, leaves [][]byte) ([]Hash, error) {
	if m < 0 || n < 0 || m > n {
		return nil, ErrInvalidConsistencyRange
	}
	if n != len(leaves) {
		return nil, ErrInvalidConsistencyRange
	}
	if m == 0 || m == n {
		return nil, nil
	}
	hashes := make([]Hash, n)
	for i, leaf := range leaves {
		hashes[i] = HashLeaf(leaf)
	}
	return subproof(m, hashes, true), nil
}

// subproof implements SUBPROOF(m, D[n], b) from RFC 6962 §2.1.2.
//
//	SUBPROOF(m, D[n], true)  = {}                              if m = n
//	SUBPROOF(m, D[n], false) = {MTH(D[n])}                     if m = n
//	SUBPROOF(m, D[n], b)     = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])            if m <= k
//	SUBPROOF(m, D[n], b)     = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])    if m > k
//
// where k is the largest power of 2 less than n.
func subproof(m int, hashes []Hash, b bool) []Hash {
	n := len(hashes)
	if m == n {
		if b {
			return nil
		}
		return []Hash{mth(hashes)}
	}
	k := largestPow2Less(n)
	if m <= k {
		return append(subproof(m, hashes[:k], b), mth(hashes[k:]))
	}
	return append(subproof(m-k, hashes[k:], false), mth(hashes[:k]))
}

// VerifyConsistency verifies a consistency proof between first_root (tree size
// m) and second_root (tree size n), per RFC 6962 §2.1.2 / §2.1.4.2.
//
// Returns true iff the proof demonstrates that the tree of size n is an
// append-only extension of the tree of size m.
func VerifyConsistency(m, n int, firstRoot, secondRoot Hash, proof []Hash) bool {
	switch {
	case m < 0 || n < 0 || m > n:
		return false
	case m == 0:
		// An empty tree is always a prefix of any tree. The proof must be
		// empty and the second root stands on its own — we cannot verify it
		// against anything external here, so we accept any value.
		return len(proof) == 0
	case m == n:
		return len(proof) == 0 && firstRoot == secondRoot
	}

	// Per RFC 6962 §2.1.4.2: if m is a power of 2 and equals a "clean"
	// left-subtree boundary of the tree-of-size-n, then first_root is
	// implicit at the start of the reduction. Otherwise, the first entry of
	// the proof is a prefix hash we fold in from the start.
	fn := m - 1
	sn := n - 1

	// Right-shift both until LSB(fn) is clear. This strips the right-most
	// "always-left" bits from the first tree's position.
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	var fr, sr Hash
	if fn == 0 {
		// m is a perfect power-of-two prefix; first_root is our starting
		// point for both reductions.
		fr = firstRoot
		sr = firstRoot
	} else {
		if len(proof) == 0 {
			return false
		}
		fr = proof[0]
		sr = proof[0]
		proof = proof[1:]
	}

	for _, c := range proof {
		if sn == 0 {
			// More proof entries than the tree accommodates.
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = HashChildren(c, fr)
			sr = HashChildren(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashChildren(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && fr == firstRoot && sr == secondRoot
}
