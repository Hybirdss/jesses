// Package merkle implements RFC 6962 byte-exact Merkle tree construction,
// inclusion proofs, and consistency proofs as specified in Certificate
// Transparency (https://datatracker.ietf.org/doc/html/rfc6962).
//
// Every hash in this package follows the domain-separated scheme in
// RFC 6962 §2.1:
//
//	leaf hash     = SHA-256(0x00 || leaf_data)
//	internal hash = SHA-256(0x01 || left_child_hash || right_child_hash)
//	empty tree    = SHA-256("")
//
// The split point for a tree of size n (where n > 1) is k, the largest power
// of 2 strictly less than n. This produces left subtrees that are always
// complete perfect binary trees.
//
// This package has zero external dependencies beyond the Go standard library.
// The lack of external dependencies is a deliberate design constraint: the
// Merkle tree implementation is the trust anchor for every jesses attestation,
// and its dependency set must be auditable by a single reader in one sitting.
//
// The inclusion and consistency proof algorithms are direct implementations of
// RFC 6962 §2.1.1 and §2.1.2 respectively.
//
// This package is part of the jesses project (see https://jesses.dev).
package merkle
