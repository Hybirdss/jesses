package rekor

import (
	"crypto/sha256"
	"hash"
)

// sha256Fresh returns a new SHA-256 hasher. It exists as its own
// tiny helper so rekor.go can stay focused on the Client surface.
func sha256Fresh() hash.Hash {
	return sha256.New()
}
