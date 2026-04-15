package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256hexRaw returns the hex SHA-256 of b.
func sha256hexRaw(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
