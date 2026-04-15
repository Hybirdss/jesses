package jesses

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Hybirdss/jesses/internal/extractors"
	"github.com/Hybirdss/jesses/internal/policy"
)

// sumSHA256 hashes b and returns lowercase hex. Small helper so the
// public API file can stay focused on types.
func sumSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// identifierFor composes the policy-visible identifier from a
// Destination. Keeps the mapping consistent with the CLI hook.
func identifierFor(d extractors.Destination) string {
	switch {
	case strings.HasPrefix(d.Kind, "path:"):
		return "path:" + d.Path
	case d.Kind == "mcp":
		return d.Host
	}
	if d.Host != "" {
		return d.Host
	}
	return d.Path
}

// namespaceFor returns the policy namespace + value for a
// Destination so policy.Evaluate can be called uniformly.
func namespaceFor(d extractors.Destination) (policy.Namespace, string) {
	switch {
	case strings.HasPrefix(d.Kind, "path:"):
		return policy.NSPath, d.Path
	case d.Kind == "mcp":
		return policy.NSMCP, d.Host
	}
	// Contract shape: <chain>:0x[hex]
	if colon := strings.IndexByte(d.Host, ':'); colon > 0 &&
		strings.HasPrefix(d.Host[colon+1:], "0x") {
		return policy.NSContract, d.Host
	}
	// Repo shape: <org>/<name>
	if slash := strings.IndexByte(d.Host, '/'); slash > 0 &&
		!strings.ContainsRune(d.Host, '.') && !strings.ContainsRune(d.Host, ':') {
		return policy.NSRepo, d.Host
	}
	return policy.NSHost, d.Host
}
