// Package precommit implements the SCT-style session-start
// commitment that makes fabricate-entire-session attacks detectable.
//
// The core idea borrowed from Certificate Transparency: before a
// session emits its first tool-use event, it publishes a
// commitment to a public transparency log (Rekor). The commitment
// binds:
//
//   - session ID           — random UUID, generated once per session
//   - scope hash           — SHA-256 of the canonical scope.txt bytes
//   - attestation pubkey   — the ed25519 public key that will sign
//     the final attestation envelope
//   - timestamp            — RFC3339Nano UTC, truncated to seconds
//
// The receipt Rekor returns (LogIndex + SignedEntryTimestamp) is
// embedded in the final envelope as the Pre-Commit field. A verifier
// that receives the envelope can:
//
//  1. Recompute the commitment from (session_id, scope_hash, pubkey,
//     timestamp) and check it matches what Rekor signed.
//  2. Fetch the entry at LogIndex and cross-check Rekor's signature.
//  3. Know that the session was declared BEFORE any of its events
//     could have been faked — the log is append-only and the entry
//     was signed with an RFC3161-class timestamp by Rekor.
//
// Without this step, an adversary with access to the ed25519 private
// key could fabricate an entire session after the fact (an A3 attack
// in THREAT_MODEL.md). The pre-commitment shifts the trust from
// "trust the submitter's clock" to "trust Rekor's append-only log
// plus the submitter's key discipline at one moment in time."
package precommit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Hybirdss/jesses/internal/rekor"
)

// Receipt is the pre-commitment data that must be included in every
// attestation envelope. It is what Rekor signed and what the verifier
// recomputes.
type Receipt struct {
	// SessionID is the random UUID-shaped identifier assigned at
	// session open.
	SessionID string `json:"session_id"`

	// ScopeHash is the hex-encoded SHA-256 of the canonical
	// scope.txt bytes in effect at session open.
	ScopeHash string `json:"scope_hash"`

	// PubKey is the hex-encoded ed25519 public key of the signer.
	// Callers that want to be fancy can rotate the key mid-session;
	// in v0.1 we do not support rotation.
	PubKey string `json:"pub_key"`

	// Timestamp is the RFC3339 UTC wall-clock time the commitment
	// was computed. Included in the signed body so a verifier can
	// see when the session declared itself.
	Timestamp string `json:"timestamp"`

	// Version pins the precommitment schema so future schema changes
	// are detectable by verifiers. Bump when fields are added.
	Version string `json:"version"`

	// LogEntry is filled by Submit once Rekor has accepted the
	// commitment. The verifier checks the LogEntry's BodyHash
	// against a recomputation of CanonicalBytes(Receipt).
	LogEntry rekor.Entry `json:"log_entry,omitempty"`
}

// Version is the current precommitment schema version. Verifiers
// reject receipts with an unknown version.
const Version = "v0.1"

// Compute builds a Receipt (without LogEntry) from the raw inputs.
// Timestamp is formatted as RFC3339Nano in UTC.
func Compute(sessionID string, scopeBytes, pubKey []byte, at time.Time) Receipt {
	scope := sha256.Sum256(scopeBytes)
	return Receipt{
		SessionID: sessionID,
		ScopeHash: hex.EncodeToString(scope[:]),
		PubKey:    hex.EncodeToString(pubKey),
		Timestamp: at.UTC().Format(time.RFC3339Nano),
		Version:   Version,
	}
}

// CanonicalBytes returns the deterministic serialization of a
// Receipt (excluding LogEntry). This is what Rekor signs and what
// the verifier recomputes — any drift here is a verifier failure.
func CanonicalBytes(r Receipt) ([]byte, error) {
	c := struct {
		SessionID string `json:"session_id"`
		ScopeHash string `json:"scope_hash"`
		PubKey    string `json:"pub_key"`
		Timestamp string `json:"timestamp"`
		Version   string `json:"version"`
	}{r.SessionID, r.ScopeHash, r.PubKey, r.Timestamp, r.Version}
	return json.Marshal(c)
}

// Submit computes the canonical body, uploads it to the Rekor Client,
// and returns the Receipt with LogEntry populated. Session open must
// block on this — every later event references the returned LogIndex.
func Submit(ctx context.Context, c rekor.Client, r Receipt) (Receipt, error) {
	body, err := CanonicalBytes(r)
	if err != nil {
		return r, err
	}
	entry, err := c.Upload(ctx, body)
	if err != nil {
		return r, err
	}
	r.LogEntry = entry
	return r, nil
}

// Verify re-derives the canonical body of a Receipt, recomputes its
// SHA-256, and checks that LogEntry.BodyHash matches. It does NOT
// validate Rekor's signature (that is internal/verify's job) — this
// just proves that the Receipt's data matches what was logged.
func Verify(r Receipt) (bool, error) {
	body, err := CanonicalBytes(r)
	if err != nil {
		return false, err
	}
	want := sha256.Sum256(body)
	return hex.EncodeToString(want[:]) == r.LogEntry.BodyHash, nil
}
