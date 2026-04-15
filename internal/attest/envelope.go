// Package attest constructs and parses in-toto ITE-6 envelopes with
// the jesses.dev action-envelope predicate type.
//
// The wire format follows the in-toto specification v1 exactly:
//
//	{
//	  "payloadType": "application/vnd.in-toto+json",
//	  "payload":     "<base64-encoded Statement>",
//	  "signatures":  [{"keyid":"<hex>","sig":"<base64>"}]
//	}
//
// Statement.predicateType is the stable URI
// "https://jesses.dev/v0.1/action-envelope". A verifier that does
// not recognize the URI MUST refuse to interpret the predicate.
//
// The predicate shape itself is what makes jesses different from
// every other in-toto predicate: it records a session's tool-call
// history summary, Merkle root over the append-only audit log, and
// the Rekor pre-commitment receipt that binds the session's start
// to a transparency log entry. See rules/40-* in the spec for the
// full list of verifier gates that act on these fields.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/precommit"
	"github.com/Hybirdss/jesses/internal/session"
)

// PredicateType is the stable URI identifying jesses action envelopes.
// The path includes the schema version; bump it when the predicate
// shape changes.
const PredicateType = "https://jesses.dev/v0.1/action-envelope"

// PayloadType is the in-toto envelope payload MIME type.
const PayloadType = "application/vnd.in-toto+json"

// StatementType is the in-toto Statement type URI.
const StatementType = "https://in-toto.io/Statement/v1"

// Envelope is the outer DSSE-like structure. jesses uses DSSE's
// payloadType + payload + signatures shape but does NOT apply the
// DSSE PAE (pre-authentication encoding) wrapper in v0.1; the
// signature is over the raw base64-decoded payload bytes. v0.2 will
// migrate to full DSSE PAE for Sigstore compatibility.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64(Statement JSON)
	Signatures  []Signature `json:"signatures"`
}

// Signature pairs a signer keyid with a base64 signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Statement is the in-toto Statement V1 body that gets base64-encoded
// into Envelope.Payload.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject identifies what the envelope attests to. For jesses the
// subject is the session's audit-log merkle root: there is one
// Subject whose Name is the session ID and whose Digest contains a
// sha256 key holding the Merkle root hex.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the jesses-specific payload.
type Predicate struct {
	// SchemaVersion pins the predicate schema so a verifier can fail
	// fast on unknown shapes.
	SchemaVersion string `json:"schema_version"`

	// SessionID is the random ID generated at session open; echoed
	// here so the envelope is self-describing without requiring the
	// verifier to trust Subject.Name alone.
	SessionID string `json:"session_id"`

	// StartedAt / EndedAt are RFC3339Nano UTC wall-clock times.
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`

	// ScopeHash is the hex-encoded SHA-256 of the scope.txt bytes in
	// effect for the whole session. A verifier that wants to evaluate
	// policy has to obtain the scope.txt out-of-band and check the
	// hash matches.
	ScopeHash string `json:"scope_hash"`

	// PubKey is the hex-encoded ed25519 public key that signed this
	// envelope. Embedding it here (in addition to the Signatures
	// KeyID) saves the verifier one key-lookup step.
	PubKey string `json:"pub_key"`

	// Precommit is the Rekor receipt produced at session open.
	// Verifier gate "G3" fetches LogEntry.LogIndex and cross-checks
	// the hash matches.
	Precommit precommit.Receipt `json:"precommit"`

	// MerkleRoot is the hex-encoded RFC 6962 root of the audit log's
	// canonical leaves. Verifier gate "G2" re-computes it from the
	// raw log.
	MerkleRoot string `json:"merkle_root"`

	// LeafCount is the number of leaves in the tree. Included for
	// sanity checking the log's length matches what the envelope
	// claims.
	LeafCount int `json:"leaf_count"`

	// OTSReceipt is the OpenTimestamps calendar receipt. Empty when
	// no OTS client was configured; carries status="pending" until
	// the Bitcoin anchor confirms. Verifier gate G6 is advisory
	// for pending receipts at v0.1.
	OTSReceipt ots.Receipt `json:"ots_receipt,omitempty"`

	// OTSError records why OTS anchoring failed if it was attempted
	// but errored. Verifier-facing explanation; not security-critical
	// at v0.1.
	OTSError string `json:"ots_error,omitempty"`
}

// SchemaVersion is the current jesses predicate schema version.
const SchemaVersion = "v0.1"

// Build takes the session.Finalized bundle produced by Close, builds
// the Statement, signs it, and returns the DSSE-ish envelope.
func Build(f session.Finalized) (Envelope, error) {
	stmt := Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   f.SessionID,
			Digest: map[string]string{"sha256": f.MerkleRoot},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			SchemaVersion: SchemaVersion,
			SessionID:     f.SessionID,
			StartedAt:     f.StartedAt.Format(time.RFC3339Nano),
			EndedAt:       f.EndedAt.Format(time.RFC3339Nano),
			ScopeHash:     f.ScopeHash,
			PubKey:        hex.EncodeToString(f.PubKey),
			Precommit:     f.Precommit,
			MerkleRoot:    f.MerkleRoot,
			LeafCount:     f.LeafCount,
			OTSReceipt:    f.OTSReceipt,
			OTSError:      f.OTSError,
		},
	}
	body, err := json.Marshal(stmt)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(f.PrivKey, body)
	keyID := sha256.Sum256(f.PubKey)
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures: []Signature{{
			KeyID: hex.EncodeToString(keyID[:]),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

// Parse decodes an envelope's payload back into a Statement. It does
// NOT verify signatures — that is the verify package's job.
func Parse(env Envelope) (Statement, []byte, error) {
	if env.PayloadType != PayloadType {
		return Statement{}, nil, errors.New("attest: unknown payload type")
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, nil, err
	}
	var stmt Statement
	if err := json.Unmarshal(body, &stmt); err != nil {
		return Statement{}, nil, err
	}
	return stmt, body, nil
}

// WriteFile marshals an envelope to indented JSON and writes it to
// path. Used by cmd/jesses when finalizing a session to a .jes file.
func WriteFile(path string, env Envelope) error {
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, out)
}

// ReadFile loads an envelope from a .jes file on disk.
func ReadFile(path string) (Envelope, error) {
	raw, err := readFile(path)
	if err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}
