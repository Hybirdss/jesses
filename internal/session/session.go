// Package session ties the audit writer, Merkle tree, precommit, and
// signing key into a single Open → Append → Close lifecycle.
//
// A Session:
//  1. On Open, generates a UUID, hashes the scope, pre-commits to
//     Rekor (blocking), and writes the receipt into the audit log as
//     event 0.
//  2. On Append, appends a canonical Event to the audit writer and
//     retains its leaf hash for later Merkle root computation.
//  3. On Close, computes the final Merkle root, builds an in-toto
//     ITE-6 envelope containing (precommit receipt, merkle root, leaf
//     count, session metadata), signs the envelope body with ed25519,
//     and returns the envelope to the caller.
//
// What Close does NOT do: it does NOT upload the final envelope to
// Rekor or OpenTimestamps. Those are the attestation submitter's job
// (see cmd/jesses), because batching / throttling belongs at the
// CLI layer, not inside the session primitive.
package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/merkle"
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/precommit"
	"github.com/Hybirdss/jesses/internal/rekor"
)

// Session owns the mutable state of an in-progress attestation
// session. Only one Session should be active per audit-log path.
type Session struct {
	ID        string
	StartedAt time.Time
	ScopeHash string
	PubKey    ed25519.PublicKey
	privKey   ed25519.PrivateKey
	writer    *audit.Writer
	leafs     []merkle.Hash
	precommit precommit.Receipt
	ots       ots.Client
	seq       uint64
	closed    bool
}

// Config is the open-time configuration for a Session.
type Config struct {
	// LogPath is the path to the audit log file that the session
	// will append to. The writer is opened in append mode.
	LogPath string

	// ScopeBytes is the raw bytes of the scope.txt in effect at
	// session open. Its SHA-256 is pre-committed and can never change
	// mid-session; swap-policy attacks are prevented by this binding.
	ScopeBytes []byte

	// PrivateKey is the ed25519 private key the session uses to sign
	// the final envelope. In production this comes from a TPM or HSM
	// (v0.3); for v0.1 software keys are the baseline.
	PrivateKey ed25519.PrivateKey

	// Rekor is the transparency-log client. Pre-commit upload
	// happens inline during Open. Production callers pass
	// rekor.NewHTTPClient("https://rekor.sigstore.dev"); tests pass
	// rekor.NewFakeClient().
	Rekor rekor.Client

	// OTS is the OpenTimestamps client. Optional at v0.1 — a nil OTS
	// client means the session skips Bitcoin anchoring and the final
	// envelope's OTS field stays empty. When present, session.Close
	// submits the Merkle root digest and embeds the pending receipt
	// in the returned Finalized.
	OTS ots.Client

	// Now returns the current time. Tests override this for
	// deterministic timestamps in golden envelopes.
	Now func() time.Time

	// OverrideID pins the session ID to a known value. Only used by
	// spec-vector generation and tests that want byte-exact goldens.
	// Empty means "generate a fresh random ID", which is the
	// production path.
	OverrideID string
}

// Open starts a new session. Steps:
//
//  1. Generate a random session ID.
//  2. Open the audit writer for append.
//  3. Build the precommit Receipt from (session_id, scope_hash,
//     pubkey, timestamp) and upload it to Rekor.
//  4. Write the Receipt into the audit log as event 0 (seq=0, tool=
//     "jesses.precommit").
//
// If Rekor upload fails, Open returns the error WITHOUT creating the
// log file — a session that cannot pre-commit has zero security
// value. Callers must handle the error; there is deliberately no
// "skip pre-commit" flag.
func Open(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("session: invalid private key length")
	}
	if cfg.Rekor == nil {
		return nil, errors.New("session: Rekor client required (pre-commitment is mandatory)")
	}

	id := cfg.OverrideID
	var err error
	if id == "" {
		id, err = randomSessionID()
		if err != nil {
			return nil, err
		}
	}

	pub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	scope := sha256.Sum256(cfg.ScopeBytes)
	startedAt := cfg.Now()

	receipt := precommit.Compute(id, cfg.ScopeBytes, pub, startedAt)
	receipt, err = precommit.Submit(ctx, cfg.Rekor, receipt)
	if err != nil {
		return nil, fmt.Errorf("session: rekor pre-commit failed: %w", err)
	}

	writer, err := audit.NewWriter(cfg.LogPath)
	if err != nil {
		return nil, err
	}

	s := &Session{
		ID:        id,
		StartedAt: startedAt,
		ScopeHash: hex.EncodeToString(scope[:]),
		PubKey:    pub,
		privKey:   cfg.PrivateKey,
		writer:    writer,
		precommit: receipt,
		ots:       cfg.OTS,
	}

	// Event 0 records the pre-commitment itself so the verifier can
	// follow a single timeline inside the audit log rather than
	// treating pre-commitment as an external artifact.
	ev := audit.Event{
		Seq:       0,
		TS:        startedAt.Format(time.RFC3339Nano),
		Tool:      "jesses.precommit",
		InputHash: receipt.LogEntry.BodyHash,
		Decision:  "commit",
		Reason:    "session pre-commitment",
		PolicyRef: s.ScopeHash,
	}
	if err := s.appendRaw(ev); err != nil {
		writer.Close()
		return nil, err
	}
	return s, nil
}

// Append records one tool-use event. Seq is assigned here so callers
// do not have to track it.
func (s *Session) Append(ev audit.Event) error {
	if s.closed {
		return errors.New("session: already closed")
	}
	ev.Seq = s.seq
	return s.appendRaw(ev)
}

// appendRaw writes an Event to the log and updates the Merkle leaf
// accumulator. Called from Open for event 0 and from Append for the
// rest; shared path keeps leaf order consistent.
func (s *Session) appendRaw(ev audit.Event) error {
	if err := s.writer.Append(ev); err != nil {
		return err
	}
	canon, err := audit.CanonicalJSON(ev)
	if err != nil {
		return err
	}
	s.leafs = append(s.leafs, merkle.HashLeaf(canon))
	s.seq = ev.Seq + 1
	return nil
}

// Close finalizes the session. No further Append is allowed.
//
// When an OTS client is configured, Close submits the final Merkle
// root digest to the OpenTimestamps calendar and embeds the pending
// receipt in the returned Finalized. OTS failures are non-fatal at
// v0.1 (Rekor carries the mandatory pre-commit; OTS is
// complementary) — the Finalized still comes back with an empty
// OTSReceipt and the caller can log the error.
func (s *Session) Close(ctx context.Context) (Finalized, error) {
	if s.closed {
		return Finalized{}, errors.New("session: already closed")
	}
	s.closed = true
	if err := s.writer.Close(); err != nil {
		return Finalized{}, err
	}
	root := merkle.RootFromLeafHashes(s.leafs)

	fin := Finalized{
		SessionID:  s.ID,
		StartedAt:  s.StartedAt,
		EndedAt:    time.Now().UTC(),
		ScopeHash:  s.ScopeHash,
		PubKey:     s.PubKey,
		PrivKey:    s.privKey,
		MerkleRoot: hex.EncodeToString(root[:]),
		LeafCount:  len(s.leafs),
		Precommit:  s.precommit,
	}

	if s.ots != nil {
		receipt, err := s.ots.Submit(ctx, root[:])
		if err != nil {
			fin.OTSError = err.Error()
		} else {
			fin.OTSReceipt = receipt
		}
	}
	return fin, nil
}

// Finalized is the immutable bundle produced by Close. cmd/jesses
// uses this to build the ITE-6 envelope.
type Finalized struct {
	SessionID  string
	StartedAt  time.Time
	EndedAt    time.Time
	ScopeHash  string
	PubKey     ed25519.PublicKey
	PrivKey    ed25519.PrivateKey
	MerkleRoot string
	LeafCount  int
	Precommit  precommit.Receipt

	// OTSReceipt is populated when an OTS client was configured on
	// the session. Empty when OTS was not configured or when the
	// calendar submission failed (OTSError explains why).
	OTSReceipt ots.Receipt
	OTSError   string
}

// randomSessionID returns a 16-byte random ID in lowercase hex. It
// is not a full UUIDv4 (no version/variant bits) because jesses does
// not need the structured semantics; raw random is simpler and still
// collision-resistant.
func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
