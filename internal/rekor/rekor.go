// Package rekor defines the minimal client surface jesses uses to
// commit and retrieve attestation entries from a Rekor transparency
// log.
//
// For v0.1 the package ships with an in-memory FakeClient for tests
// and a real HTTP Client that speaks Sigstore Rekor v2's JSON API
// (rekor.sigstore.dev by default, overridable per environment). The
// Client interface is what every downstream caller takes as a
// dependency — this keeps the session and verify paths free of HTTP
// plumbing and makes offline tests fast.
//
// Deliberately NOT in scope here:
//   - Merkle inclusion proof verification — delegated to
//     internal/merkle using the root returned by the Rekor API.
//   - Rekor shard discovery / witness cosigning — v0.2 work.
//   - Upload retry backoff — wrapped by the session layer.
package rekor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Entry is a single record stored in a Rekor log. The fields map to
// the Rekor v2 API response shape, trimmed to what jesses needs.
//
// LogIndex is the ever-increasing integer position the entry holds
// in the log. LogID identifies the specific log shard (a 32-byte
// SHA-256 of the log's public key, hex-encoded).
//
// BodyHash is the SHA-256 of the canonical entry body that Rekor
// signed; jesses recomputes this locally during verification.
//
// SignedEntryTimestamp (SET) is the Rekor signer's attestation that
// BodyHash was incorporated at LogIndex at the given SignedAt.
type Entry struct {
	LogIndex             int64     `json:"log_index"`
	LogID                string    `json:"log_id"`
	BodyHash             string    `json:"body_hash"` // hex of SHA-256
	SignedAt             time.Time `json:"signed_at"`
	SignedEntryTimestamp []byte    `json:"signed_entry_timestamp"`

	// Optional: the actual body (rare — Rekor clients usually fetch
	// on demand). Kept as raw base64 to avoid re-serialization drift.
	BodyBase64 string `json:"body_base64,omitempty"`
}

// Client is the slim surface jesses uses against a Rekor server.
// Implementations are swappable: a real HTTP client talks to
// rekor.sigstore.dev; the FakeClient records everything in memory
// for tests.
type Client interface {
	// Upload commits a canonical entry body to the log and returns
	// the resulting Entry with LogIndex filled in. The body must be
	// the already-canonicalized bytes that downstream verification
	// will re-hash; this function does NOT re-serialize it.
	Upload(ctx context.Context, body []byte) (Entry, error)

	// Fetch returns the Entry at LogIndex. Used during verification.
	Fetch(ctx context.Context, logIndex int64) (Entry, error)
}

// HTTPClient speaks Rekor v2's JSON API over HTTPS.
//
// Baseline: https://rekor.sigstore.dev for the public Sigstore
// instance. Enterprise deployments point Base at a self-hosted shard.
type HTTPClient struct {
	Base string
	HTTP *http.Client
}

// NewHTTPClient returns a client pointed at base with a 20-second
// default timeout. Caller may override HTTP for testing or custom
// transports.
func NewHTTPClient(base string) *HTTPClient {
	return &HTTPClient{
		Base: base,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

// Upload posts the body to /api/v2/log/entries and decodes the
// canonical response shape.
func (c *HTTPClient) Upload(ctx context.Context, body []byte) (Entry, error) {
	u := c.Base + "/api/v2/log/entries"
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return Entry{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Entry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return Entry{}, fmt.Errorf("rekor: upload status %d: %s", resp.StatusCode, string(b))
	}
	var raw struct {
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
		IntegratedTime int64  `json:"integratedTime"`
		Verification   struct {
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Entry{}, err
	}
	set, _ := base64.StdEncoding.DecodeString(raw.Verification.SignedEntryTimestamp)
	return Entry{
		LogIndex:             raw.LogIndex,
		LogID:                raw.LogID,
		BodyHash:             hex.EncodeToString(hashSHA256(body)),
		SignedAt:             time.Unix(raw.IntegratedTime, 0).UTC(),
		SignedEntryTimestamp: set,
	}, nil
}

// Fetch retrieves an entry by log index.
func (c *HTTPClient) Fetch(ctx context.Context, logIndex int64) (Entry, error) {
	u := fmt.Sprintf("%s/api/v2/log/entries?logIndex=%d", c.Base, logIndex)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return Entry{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Entry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Entry{}, fmt.Errorf("rekor: fetch status %d", resp.StatusCode)
	}
	var raw struct {
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Entry{}, err
	}
	body, _ := base64.StdEncoding.DecodeString(raw.Body)
	return Entry{
		LogIndex:   raw.LogIndex,
		LogID:      raw.LogID,
		BodyHash:   hex.EncodeToString(hashSHA256(body)),
		SignedAt:   time.Unix(raw.IntegratedTime, 0).UTC(),
		BodyBase64: raw.Body,
	}, nil
}

// FakeClient is a deterministic in-memory Client for tests and for
// offline CI flows. Upload assigns ascending log indices; Fetch
// retrieves any prior Upload.
type FakeClient struct {
	mu      sync.Mutex
	entries []Entry
	logID   string
}

// NewFakeClient returns a FakeClient with a fixed LogID. Tests can
// rely on LogID being the same across runs so goldens stay stable.
func NewFakeClient() *FakeClient {
	return &FakeClient{logID: "fake-log-0000000000000000000000000000000000000000000000000000000000000000"}
}

// Upload records body in the fake log.
func (f *FakeClient) Upload(_ context.Context, body []byte) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := int64(len(f.entries))
	e := Entry{
		LogIndex:   idx,
		LogID:      f.logID,
		BodyHash:   hex.EncodeToString(hashSHA256(body)),
		SignedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(idx) * time.Second),
		BodyBase64: base64.StdEncoding.EncodeToString(body),
	}
	f.entries = append(f.entries, e)
	return e, nil
}

// Fetch retrieves a previously uploaded entry by index.
func (f *FakeClient) Fetch(_ context.Context, logIndex int64) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if logIndex < 0 || logIndex >= int64(len(f.entries)) {
		return Entry{}, errors.New("rekor: log index out of range")
	}
	return f.entries[logIndex], nil
}

// hashSHA256 is a small helper that avoids importing crypto/sha256 at
// the top of this file (keeps the public API block at the top clean).
func hashSHA256(b []byte) []byte {
	h := sha256Fresh()
	h.Write(b)
	return h.Sum(nil)
}
