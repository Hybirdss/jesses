// Package ots is the minimal OpenTimestamps client surface jesses
// uses to anchor a session's Merkle root to the Bitcoin blockchain.
//
// The protocol has two phases:
//
//  1. Submit — POST the 32-byte SHA-256 digest to one or more OTS
//     calendar servers. The server immediately aggregates the digest
//     into a pending batch and returns a receipt that points at a
//     future Bitcoin transaction (typically confirmed within 10-60
//     minutes).
//
//  2. Upgrade — after the aggregation batch's merkle root lands in a
//     Bitcoin block, the server can return a complete proof that
//     binds the original digest to the block header via a chain of
//     hashes. This upgrade is what gives the OTS receipt its
//     blockchain-grade timestamp property.
//
// For v0.1 jesses implements phase 1 only and embeds the pending
// receipt in the attestation envelope. Phase 2 is a future concern:
// a verifier that sees a pending receipt treats G6 as advisory. When
// the upgrade path ships (v0.1.1), a verifier will fetch the full
// proof and upgrade G6 from advisory to mandatory-when-present.
//
// The Sigstore trust path (Rekor, G3) is mandatory from day one —
// OTS is complementary proof, not a replacement. A verifier that
// only accepts Rekor gates is still cryptographically sound.
package ots

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Receipt is the OTS calendar server's pending proof. At v0.1 this
// is just the opaque blob the server returns plus enough metadata to
// upgrade it later.
type Receipt struct {
	// CalendarURL is the server that issued this receipt.
	CalendarURL string `json:"calendar_url"`

	// Digest is the hex-encoded SHA-256 of the data that was anchored.
	Digest string `json:"digest"`

	// ReceiptBytes is the server's pending proof, base64-encoded. A
	// future Upgrade call feeds this back to the calendar to fetch
	// the completed proof.
	ReceiptBytes string `json:"receipt_bytes"`

	// SubmittedAt is the client-side wall-clock time at submission.
	SubmittedAt time.Time `json:"submitted_at"`

	// Status is one of "pending" or "confirmed". Pending receipts
	// have not yet been upgraded to a final Bitcoin-anchored proof.
	Status string `json:"status"`
}

// Client is the slim surface jesses takes as a dependency. As with
// rekor.Client, the interface exists so production code takes a
// FakeClient during tests and offline CI.
type Client interface {
	// Submit anchors the given 32-byte digest to the calendar and
	// returns a pending Receipt. Called once per session during
	// session.Close; the returned receipt is embedded in the
	// attestation envelope.
	Submit(ctx context.Context, digest []byte) (Receipt, error)
}

// HTTPClient talks to an OpenTimestamps calendar server over HTTPS.
// The public default is https://alice.btc.calendar.opentimestamps.org
// which is free and does not require authentication.
type HTTPClient struct {
	Calendar string
	HTTP     *http.Client
}

// NewHTTPClient returns a client pointed at the given calendar base
// URL with a 10-second default timeout.
func NewHTTPClient(calendar string) *HTTPClient {
	return &HTTPClient{
		Calendar: calendar,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

// DefaultCalendar is the public calendar used when no custom URL is
// provided. Operated by the OpenTimestamps project.
const DefaultCalendar = "https://alice.btc.calendar.opentimestamps.org"

// Submit POSTs the digest to /digest and returns the server's
// pending receipt. Errors are wrapped with the calendar URL so a
// triage reading verification output can see which server failed.
func (c *HTTPClient) Submit(ctx context.Context, digest []byte) (Receipt, error) {
	if len(digest) != 32 {
		return Receipt{}, errors.New("ots: digest must be 32 bytes (SHA-256)")
	}
	u := c.Calendar + "/digest"
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(digest))
	if err != nil {
		return Receipt{}, err
	}
	req.Header.Set("Content-Type", "application/vnd.opentimestamps.v1")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("ots: submit to %s: %w", c.Calendar, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return Receipt{}, fmt.Errorf("ots: %s status %d: %s", c.Calendar, resp.StatusCode, string(b))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		CalendarURL:  c.Calendar,
		Digest:       hexLower(digest),
		ReceiptBytes: base64.StdEncoding.EncodeToString(body),
		SubmittedAt:  time.Now().UTC(),
		Status:       "pending",
	}, nil
}

// FakeClient records submissions in memory. Deterministic digest-
// based receipt bytes so goldens stay stable.
type FakeClient struct {
	mu    sync.Mutex
	calls [][]byte
}

// NewFakeClient returns an in-memory OTS client.
func NewFakeClient() *FakeClient { return &FakeClient{} }

// Submit records the digest and returns a synthetic Receipt. Useful
// for E2E tests without network.
func (f *FakeClient) Submit(_ context.Context, digest []byte) (Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]byte(nil), digest...))
	return Receipt{
		CalendarURL:  "fake://ots",
		Digest:       hexLower(digest),
		ReceiptBytes: base64.StdEncoding.EncodeToString(append([]byte("fake-ots:"), digest...)),
		SubmittedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:       "pending",
	}, nil
}

// Calls returns the digests that have been submitted. Tests use it
// to assert that session.Close anchored the expected root.
func (f *FakeClient) Calls() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]byte(nil), c...)
	}
	return out
}

// hexLower is a tiny helper avoiding an encoding/hex import at the
// top of the file.
func hexLower(b []byte) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, len(b)*2)
	for i, c := range b {
		buf[i*2] = hex[c>>4]
		buf[i*2+1] = hex[c&0xf]
	}
	return string(buf)
}
