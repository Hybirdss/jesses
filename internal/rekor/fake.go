//go:build !production

package rekor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// FakeClient is a deterministic in-memory Client for tests and for
// offline CI flows. Upload assigns ascending log indices; Fetch
// retrieves any prior Upload.
//
// Build-tag gated: compiled only when the `production` tag is NOT
// set. Release binaries built with `-tags=production` do not contain
// this symbol, so operators cannot accidentally (or an attacker
// cannot maliciously) ship a release that silently talks to the
// fake log.
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
