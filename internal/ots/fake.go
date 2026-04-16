//go:build !production

package ots

import (
	"context"
	"encoding/base64"
	"sync"
	"time"
)

// FakeClient records submissions in memory. Deterministic digest-
// based receipt bytes so goldens stay stable.
//
// Build-tag gated: compiled only when the `production` tag is NOT
// set. Release binaries (`-tags=production`) do not contain this
// symbol, so an operator cannot accidentally ship a release that
// silently anchors to the fake calendar.
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
