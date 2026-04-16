//go:build production

package main

import (
	"errors"

	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/rekor"
)

// newFakeClients is a no-op in production builds. The FakeClient
// symbols are compiled out (see internal/rekor/fake.go and
// internal/ots/fake.go), so `--fake-rekor` in a released binary
// returns an error rather than silently anchoring to an in-memory
// stand-in. This preserves the trust model: if the binary is
// running, the Rekor round-trip is real.
func newFakeClients() (rekor.Client, ots.Client, error) {
	return nil, nil, errors.New("jesses: --fake-rekor is unavailable in production builds")
}
