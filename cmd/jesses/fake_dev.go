//go:build !production

package main

import (
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/rekor"
)

// newFakeClients returns in-memory Rekor + OTS stand-ins for offline
// testing, CI goldens, and the `--fake-rekor` flag. Only compiled
// into dev/test builds — release binaries (see fake_prod.go) refuse
// to materialize these symbols, so `--fake-rekor` in a production
// binary fails loudly instead of silently short-circuiting the
// transparency-log path.
func newFakeClients() (rekor.Client, ots.Client, error) {
	return rekor.NewFakeClient(), ots.NewFakeClient(), nil
}
