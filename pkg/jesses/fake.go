//go:build !production

package jesses

import (
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/rekor"
)

// NewFakeRekor exposes the rekor.FakeClient for tests written against
// this package. It avoids forcing downstream tests to import
// internal/rekor (which would break if a consumer assumed internal/*
// means public).
//
// Build-tag gated (!production). Production binaries do not export
// this symbol; a consumer that tries to call it in a release build
// will fail at compile time, not silently fall through.
func NewFakeRekor() rekor.Client { return rekor.NewFakeClient() }

// NewFakeOTS exposes the ots.FakeClient for tests.
func NewFakeOTS() ots.Client { return ots.NewFakeClient() }
