package jesses_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Hybirdss/jesses/pkg/jesses"
)

// TestPublicAPIHappyPath exercises the public surface end-to-end:
// Open → Process (3 events, 2 allow + 1 deny) → Close → Verify.
// This is the reference demo for anyone integrating jesses into a
// custom agent harness.
func TestPublicAPIHappyPath(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.log")
	envPath := filepath.Join(dir, "session.jes")
	scopePath := filepath.Join(dir, "scope.txt")

	scope := []byte("mode: strict\nin: *.target.com\n")
	if err := writeFile(scopePath, scope); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	sess, err := jesses.Open(ctx, jesses.OpenOptions{
		LogPath:    logPath,
		ScopeBytes: scope,
		Rekor:      jesses.NewFakeRekor(),
		OTS:        jesses.NewFakeOTS(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		raw         map[string]any
		wantVerdict string
	}{
		{
			raw: map[string]any{
				"tool":  "bash",
				"input": map[string]any{"command": "curl https://api.target.com/a"},
			},
			wantVerdict: "allow",
		},
		{
			raw: map[string]any{
				"tool":  "bash",
				"input": map[string]any{"command": "curl https://attacker.com/x"},
			},
			wantVerdict: "deny",
		},
		{
			raw: map[string]any{
				"tool":  "webfetch",
				"input": map[string]any{"url": "https://api.target.com/b"},
			},
			wantVerdict: "allow",
		},
	}
	for i, c := range cases {
		dec, err := sess.Process(c.raw)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if dec.Verdict != c.wantVerdict {
			t.Errorf("event %d: verdict = %q want %q (reason %q, dests %d)",
				i, dec.Verdict, c.wantVerdict, dec.Reason, len(dec.Destinations))
		}
	}

	envBytes, err := sess.Close(ctx, envPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(envBytes) < 100 {
		t.Errorf("envelope bytes suspiciously small: %d", len(envBytes))
	}

	rpt, err := jesses.Verify(ctx, jesses.VerifyOptions{
		EnvelopePath: envPath,
		AuditLogPath: logPath,
		ScopePath:    scopePath,
		Rekor:        nil, // offline local-hash verification
	})
	if err != nil {
		t.Fatal(err)
	}

	// Expect G5 to fail (one deny event) and others to pass.
	if rpt.OK {
		t.Errorf("expected G5 to fail due to deny event; report OK")
	}
	var g5 jesses.Gate
	for _, g := range rpt.Gates {
		if g.Name == "G5" {
			g5 = g
		}
	}
	if g5.Pass {
		t.Errorf("G5 should have failed on deny event")
	}
}

// TestFinalizeDoesNotRequireFile shows the streaming path: Finalize
// returns the envelope object without touching the filesystem.
func TestFinalizeDoesNotRequireFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	sess, err := jesses.Open(ctx, jesses.OpenOptions{
		LogPath:    filepath.Join(dir, "session.log"),
		ScopeBytes: []byte("in: *"),
		Rekor:      jesses.NewFakeRekor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Process(map[string]any{
		"tool":  "bash",
		"input": map[string]any{"command": "curl evil.com"},
	}); err != nil {
		t.Fatal(err)
	}
	env, err := sess.Finalize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env.PayloadType == "" {
		t.Error("envelope PayloadType empty")
	}
	if len(env.Signatures) != 1 {
		t.Errorf("want 1 signature, got %d", len(env.Signatures))
	}
}

func writeFile(path string, data []byte) error {
	return osWriteFile(path, data)
}
