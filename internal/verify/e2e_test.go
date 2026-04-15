package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
)

// TestEndToEndHappyPath walks the full lifecycle: open a session
// backed by a FakeClient Rekor, append three allowed events, close,
// build the envelope, write it to disk, then re-read and run Verify.
// All six gates (with G4 skipped because no scope file on disk) must
// pass.
func TestEndToEndHappyPath(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.log")
	envPath := filepath.Join(dir, "session.jes")
	scopePath := filepath.Join(dir, "scope.txt")

	scopeTxt := []byte("mode: strict\nin: *.target.com\n")
	if err := writeTestFile(scopePath, scopeTxt); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	fake := rekor.NewFakeClient()
	ctx := context.Background()

	sess, err := session.Open(ctx, session.Config{
		LogPath:    logPath,
		ScopeBytes: scopeTxt,
		PrivateKey: priv,
		Rekor:      fake,
		Now:        func() time.Time { return time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, dest := range []string{"api.target.com/a", "api.target.com/b", "api.target.com/c"} {
		if err := sess.Append(audit.Event{
			TS:           time.Date(2026, 4, 16, 12, 0, i+1, 0, time.UTC).Format(time.RFC3339Nano),
			Tool:         "bash",
			InputHash:    "hash-" + string(rune('0'+i)),
			Destinations: []string{dest},
			Decision:     "allow",
			Reason:       "in scope",
			PolicyRef:    sess.ScopeHash,
		}); err != nil {
			t.Fatal(err)
		}
	}

	fin, err := sess.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fin.LeafCount != 4 {
		t.Errorf("leaf count = %d, want 4 (precommit + 3 events)", fin.LeafCount)
	}

	env, err := attest.Build(fin)
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WriteFile(envPath, env); err != nil {
		t.Fatal(err)
	}

	rpt, err := Verify(ctx, Options{
		EnvelopePath: envPath,
		AuditLogPath: logPath,
		ScopePath:    scopePath,
		RekorClient:  fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rpt.OK {
		t.Errorf("verify NOT ok:\n%s", Render(rpt))
	}

	// Every mandatory gate should have Pass=true.
	for _, g := range rpt.Gates {
		if g.Severity == "mandatory" && !g.Pass {
			t.Errorf("gate %s failed: %s", g.Name, g.Detail)
		}
	}
}

// TestTamperedLogFailsG2 demonstrates the attacker cannot rewrite the
// audit log after signing: flipping a byte in the log breaks the
// Merkle root gate.
func TestTamperedLogFailsG2(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.log")
	envPath := filepath.Join(dir, "session.jes")

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake := rekor.NewFakeClient()
	ctx := context.Background()

	sess, err := session.Open(ctx, session.Config{
		LogPath: logPath, ScopeBytes: []byte("in: *"),
		PrivateKey: priv, Rekor: fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Append(audit.Event{TS: "2026", Tool: "bash", InputHash: "h", Decision: "allow"})
	fin, _ := sess.Close(ctx)
	env, _ := attest.Build(fin)
	_ = attest.WriteFile(envPath, env)

	// Tamper with the log: rewrite a line so Merkle root no longer matches.
	raw, _ := readTestFile(logPath)
	tampered := append([]byte{}, raw...)
	// Find a JSON record and replace the tool field.
	for i := 0; i < len(tampered)-4; i++ {
		if string(tampered[i:i+6]) == `"bash"` {
			tampered[i+1] = 'B' // "bash" -> "Bash"
			break
		}
	}
	if err := writeTestFile(logPath, tampered); err != nil {
		t.Fatal(err)
	}

	rpt, _ := Verify(ctx, Options{
		EnvelopePath: envPath,
		AuditLogPath: logPath,
		RekorClient:  fake,
	})
	if rpt.OK {
		t.Errorf("tampered log should fail verification")
	}
	var g2Failed bool
	for _, g := range rpt.Gates {
		if g.Name == "G2" && !g.Pass {
			g2Failed = true
		}
	}
	if !g2Failed {
		t.Errorf("expected G2 to fail; got:\n%s", Render(rpt))
	}
}

// TestPolicyBreachFailsG5 demonstrates that an event marked deny in
// the log causes verification to fail even if the Merkle root
// recomputes correctly.
func TestPolicyBreachFailsG5(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.log")
	envPath := filepath.Join(dir, "session.jes")

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake := rekor.NewFakeClient()
	ctx := context.Background()

	sess, err := session.Open(ctx, session.Config{
		LogPath: logPath, ScopeBytes: []byte("in: *.target.com"),
		PrivateKey: priv, Rekor: fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Append(audit.Event{TS: "2026", Tool: "bash", InputHash: "h",
		Destinations: []string{"attacker.com"}, Decision: "deny",
		Reason: "not in scope"})
	fin, _ := sess.Close(ctx)
	env, _ := attest.Build(fin)
	_ = attest.WriteFile(envPath, env)

	rpt, _ := Verify(ctx, Options{
		EnvelopePath: envPath, AuditLogPath: logPath, RekorClient: fake,
	})
	if rpt.OK {
		t.Errorf("policy breach should fail: %s", Render(rpt))
	}
}

// TestEnvelopeRoundTrip verifies that Build→WriteFile→ReadFile→Parse
// preserves every predicate field byte-exactly.
func TestEnvelopeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "session.jes")

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake := rekor.NewFakeClient()
	ctx := context.Background()

	sess, _ := session.Open(ctx, session.Config{
		LogPath:    filepath.Join(dir, "session.log"),
		ScopeBytes: []byte("in: *"),
		PrivateKey: priv, Rekor: fake,
	})
	_ = sess.Append(audit.Event{TS: "2026", Tool: "bash", InputHash: "h", Decision: "allow"})
	fin, _ := sess.Close(ctx)
	env, _ := attest.Build(fin)
	_ = attest.WriteFile(envPath, env)

	got, err := attest.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	origJSON, _ := json.Marshal(env)
	gotJSON, _ := json.Marshal(got)
	if string(origJSON) != string(gotJSON) {
		t.Errorf("round-trip mismatch\norig=%s\ngot=%s", origJSON, gotJSON)
	}
}

func writeTestFile(path string, data []byte) error {
	return osWriteFile(path, data)
}

func readTestFile(path string) ([]byte, error) {
	return osReadFile(path)
}
