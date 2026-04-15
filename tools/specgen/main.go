// Command specgen generates the canonical test-vector corpus for
// the jesses v0.1 specification.
//
// The corpus under spec/test-vectors/v0.1/ IS the specification:
// any implementation of the jesses verifier — in any language — is
// conformant if and only if it produces byte-exact identical
// Report JSON for each vector. Two implementations passing the
// same vectors is how a standard is proved, not a claim.
//
// Each vector directory contains:
//
//	session.jes       — the attestation envelope
//	session.log       — the append-only audit log
//	scope.txt         — the policy used at session open
//	vector.json       — { name, description, verify_options, expected_report }
//
// The generator uses deterministic inputs (fixed ed25519 seed, fixed
// timestamps, fixed session ID, FakeClient Rekor with known LogID)
// so re-running specgen is a no-op when behavior is stable. A diff
// in the generated files signals a spec-breaking change.
//
// Regeneration:
//
//	go run ./tools/specgen ./spec/test-vectors/v0.1
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
	"github.com/Hybirdss/jesses/internal/verify"
)

// fixedSeed is the 32-byte seed used to derive the ed25519 key for
// every spec vector. Deterministic keys mean deterministic envelope
// bytes, which means byte-exact test vectors across implementations.
var fixedSeed = []byte("jesses-spec-v0.1-fixed-seed-x32x")

// fixedStart is the wall-clock time used for every spec vector's
// session StartedAt. Chosen arbitrarily; only the bytes matter.
var fixedStart = time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

// vector represents one generated vector ready to be written.
type vector struct {
	name           string
	description    string
	scope          []byte
	events         []audit.Event
	tamperLogAfter func([]byte) []byte // optional post-hoc log tamper
	expectedOK     bool
	expectedG2Pass bool
	expectedG5Pass bool
	expectedG6Pass bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: specgen <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		die(err)
	}

	vectors := []vector{
		{
			name:        "happy-path",
			description: "Three allowed events, scope matches, Merkle + signature verify.",
			scope:       []byte("mode: strict\nin: *.target.com\n"),
			events: []audit.Event{
				evAllow(1, "bash", []string{"api.target.com"}),
				evAllow(2, "bash", []string{"api.target.com"}),
				evAllow(3, "webfetch", []string{"api.target.com"}),
			},
			expectedOK:     true,
			expectedG2Pass: true,
			expectedG5Pass: true,
			expectedG6Pass: false, // G6 pending by default (fake OTS returns pending)
		},
		{
			name:        "policy-breach",
			description: "One event was denied — G5 must fail even though G1-G4 pass.",
			scope:       []byte("mode: strict\nin: *.target.com\n"),
			events: []audit.Event{
				evAllow(1, "bash", []string{"api.target.com"}),
				evDeny(2, "bash", []string{"attacker.com"}, "unpoliced (strict mode)"),
				evAllow(3, "bash", []string{"api.target.com"}),
			},
			expectedOK:     false,
			expectedG2Pass: true,
			expectedG5Pass: false,
			expectedG6Pass: false,
		},
		{
			name:        "tampered-log",
			description: "Log rewritten after envelope signing — G2 Merkle root must fail.",
			scope:       []byte("mode: strict\nin: *.target.com\n"),
			events: []audit.Event{
				evAllow(1, "bash", []string{"api.target.com"}),
			},
			// Flip the "bash" tool to "curl" in the log. Root recompute fails.
			tamperLogAfter: func(b []byte) []byte {
				out := append([]byte{}, b...)
				for i := 0; i < len(out)-5; i++ {
					if string(out[i:i+6]) == `"bash"` {
						copy(out[i:i+6], []byte(`"curl"`))
						break
					}
				}
				return out
			},
			expectedOK:     false,
			expectedG2Pass: false,
			expectedG5Pass: true, // events themselves don't breach policy
			expectedG6Pass: false,
		},
	}

	for _, v := range vectors {
		dir := filepath.Join(outDir, v.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			die(err)
		}
		if err := writeVector(dir, v); err != nil {
			die(fmt.Errorf("%s: %w", v.name, err))
		}
		fmt.Printf("wrote %s\n", dir)
	}
}

func writeVector(dir string, v vector) error {
	logPath := filepath.Join(dir, "session.log")
	envPath := filepath.Join(dir, "session.jes")
	scopePath := filepath.Join(dir, "scope.txt")
	vectorPath := filepath.Join(dir, "vector.json")

	if err := os.WriteFile(scopePath, v.scope, 0o644); err != nil {
		return err
	}

	priv := ed25519.NewKeyFromSeed(fixedSeed)

	fakeRekor := rekor.NewFakeClient()
	fakeOTS := ots.NewFakeClient()

	ctx := context.Background()
	sess, err := session.Open(ctx, session.Config{
		LogPath:    logPath,
		ScopeBytes: v.scope,
		PrivateKey: priv,
		Rekor:      fakeRekor,
		OTS:        fakeOTS,
		OverrideID: deterministicID(v.name),
		Now:        func() time.Time { return fixedStart },
	})
	if err != nil {
		return err
	}

	for i, ev := range v.events {
		ev.TS = fixedStart.Add(time.Duration(i+1) * time.Second).Format(time.RFC3339Nano)
		if err := sess.Append(ev); err != nil {
			return err
		}
	}

	fin, err := sess.Close(ctx)
	if err != nil {
		return err
	}
	// Pin the end-time to a deterministic value so envelope bytes
	// stay stable across regenerations.
	fin.EndedAt = fixedStart.Add(time.Duration(len(v.events)+1) * time.Second)

	env, err := attest.Build(fin)
	if err != nil {
		return err
	}
	if err := attest.WriteFile(envPath, env); err != nil {
		return err
	}

	if v.tamperLogAfter != nil {
		raw, err := os.ReadFile(logPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(logPath, v.tamperLogAfter(raw), 0o644); err != nil {
			return err
		}
	}

	// Compute the expected Report in OFFLINE mode (no Rekor
	// round-trip). The vector corpus documents offline-verify
	// behavior so second implementations without a Rekor client
	// can match byte-exactly. Online verification adds one more
	// successful check but is not part of the conformance corpus
	// at v0.1.
	rpt, err := verify.Verify(ctx, verify.Options{
		EnvelopePath: envPath,
		AuditLogPath: logPath,
		ScopePath:    scopePath,
		// RekorClient intentionally nil — offline behavior is the
		// spec baseline.
	})
	if err != nil {
		return err
	}

	meta := map[string]any{
		"name":            v.name,
		"description":     v.description,
		"schema_version":  "v0.1",
		"fixed_seed_hex":  hex.EncodeToString(fixedSeed),
		"fixed_start":     fixedStart.Format(time.RFC3339Nano),
		"expected_report": rpt,
		"expected_summary": map[string]bool{
			"overall_ok": v.expectedOK,
			"g2_pass":    v.expectedG2Pass,
			"g5_pass":    v.expectedG5Pass,
			"g6_pass":    v.expectedG6Pass,
		},
	}
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(vectorPath, append(out, '\n'), 0o644)
}

func evAllow(seq uint64, tool string, dests []string) audit.Event {
	return audit.Event{
		Seq: seq, Tool: tool, InputHash: fmt.Sprintf("hash-%d", seq),
		Destinations: dests, Decision: "allow", Reason: "in scope",
	}
}

func evDeny(seq uint64, tool string, dests []string, reason string) audit.Event {
	return audit.Event{
		Seq: seq, Tool: tool, InputHash: fmt.Sprintf("hash-%d", seq),
		Destinations: dests, Decision: "deny", Reason: reason,
	}
}

// deterministicID produces a 32-char lowercase-hex ID from the
// vector name so each vector has a stable session_id across regens.
func deterministicID(name string) string {
	var out [16]byte
	copy(out[:], []byte("jesses-vec:"+name))
	return hex.EncodeToString(out[:])
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "specgen:", err)
	os.Exit(1)
}
