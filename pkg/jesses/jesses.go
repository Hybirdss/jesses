// Package jesses is the stable public API for embedding attestation
// sessions into a Go program.
//
// A custom agent harness (bespoke CLI, in-house bounty runner, a
// platform's integration layer) imports this package instead of
// shelling out to the `jesses` binary when it wants:
//
//   - in-process session lifecycle (open → process tool events → close)
//   - direct Envelope construction without stdin/stdout marshaling
//   - programmatic verification of a .jes file
//
// Stability contract: the symbols exported from this package
// (Session, Process, Decision, OpenOptions, Verify, VerifyOptions,
// Report) are versioned under the jesses v0.1 compatibility guarantee.
// Internal packages (internal/*) MAY change shape without a major
// version bump; this package MAY NOT. When breaking changes are
// required, a new pkg/jesses/v0_2 will be introduced alongside.
package jesses

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/extractors"
	"github.com/Hybirdss/jesses/internal/extractors/dispatch"
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/policy"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
	"github.com/Hybirdss/jesses/internal/verify"
)

// Session wraps an in-flight attestation session.
type Session struct {
	inner  *session.Session
	policy *policy.Policy
	seq    uint64
}

// Decision is the policy evaluation result returned by Process.
type Decision struct {
	// Verdict is "allow", "warn", or "deny". The hook should refuse
	// to execute the tool call when Verdict == "deny".
	Verdict string `json:"verdict"`

	// Reason is a human-readable explanation (the matching scope
	// rule text, or why the destination did not fall inside scope).
	Reason string `json:"reason"`

	// Destinations is the list of parsed destinations for the tool
	// event, in source order. Exposed so a harness can render them
	// alongside the verdict.
	Destinations []extractors.Destination `json:"destinations"`
}

// OpenOptions configures a new session.
type OpenOptions struct {
	// LogPath is where the append-only audit log is written. A
	// session creates the file on Open.
	LogPath string

	// ScopeBytes is the raw scope.txt bytes in effect at session
	// open. The hash is committed in the pre-commitment; policy
	// evaluation uses the parsed form.
	ScopeBytes []byte

	// PrivateKey signs the final envelope. If nil, a fresh ed25519
	// key is generated. Long-lived harnesses SHOULD pass a key they
	// own so Subject.KeyID stays stable across sessions.
	PrivateKey ed25519.PrivateKey

	// Rekor is the transparency-log client. Required — jesses does
	// not run without pre-commitment. For tests, pass rekor.NewFakeClient().
	Rekor rekor.Client

	// OTS is optional OpenTimestamps anchoring. When nil, the
	// session skips Bitcoin anchoring and the envelope's OTS field
	// stays empty.
	OTS ots.Client

	// Now returns the wall-clock for session timestamps. Tests pass
	// a fixed value for deterministic goldens.
	Now func() time.Time
}

// Open starts a new attestation session. The pre-commitment uploads
// to Rekor inline; a failure is returned without creating the log
// file.
func Open(ctx context.Context, opts OpenOptions) (*Session, error) {
	if opts.Rekor == nil {
		return nil, errors.New("jesses: OpenOptions.Rekor is required")
	}
	if opts.PrivateKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		opts.PrivateKey = priv
	}

	pol, err := policy.ParseBytes(opts.ScopeBytes)
	if err != nil {
		return nil, fmt.Errorf("jesses: parse scope: %w", err)
	}

	inner, err := session.Open(ctx, session.Config{
		LogPath:    opts.LogPath,
		ScopeBytes: opts.ScopeBytes,
		PrivateKey: opts.PrivateKey,
		Rekor:      opts.Rekor,
		OTS:        opts.OTS,
		Now:        opts.Now,
	})
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner, policy: pol}, nil
}

// Process evaluates a single tool-use event and records it in the
// session's audit log. The raw map shape matches the line-delimited
// JSON that the `jesses hook` subcommand consumes:
//
//	{"tool": "<name>", "input": {...tool-specific fields...}}
//
// Returns the policy Decision. A deny verdict has already been
// recorded in the audit log — the harness's job is to NOT run the
// tool call after seeing deny.
func (s *Session) Process(raw map[string]any) (Decision, error) {
	tool, _ := raw["tool"].(string)
	input, _ := raw["input"].(map[string]any)
	inputJSON, _ := json.Marshal(input)

	dsts, err := dispatch.Extract(raw)
	if err != nil {
		ev := audit.Event{
			Seq:       s.seq,
			TS:        time.Now().UTC().Format(time.RFC3339Nano),
			Tool:      tool,
			InputHash: sumSHA256(inputJSON),
			Input:     input,
			Decision:  "deny",
			Reason:    "extractor error: " + err.Error(),
		}
		if appendErr := s.inner.Append(ev); appendErr != nil {
			return Decision{}, appendErr
		}
		s.seq++
		return Decision{Verdict: "deny", Reason: ev.Reason}, nil
	}

	ev := audit.Event{
		Seq:       s.seq,
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		Tool:      tool,
		InputHash: sumSHA256(inputJSON),
		Input:     input,
		Decision:  "allow",
		Reason:    "in scope",
	}

	var dstStrs []string
	var dec Decision
	dec.Destinations = dsts
	for _, d := range dsts {
		dstStrs = append(dstStrs, identifierFor(d))
		ns, val := namespaceFor(d)
		verdict := s.policy.Evaluate(ns, val)
		switch verdict.Verdict {
		case policy.VerdictBlock:
			ev.Decision = "deny"
			ev.Reason = verdict.Reason
			ev.Destinations = dstStrs
			if err := s.inner.Append(ev); err != nil {
				return Decision{}, err
			}
			s.seq++
			dec.Verdict = "deny"
			dec.Reason = verdict.Reason
			return dec, nil
		case policy.VerdictWarn:
			ev.Decision = "warn"
			ev.Reason = verdict.Reason
		}
	}
	ev.Destinations = dstStrs
	if err := s.inner.Append(ev); err != nil {
		return Decision{}, err
	}
	s.seq++
	dec.Verdict = ev.Decision
	dec.Reason = ev.Reason
	return dec, nil
}

// Close finalizes the session and writes the attestation envelope to
// envelopePath. Returns the envelope bytes for callers that want to
// forward it to a downstream service (platform triage queue,
// customer webhook, etc.) without re-reading the file.
func (s *Session) Close(ctx context.Context, envelopePath string) ([]byte, error) {
	fin, err := s.inner.Close(ctx)
	if err != nil {
		return nil, err
	}
	env, err := attest.Build(fin)
	if err != nil {
		return nil, err
	}
	if err := attest.WriteFile(envelopePath, env); err != nil {
		return nil, err
	}
	return os.ReadFile(envelopePath)
}

// Finalize is the no-file-write variant of Close. The envelope is
// returned but not persisted; useful when the caller wants to stream
// it directly to a log aggregator or test harness.
func (s *Session) Finalize(ctx context.Context) (attest.Envelope, error) {
	fin, err := s.inner.Close(ctx)
	if err != nil {
		return attest.Envelope{}, err
	}
	return attest.Build(fin)
}

// Verify runs the six-gate verification against an envelope on disk.
// It is a thin wrapper so external programs do not have to import
// internal/verify directly.
func Verify(ctx context.Context, opts VerifyOptions) (Report, error) {
	rpt, err := verify.Verify(ctx, verify.Options{
		EnvelopePath: opts.EnvelopePath,
		AuditLogPath: opts.AuditLogPath,
		ScopePath:    opts.ScopePath,
		RekorClient:  opts.Rekor,
	})
	if err != nil {
		return Report{}, err
	}
	gates := make([]Gate, len(rpt.Gates))
	for i, g := range rpt.Gates {
		gates[i] = Gate(g)
	}
	return Report{
		Gates:     gates,
		OK:        rpt.OK,
		SessionID: rpt.SessionID,
	}, nil
}

// VerifyOptions mirrors verify.Options without leaking the internal
// type.
type VerifyOptions struct {
	EnvelopePath string
	AuditLogPath string
	ScopePath    string
	Rekor        rekor.Client
}

// Gate mirrors verify.Gate. Using a type alias would lock us to the
// internal shape; a conversion keeps the boundary clean.
type Gate struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// Report mirrors verify.Report.
type Report struct {
	Gates     []Gate `json:"gates"`
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id"`
}
