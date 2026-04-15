package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/provenance"
	"github.com/Hybirdss/jesses/internal/session"
)

// runReport implements `jesses report --bind <report.md> <session.jes>`.
//
// Workflow: after an agent session has written session.jes while the
// signing key is still on disk, the operator runs this subcommand to:
//
//  1. Parse report.md for [^ev:N] and [^hash:H] citations
//  2. Validate each citation against session.log
//  3. Generate a "Session timeline" markdown appendix written to
//     report.md.timeline.md
//  4. Re-sign the envelope with a DeliverableBinding payload that
//     records the report's SHA-256, citation count, bare-claim count,
//     and bare-policy. The new envelope overwrites the old one.
//
// The new envelope still pins the original Merkle root and pre-
// commitment — only the Predicate is extended with the binding
// block and re-signed. The Rekor pre-commit index stays valid.
//
// Security note: this subcommand requires session-dir/key.priv. Once
// the binding is written, the operator SHOULD `rm key.priv` so
// nothing else can produce envelopes under the same identity.
func runReport(args []string) int {
	_ = context.TODO()
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	bindPath := fs.String("bind", "", "path to the report markdown file to bind")
	barePolicy := fs.String("bare-policy", "warn", "how to treat uncited factual claims: allow | warn | strict")
	sessionDir := fs.String("session-dir", ".", "directory holding session.log, key.priv")
	writeTimeline := fs.Bool("timeline", true, "write timeline appendix next to the report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses report: missing envelope path")
		fmt.Fprintln(os.Stderr, "usage: jesses report --bind <report.md> <session.jes>")
		return 2
	}
	if *bindPath == "" {
		fmt.Fprintln(os.Stderr, "jesses report: --bind is required")
		return 2
	}
	envPath := fs.Arg(0)
	logPath := filepath.Join(*sessionDir, "session.log")
	keyPath := filepath.Join(*sessionDir, "key.priv")

	rpt, err := provenance.Parse(*bindPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report: parse %s: %v\n", *bindPath, err)
		return 1
	}

	pol := provenance.BarePolicy(*barePolicy)
	switch pol {
	case provenance.BareAllow, provenance.BareWarn, provenance.BareStrict:
	default:
		fmt.Fprintf(os.Stderr, "report: --bare-policy must be allow|warn|strict, got %q\n", *barePolicy)
		return 2
	}
	rpt, ok, err := provenance.Validate(rpt, logPath, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report: validate: %v\n", err)
		return 1
	}

	if *writeTimeline {
		tl, terr := provenance.GenerateTimeline(logPath, rpt.Citations)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "report: timeline: %v\n", terr)
			return 1
		}
		timelinePath := *bindPath + ".timeline.md"
		if err := os.WriteFile(timelinePath, []byte(tl), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "report: write timeline: %v\n", err)
			return 1
		}
	}

	binding := &attest.DeliverableBinding{
		Path:           filepath.Base(rpt.Path),
		SHA256:         rpt.SHA256,
		CitationCount:  len(rpt.Citations),
		BareClaimCount: len(rpt.BareClaims),
		BarePolicy:     *barePolicy,
	}

	if err := rebuildEnvelopeWithBinding(envPath, keyPath, binding); err != nil {
		fmt.Fprintf(os.Stderr, "report: rebuild envelope: %v\n", err)
		return 1
	}

	passed := 0
	for _, v := range rpt.Validations {
		if v.Pass {
			passed++
		}
	}
	fmt.Printf("report %s bound to %s\n", rpt.Path, envPath)
	fmt.Printf("  citations:    %d total, %d validated\n", len(rpt.Citations), passed)
	fmt.Printf("  bare claims:  %d (policy: %s)\n", len(rpt.BareClaims), *barePolicy)
	if *writeTimeline {
		fmt.Printf("  timeline:     %s.timeline.md\n", rpt.Path)
	}
	if !ok {
		fmt.Printf("\n  G7 WILL FAIL on verify — see individual citation errors:\n")
		for _, v := range rpt.Validations {
			if !v.Pass {
				fmt.Printf("    ✗ [^%s] line %d — %s\n", v.Citation.MarkerID, v.Citation.ClaimLine, v.Detail)
			}
		}
		return 1
	}
	fmt.Printf("  G7 ready to pass on verify\n")
	return 0
}

// rebuildEnvelopeWithBinding reads the existing envelope's
// Statement, reconstructs a session.Finalized bundle from its
// fields, re-signs with the private key on disk + the new
// DeliverableBinding, and overwrites envPath.
func rebuildEnvelopeWithBinding(envPath, keyPath string, binding *attest.DeliverableBinding) error {
	env, err := attest.ReadFile(envPath)
	if err != nil {
		return err
	}
	stmt, _, err := attest.Parse(env)
	if err != nil {
		return err
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read %s: %w (keep key.priv around for the binding step)", keyPath, err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("key file %s has wrong size %d (expected %d)",
			keyPath, len(keyBytes), ed25519.PrivateKeySize)
	}

	p := stmt.Predicate
	startedAt, _ := time.Parse(time.RFC3339Nano, p.StartedAt)
	endedAt, _ := time.Parse(time.RFC3339Nano, p.EndedAt)

	pub, err := hexDecode(p.PubKey)
	if err != nil {
		return err
	}

	fin := session.Finalized{
		SessionID:  p.SessionID,
		StartedAt:  startedAt,
		EndedAt:    endedAt,
		ScopeHash:  p.ScopeHash,
		PubKey:     ed25519.PublicKey(pub),
		PrivKey:    ed25519.PrivateKey(keyBytes),
		MerkleRoot: p.MerkleRoot,
		LeafCount:  p.LeafCount,
		Precommit:  p.Precommit,
		OTSReceipt: p.OTSReceipt,
		OTSError:   p.OTSError,
	}

	newEnv, err := attest.BuildWithBinding(fin, binding)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(newEnv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(envPath, out, 0o644)
}

// hexDecode is a tiny hex decoder used to parse predicate pubkey
// hex. Wrapping encoding/hex would be fine too — kept inline to
// match the util.go style.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %d", len(s))
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexNibble(s[i*2])
		lo := hexNibble(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("invalid hex at index %d", i*2)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexNibble(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}
