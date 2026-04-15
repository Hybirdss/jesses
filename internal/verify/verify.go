// Package verify implements the six-gate verifier that a triage
// analyst runs against a .jes envelope.
//
// Each gate is a boolean check with a human-readable reason. A Report
// is OK only when all six mandatory gates pass. Gate G6 (OTS anchor)
// is non-blocking for v0.1: a missing anchor yields a "pending"
// Detail but does not mark the report invalid — OpenTimestamps
// confirmation can take up to 24 hours after a Bitcoin transaction.
//
// The verifier is deliberately flat and readable — no plugin system,
// no reflection. A triage analyst who does not trust jesses' code
// can read this file in five minutes and reproduce the checks by
// hand with cosign / openssl / grep.
package verify

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/merkle"
	"github.com/Hybirdss/jesses/internal/policy"
	"github.com/Hybirdss/jesses/internal/precommit"
	"github.com/Hybirdss/jesses/internal/rekor"
)

// Gate is one check in the verification ladder.
//
// Name is a short symbolic ID ("G1", "G2", ...) that never changes
// for a given gate so scripts can grep for specific failures.
// Title is a one-line human phrase. Pass is true when the gate
// succeeded. Detail is the explanation shown to the reviewer.
type Gate struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`

	// Severity: "mandatory" blocks the report when Pass is false;
	// "advisory" contributes to the detail view but does not fail.
	Severity string `json:"severity"`
}

// Report is the full verifier output.
type Report struct {
	Gates     []Gate `json:"gates"`
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id"`
}

// Options tunes the verifier. A nil ScopePath skips G4 policy-hash
// re-check. A nil RekorClient skips G3 precommit retrieval (still
// checks BodyHash locally but cannot re-fetch the log entry).
type Options struct {
	EnvelopePath string
	AuditLogPath string
	ScopePath    string
	RekorClient  rekor.Client
}

// Verify runs all six gates and returns a Report.
func Verify(ctx context.Context, opts Options) (Report, error) {
	env, err := attest.ReadFile(opts.EnvelopePath)
	if err != nil {
		return Report{}, err
	}
	stmt, body, err := attest.Parse(env)
	if err != nil {
		return Report{}, err
	}
	pred := stmt.Predicate

	rpt := Report{SessionID: pred.SessionID}

	// ---- G1: signature over payload verifies ----
	g := Gate{Name: "G1", Title: "envelope signature", Severity: "mandatory"}
	pub, err := hex.DecodeString(pred.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		g.Detail = "invalid ed25519 public key"
	} else if len(env.Signatures) == 0 {
		g.Detail = "no signatures"
	} else {
		sig, e1 := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
		if e1 != nil {
			g.Detail = "signature decode error: " + e1.Error()
		} else if !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
			g.Detail = "signature mismatch"
		} else {
			g.Pass = true
			g.Detail = "ed25519 signature valid"
		}
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G2: Merkle root recomputes from the audit log ----
	g = Gate{Name: "G2", Title: "merkle root", Severity: "mandatory"}
	if opts.AuditLogPath == "" {
		g.Detail = "audit log path not provided (skipped)"
		g.Severity = "advisory"
	} else {
		root, count, e2 := recomputeMerkleRoot(opts.AuditLogPath)
		if e2 != nil {
			g.Detail = "audit log read error: " + e2.Error()
		} else if root != pred.MerkleRoot {
			g.Detail = fmt.Sprintf("root mismatch: got %s want %s", root, pred.MerkleRoot)
		} else if count != pred.LeafCount {
			g.Detail = fmt.Sprintf("leaf count mismatch: got %d want %d", count, pred.LeafCount)
		} else {
			g.Pass = true
			g.Detail = fmt.Sprintf("%d leaves, root %s…", count, pred.MerkleRoot[:16])
		}
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G3: precommit recorded in Rekor ----
	g = Gate{Name: "G3", Title: "rekor pre-commit", Severity: "mandatory"}
	match, e3 := precommit.Verify(pred.Precommit)
	if e3 != nil {
		g.Detail = "precommit verify error: " + e3.Error()
	} else if !match {
		g.Detail = "precommit BodyHash does not match canonical receipt"
	} else if opts.RekorClient != nil {
		fetched, e := opts.RekorClient.Fetch(ctx, pred.Precommit.LogEntry.LogIndex)
		if e != nil {
			g.Detail = "rekor fetch: " + e.Error()
		} else if fetched.BodyHash != pred.Precommit.LogEntry.BodyHash {
			g.Detail = "rekor entry body hash mismatch"
		} else {
			g.Pass = true
			g.Detail = fmt.Sprintf("log index %d, signed at %s", fetched.LogIndex, fetched.SignedAt.Format("2006-01-02 15:04:05Z"))
		}
	} else {
		g.Pass = true
		g.Detail = fmt.Sprintf("local hash match (log index %d, rekor not queried)", pred.Precommit.LogEntry.LogIndex)
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G4: scope.txt hash matches ----
	g = Gate{Name: "G4", Title: "scope hash", Severity: "mandatory"}
	if opts.ScopePath == "" {
		g.Detail = "scope path not provided (advisory)"
		g.Severity = "advisory"
	} else {
		raw, e4 := os.ReadFile(opts.ScopePath)
		if e4 != nil {
			g.Detail = "scope read error: " + e4.Error()
		} else {
			h := sha256.Sum256(raw)
			if hex.EncodeToString(h[:]) != pred.ScopeHash {
				g.Detail = fmt.Sprintf("scope hash mismatch: got %s want %s",
					hex.EncodeToString(h[:])[:16]+"…", pred.ScopeHash[:16]+"…")
			} else {
				g.Pass = true
				g.Detail = "scope.txt matches committed hash"
			}
		}
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G5: every event's decision was allow (no policy breach) ----
	g = Gate{Name: "G5", Title: "policy compliance", Severity: "mandatory"}
	if opts.AuditLogPath == "" {
		g.Detail = "audit log not provided (skipped)"
		g.Severity = "advisory"
	} else {
		breaches, total, e5 := countBreaches(opts.AuditLogPath)
		if e5 != nil {
			g.Detail = "policy scan error: " + e5.Error()
		} else if breaches > 0 {
			g.Detail = fmt.Sprintf("%d of %d events breached policy", breaches, total)
		} else {
			g.Pass = true
			g.Detail = fmt.Sprintf("all %d events allowed by scope", total)
		}
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G6: OTS anchor (advisory at v0.1) ----
	g = Gate{Name: "G6", Title: "opentimestamps anchor", Severity: "advisory"}
	switch {
	case pred.OTSError != "":
		g.Detail = "anchor submission failed: " + pred.OTSError
	case pred.OTSReceipt.CalendarURL == "":
		g.Detail = "no OTS client configured (rekor provides mandatory pre-commit)"
	case pred.OTSReceipt.Status == "pending":
		g.Detail = "pending bitcoin confirmation — submitted to " + pred.OTSReceipt.CalendarURL
	case pred.OTSReceipt.Status == "confirmed":
		g.Pass = true
		g.Detail = "anchored in bitcoin via " + pred.OTSReceipt.CalendarURL
	default:
		g.Detail = "unknown status: " + pred.OTSReceipt.Status
	}
	rpt.Gates = append(rpt.Gates, g)

	// Overall OK: every mandatory gate Pass=true.
	rpt.OK = true
	for _, gg := range rpt.Gates {
		if gg.Severity == "mandatory" && !gg.Pass {
			rpt.OK = false
			break
		}
	}

	return rpt, nil
}

// recomputeMerkleRoot reads the audit log line-by-line, canonicalizes
// each event, hashes it as a Merkle leaf, and computes the RFC 6962
// tree root. Returns the hex root and the leaf count.
func recomputeMerkleRoot(path string) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var leafs []merkle.Hash
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return "", 0, err
		}
		canon, err := audit.CanonicalJSON(ev)
		if err != nil {
			return "", 0, err
		}
		leafs = append(leafs, merkle.HashLeaf(canon))
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	root := merkle.RootFromLeafHashes(leafs)
	return hex.EncodeToString(root[:]), len(leafs), nil
}

// countBreaches counts events whose Decision is neither "allow" nor
// "commit" (pre-commit event) nor "warn" (advisory mode).
func countBreaches(path string) (breaches, total int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return 0, 0, err
		}
		total++
		switch ev.Decision {
		case "allow", "commit", "warn":
			// fine
		default:
			breaches++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return breaches, total, nil
}

// Render produces a human-readable pass/fail summary of the report
// for the CLI. Each mandatory failure is prefixed ✗, each pass ✓,
// advisories get ⚠.
func Render(rpt Report) string {
	var sb strings.Builder
	pass := 0
	for _, g := range rpt.Gates {
		if g.Pass {
			pass++
		}
	}
	sb.WriteString(fmt.Sprintf("session %s\n\n", rpt.SessionID))
	for _, g := range rpt.Gates {
		mark := "✗"
		if g.Pass {
			mark = "✓"
		} else if g.Severity == "advisory" {
			mark = "⚠"
		}
		sb.WriteString(fmt.Sprintf("  %s  %s  %s — %s\n", mark, g.Name, g.Title, g.Detail))
	}
	sb.WriteString("\n")
	if rpt.OK {
		sb.WriteString(fmt.Sprintf("VERDICT: valid (%d/%d gates pass)\n", pass, len(rpt.Gates)))
	} else {
		sb.WriteString(fmt.Sprintf("VERDICT: invalid (%d/%d gates pass; mandatory gate failed)\n", pass, len(rpt.Gates)))
	}
	return sb.String()
}

// policyCompile validates the scope.txt is parseable. Exposed as a
// helper so the CLI init-scope subcommand can reuse it without
// duplicating the parser call.
func policyCompile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = policy.ParseBytes(raw)
	return err
}

// Err sentinel for callers that want to detect "envelope parsed but
// invalid" (distinct from file-I/O or signature errors).
var ErrInvalid = errors.New("verify: envelope invalid")
