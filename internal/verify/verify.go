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

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/merkle"
	"github.com/Hybirdss/jesses/internal/policy"
	"github.com/Hybirdss/jesses/internal/precommit"
	"github.com/Hybirdss/jesses/internal/provenance"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/render"
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

	// Error is the machine-readable failure detail. Populated for
	// every failed mandatory gate with a stable Code plus typed
	// fields a triage bot can pivot off without parsing Detail.
	// Nil when the gate passed or is an informational skip.
	Error *VerifyError `json:"error,omitempty"`
}

// Report is the full verifier output.
type Report struct {
	Gates     []Gate `json:"gates"`
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id"`
}

// Options tunes the verifier. A nil ScopePath skips G4 policy-hash
// re-check. A nil RekorClient skips G3 precommit retrieval (still
// checks BodyHash locally but cannot re-fetch the log entry). A
// zero ReportPath skips the G7 deliverable-binding check when the
// envelope has no binding attached; G7 is mandatory when the
// envelope DOES carry a DeliverableBinding.
type Options struct {
	EnvelopePath string
	AuditLogPath string
	ScopePath    string
	ReportPath   string
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
		g.Error = &VerifyError{Gate: "G1", Code: ErrCodeInvalidPubKey, Got: pred.PubKey}
	} else if len(env.Signatures) == 0 {
		g.Detail = "no signatures"
		g.Error = &VerifyError{Gate: "G1", Code: ErrCodeNoSignatures}
	} else {
		sig, e1 := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
		if e1 != nil {
			g.Detail = "signature decode error: " + e1.Error()
			g.Error = &VerifyError{Gate: "G1", Code: ErrCodeSigDecode, Got: e1.Error()}
		} else if !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
			g.Detail = "signature mismatch"
			g.Error = &VerifyError{Gate: "G1", Code: ErrCodeSigMismatch}
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
			g.Error = &VerifyError{Gate: "G2", Code: ErrCodeAuditRead, Got: e2.Error()}
		} else if root != pred.MerkleRoot {
			g.Detail = fmt.Sprintf("root mismatch: got %s want %s", root, pred.MerkleRoot)
			g.Error = &VerifyError{Gate: "G2", Code: ErrCodeMerkleMismatch, Expected: pred.MerkleRoot, Got: root}
		} else if count != pred.LeafCount {
			g.Detail = fmt.Sprintf("leaf count mismatch: got %d want %d", count, pred.LeafCount)
			g.Error = &VerifyError{Gate: "G2", Code: ErrCodeLeafCountMismatch,
				Expected: fmt.Sprintf("%d", pred.LeafCount), Got: fmt.Sprintf("%d", count)}
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
		g.Error = &VerifyError{Gate: "G3", Code: ErrCodePrecommitInvalid, Got: e3.Error()}
	} else if !match {
		g.Detail = "precommit BodyHash does not match canonical receipt"
		g.Error = &VerifyError{Gate: "G3", Code: ErrCodePrecommitInvalid,
			Expected: pred.Precommit.LogEntry.BodyHash}
	} else if opts.RekorClient != nil {
		fetched, e := opts.RekorClient.Fetch(ctx, pred.Precommit.LogEntry.LogIndex)
		if e != nil {
			g.Detail = "rekor fetch: " + e.Error()
			g.Error = &VerifyError{Gate: "G3", Code: ErrCodeRekorFetch, Got: e.Error()}
		} else if fetched.BodyHash != pred.Precommit.LogEntry.BodyHash {
			g.Detail = "rekor entry body hash mismatch"
			g.Error = &VerifyError{Gate: "G3", Code: ErrCodeRekorBodyHash,
				Expected: pred.Precommit.LogEntry.BodyHash, Got: fetched.BodyHash}
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
			g.Error = &VerifyError{Gate: "G4", Code: ErrCodeScopeRead, Got: e4.Error()}
		} else {
			h := sha256.Sum256(raw)
			gotHex := hex.EncodeToString(h[:])
			if gotHex != pred.ScopeHash {
				g.Detail = fmt.Sprintf("scope hash mismatch: got %s want %s",
					gotHex[:16]+"…", pred.ScopeHash[:16]+"…")
				g.Error = &VerifyError{Gate: "G4", Code: ErrCodeScopeMismatch,
					Expected: pred.ScopeHash, Got: gotHex}
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
			g.Error = &VerifyError{Gate: "G5", Code: ErrCodePolicyScan, Got: e5.Error()}
		} else if breaches > 0 {
			g.Detail = fmt.Sprintf("%d of %d events breached policy", breaches, total)
			g.Error = &VerifyError{Gate: "G5", Code: ErrCodePolicyBreach,
				Count: breaches, Total: total}
		} else {
			g.Pass = true
			g.Detail = fmt.Sprintf("all %d events allowed by scope", total)
		}
	}
	rpt.Gates = append(rpt.Gates, g)

	// ---- G7: deliverable provenance binding ----
	// Placed BEFORE G6 so the mandatory gate is evaluated before
	// the advisory one when computing the overall verdict.
	g = Gate{Name: "G7", Title: "deliverable provenance", Severity: "advisory"}
	binding := pred.DeliverableBinding
	switch {
	case binding == nil:
		g.Detail = "no deliverable bound to envelope"
	case opts.ReportPath == "":
		g.Detail = fmt.Sprintf("envelope declares report %q but none provided to verify", binding.Path)
		g.Severity = "mandatory"
		g.Error = &VerifyError{Gate: "G7", Code: ErrCodeMissingReport, Expected: binding.Path}
	default:
		g.Severity = "mandatory"
		g7OK, detail, verr := checkDeliverable(opts.ReportPath, opts.AuditLogPath, binding)
		g.Pass = g7OK
		g.Detail = detail
		if !g7OK && verr != nil {
			g.Error = verr
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
// for the CLI. The default style auto-detects terminal + NO_COLOR;
// callers who want plain ASCII can pass a Style with ASCII=true to
// RenderStyled.
func Render(rpt Report) string {
	return RenderStyled(rpt, render.NewStyle(os.Stdout))
}

// RenderStyled is Render with an explicit Style. Used by `jesses
// verify --ascii` and by tests that want deterministic output.
func RenderStyled(rpt Report, st render.Style) string {
	const width = 74

	mandatory := []string{}
	advisory := []string{}
	pass := 0
	mandatoryFail := false
	for _, g := range rpt.Gates {
		if g.Pass {
			pass++
		} else if g.Severity == "mandatory" {
			mandatoryFail = true
		}
		line := renderGateLine(g, st, width-2)
		if g.Severity == "advisory" {
			advisory = append(advisory, line)
		} else {
			mandatory = append(mandatory, line)
		}
	}

	// Verdict stamp: big bold line at the top of the first section.
	verdictLines := []string{""}
	if rpt.OK {
		verdictLines = append(verdictLines,
			"              "+st.BoldGreen("✓  VALID"),
			"                 "+st.Dim(fmt.Sprintf("%d of %d gates pass", pass, len(rpt.Gates))),
		)
	} else {
		reason := "no passing mandatory failures"
		if mandatoryFail {
			reason = "1 or more mandatory gates failed"
		}
		verdictLines = append(verdictLines,
			"              "+st.BoldRed("✗  INVALID"),
			"                 "+st.Dim(fmt.Sprintf("%d of %d gates pass · %s", pass, len(rpt.Gates), reason)),
		)
	}
	verdictLines = append(verdictLines, "")

	sections := []render.Section{
		{Label: "", Lines: verdictLines},
	}
	if len(mandatory) > 0 {
		sections = append(sections, render.Section{Label: "mandatory", Lines: mandatory})
	}
	if len(advisory) > 0 {
		sections = append(sections, render.Section{Label: "advisory", Lines: advisory})
	}

	title := "jesses verify"
	if rpt.SessionID != "" {
		title = title + "   " + st.Dim("session "+render.HexTrunc(rpt.SessionID, 16))
	}

	return st.Box(title, sections, width) + "\n"
}

// renderGateLine formats one gate row: marker, id, title, detail.
// Aligned columns for visual consistency.
func renderGateLine(g Gate, st render.Style, width int) string {
	var mark string
	switch {
	case g.Pass:
		mark = st.GatePass()
	case g.Severity == "advisory":
		mark = st.GateAdvisory()
	default:
		mark = st.GateFail()
	}

	nameCol := fmt.Sprintf("%-2s", g.Name)
	titleCol := fmt.Sprintf("%-25s", g.Title)
	line := fmt.Sprintf("%s %s  %s  %s", mark, st.Dim(nameCol), titleCol, st.Dim(g.Detail))
	return line
}

// checkDeliverable runs the G7 pipeline on the provided report:
// reads the file, re-hashes it, compares to the binding's SHA-256,
// parses citations, and validates each against the audit log.
//
// Returns (pass, human-readable-detail, structured-error). Structured
// error is nil on success; on failure it carries the stable Code plus
// Expected/Got hashes or counts so triage bots can pivot off it. The
// bare-policy recorded in the binding dictates whether bare claims
// count toward a fail.
func checkDeliverable(reportPath, auditLogPath string, b *attest.DeliverableBinding) (bool, string, *VerifyError) {
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return false, "report read error: " + err.Error(),
			&VerifyError{Gate: "G7", Code: ErrCodeReportRead, Got: err.Error()}
	}
	gotHash := sha256hex(raw)
	if gotHash != b.SHA256 {
		return false, fmt.Sprintf("hash mismatch: got %s… want %s…",
				gotHash[:16], b.SHA256[:16]),
			&VerifyError{Gate: "G7", Code: ErrCodeReportHash, Expected: b.SHA256, Got: gotHash}
	}
	rpt, err := provenance.Parse(reportPath)
	if err != nil {
		return false, "parse error: " + err.Error(),
			&VerifyError{Gate: "G7", Code: ErrCodeReportParse, Got: err.Error()}
	}
	if auditLogPath == "" {
		return false, "audit log path required for G7 citation check",
			&VerifyError{Gate: "G7", Code: ErrCodeMissingAuditForG7}
	}
	rpt, ok, err := provenance.Validate(rpt, auditLogPath, provenance.BarePolicy(b.BarePolicy))
	if err != nil {
		return false, "validate error: " + err.Error(),
			&VerifyError{Gate: "G7", Code: ErrCodeReportValidate, Got: err.Error()}
	}
	passed := 0
	for _, v := range rpt.Validations {
		if v.Pass {
			passed++
		}
	}
	detail := fmt.Sprintf("%d/%d citations valid, %d bare claims (policy: %s)",
		passed, len(rpt.Citations), len(rpt.BareClaims), b.BarePolicy)
	if !ok || passed != len(rpt.Citations) {
		return false, detail,
			&VerifyError{Gate: "G7", Code: ErrCodeCitationInvalid,
				Count: passed, Total: len(rpt.Citations)}
	}
	return true, detail, nil
}

// sha256hex returns the hex-encoded SHA-256 of b.
func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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
