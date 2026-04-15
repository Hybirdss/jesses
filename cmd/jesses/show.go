package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/render"
)

// runShow implements `jesses show <file.jes>`.
//
// Pretty-print an envelope without cryptographic verification.
// Complements `jesses verify` (which checks) — `show` just tells you
// what the envelope CLAIMS. Useful for:
//
//   - editor users opening a .jes out of curiosity (raw JSON +
//     base64 is illegible)
//   - quickly scanning an envelope's metadata (session id, start/end,
//     merkle root, rekor index, binding) without doing network
//     round-trips for verification
//   - showing the envelope inside a bug-report readme or PR body
//
// Output is nested boxes per logical section: session / audit / rekor
// pre-commit / OTS anchor / deliverable binding / signatures. Colors
// auto-detect terminal + NO_COLOR just like verify/stats.
func runShow(args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	emitJSON := fs.Bool("json", false, "emit the parsed Statement as JSON instead of the pretty view")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses show: missing envelope path")
		fmt.Fprintln(os.Stderr, "usage: jesses show [--json] <file.jes>")
		return 2
	}
	envPath := fs.Arg(0)

	env, err := attest.ReadFile(envPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "show: %v\n", err)
		return 1
	}
	stmt, _, err := attest.Parse(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "show: parse: %v\n", err)
		return 1
	}

	if *emitJSON {
		out, _ := json.MarshalIndent(stmt, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	st := render.NewStyle(os.Stdout)
	fmt.Print(renderEnvelope(envPath, env, stmt, st))
	return 0
}

// renderEnvelope is pure: no I/O. Returned string is the full
// pretty view ready to Write to stdout.
func renderEnvelope(path string, env attest.Envelope, stmt attest.Statement, st render.Style) string {
	const width = 74
	p := stmt.Predicate

	header := []string{
		kv(st, "type", "in-toto Statement V1 · DSSE-ish · ed25519 signed"),
		kv(st, "predicate", p.SchemaVersion+"  ·  "+stmt.PredicateType),
	}

	session := []string{
		kv(st, "id", p.SessionID),
		kv(st, "started", p.StartedAt),
		kv(st, "ended", p.EndedAt+"   "+st.Dim("("+formatDuration(p.StartedAt, p.EndedAt)+")")),
		kv(st, "scope hash", st.Cyan(render.HexTrunc(p.ScopeHash, 16))+st.Dim("   (sha256)")),
		kv(st, "pub key", st.Cyan(render.HexTrunc(p.PubKey, 16))+st.Dim("   (ed25519)")),
	}

	audit := []string{
		kv(st, "merkle root", st.Cyan(render.HexTrunc(p.MerkleRoot, 20))),
		kv(st, "leaf count", fmt.Sprintf("%d", p.LeafCount)),
	}

	rekorSection := []string{
		kv(st, "log index", fmt.Sprintf("%d", p.Precommit.LogEntry.LogIndex)),
		kv(st, "log id", render.HexTrunc(p.Precommit.LogEntry.LogID, 20)),
		kv(st, "signed at", p.Precommit.LogEntry.SignedAt.Format(time.RFC3339)),
		kv(st, "body hash", st.Cyan(render.HexTrunc(p.Precommit.LogEntry.BodyHash, 20))),
	}

	sections := []render.Section{
		{Label: "", Lines: header},
		{Label: "session", Lines: session},
		{Label: "audit log", Lines: audit},
		{Label: "pre-commit (rekor)", Lines: rekorSection},
	}

	if p.OTSReceipt.CalendarURL != "" || p.OTSError != "" {
		ots := []string{}
		if p.OTSError != "" {
			ots = append(ots, kv(st, "status", st.BoldRed("error")))
			ots = append(ots, kv(st, "message", p.OTSError))
		} else {
			statusStr := p.OTSReceipt.Status
			if statusStr == "confirmed" {
				statusStr = st.BoldGreen(statusStr)
			} else {
				statusStr = st.Yellow(statusStr)
			}
			ots = append(ots, kv(st, "status", statusStr))
			ots = append(ots, kv(st, "calendar", p.OTSReceipt.CalendarURL))
			ots = append(ots, kv(st, "submitted", p.OTSReceipt.SubmittedAt.Format(time.RFC3339)))
			ots = append(ots, kv(st, "digest", st.Cyan(render.HexTrunc(p.OTSReceipt.Digest, 20))))
		}
		sections = append(sections, render.Section{Label: "ots anchor", Lines: ots})
	}

	if p.DeliverableBinding != nil {
		b := p.DeliverableBinding
		deliverable := []string{
			kv(st, "path", b.Path),
			kv(st, "sha256", st.Cyan(render.HexTrunc(b.SHA256, 20))),
			kv(st, "citations", fmt.Sprintf("%d", b.CitationCount)),
			kv(st, "bare claims", fmt.Sprintf("%d  %s", b.BareClaimCount, st.Dim("(policy: "+b.BarePolicy+")"))),
		}
		sections = append(sections, render.Section{Label: "deliverable binding", Lines: deliverable})
	}

	sigs := []string{}
	for i, sig := range env.Signatures {
		sigs = append(sigs, kv(st, fmt.Sprintf("sig %d", i+1),
			"keyid "+st.Cyan(render.HexTrunc(sig.KeyID, 20))))
	}
	if len(sigs) == 0 {
		sigs = []string{st.Dim("(no signatures)")}
	}
	sections = append(sections, render.Section{Label: "signatures", Lines: sigs})

	title := "envelope   " + st.Dim(path)
	out := st.Box(title, sections, width)
	out += "\n"
	out += st.Dim("  verify cryptographically:  jesses verify ") + path + "\n"
	return out
}

// kv formats a key-value line with aligned key column for use inside
// a Box section. keys are shown dim, values in default color.
func kv(st render.Style, key, value string) string {
	return fmt.Sprintf("%-14s %s", st.Dim(key), value)
}

// formatDuration parses two RFC3339Nano strings and returns a human-
// friendly duration string (5m 14s). Falls back to the raw strings
// when parsing fails.
func formatDuration(startStr, endStr string) string {
	start, err1 := time.Parse(time.RFC3339Nano, startStr)
	end, err2 := time.Parse(time.RFC3339Nano, endStr)
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	d := end.Sub(start)
	if d < 0 {
		return render.Duration(-d) + " reverse"
	}
	return render.Duration(d)
}
