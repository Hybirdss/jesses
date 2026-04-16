// Package provenance binds a deliverable (bug report, audit finding,
// compliance artifact) to the audit log events that substantiate it.
//
// The point: without binding, an LLM agent could fetch a secret
// outside the jesses-wrapped session, start a clean session, and
// paste the secret into its report. Every gate G1-G6 passes, yet
// the attestation is a lie. A8 "theater mode" in THREAT_MODEL.md.
//
// Defense: every non-trivial factual claim in the report must cite
// one or more specific events from the session's audit log. Citations
// are markdown footnotes using one of two forms:
//
//	[^ev:14]        — reference by event sequence number
//	[^hash:7a3f5c89] — reference by leaf-hash prefix (more forgery-resistant)
//
// A verifier pass (G7) checks:
//
//  1. Every citation resolves to a real event in the audit log
//  2. Every claimed event hash matches the canonical leaf hash
//  3. Every event cited appears exactly once (no fabricated reuse)
//  4. Bare (uncited) claims are counted; policy decides severity
//
// What the package does NOT do:
//   - Semantic claim verification ("does event #14's output actually
//     support the IDOR claim?") — that is human judgment. Jesses
//     makes the inspection checkable, not automatic.
//   - Format enforcement beyond markdown footnotes — a report is
//     free-form prose, jesses just indexes the citation graph.
package provenance

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/merkle"
)

// BarePolicy dictates how Validate treats claims without a citation.
type BarePolicy string

const (
	// BareAllow counts bare claims but never fails G7 on them.
	BareAllow BarePolicy = "allow"

	// BareWarn is the default — bare claims are reported as advisory.
	BareWarn BarePolicy = "warn"

	// BareStrict fails G7 if any bare claim is detected.
	BareStrict BarePolicy = "strict"
)

// Citation is one evidence reference in the report.
//
// MarkerID is the raw marker text ("ev:14" or "hash:7a3f5c89").
// CitedEventSeq and CitedEventHash identify the target event; at
// least one is set. EventTimestamp, EventTool, EventSnippet are
// filled in by Validate for the timeline appendix.
type Citation struct {
	MarkerID       string `json:"marker_id"`
	CitedEventSeq  int64  `json:"cited_event_seq"`
	CitedEventHash string `json:"cited_event_hash"`
	ClaimLine      int    `json:"claim_line"`

	// Populated during Validate for the timeline:
	EventTimestamp string `json:"event_timestamp,omitempty"`
	EventTool      string `json:"event_tool,omitempty"`
	EventSnippet   string `json:"event_snippet,omitempty"`
}

// ValidationResult is the per-citation outcome from Validate.
type ValidationResult struct {
	Citation Citation `json:"citation"`
	Pass     bool     `json:"pass"`
	Detail   string   `json:"detail"`
}

// Report is the parsed representation of a deliverable markdown file.
type Report struct {
	Path        string             `json:"path"`
	SHA256      string             `json:"sha256"`
	Citations   []Citation         `json:"citations"`
	BareClaims  []BareClaim        `json:"bare_claims"`
	RawSize     int                `json:"raw_size"`
	Validations []ValidationResult `json:"validations"`
}

// BareClaim marks a line that looks like a factual assertion but
// carries no citation. Pattern-heuristic only — "it appears that",
// "we believe", "is considered" etc. are narrative; concrete URLs,
// IPs, specific field values, API responses are facts.
type BareClaim struct {
	Line    int    `json:"line"`
	Text    string `json:"text"`
	Trigger string `json:"trigger"`
}

// footnoteRE matches [^ev:14] or [^hash:7a3f5c89] inline citations.
var footnoteRE = regexp.MustCompile(`\[\^(ev:\d+|hash:[a-fA-F0-9]{4,64})\]`)

// factPattern is a cheap heuristic for spotting "this is a fact" lines
// in a bug-report context without a citation. Patterns the agent
// typically uses when asserting evidence:
//
//	URLs / IPs / /path/style — something concrete
//	a quoted response body
//	numbers alongside units
//
// Missing a cite right after such a sentence earns a BareClaim.
var factPattern = regexp.MustCompile(
	`(?i)\b(https?://[^\s)]+|/[a-z0-9_./-]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|(?:HTTP/[12](?:\.\d)?)\s*\d{3})`,
)

// Parse reads the report file, extracts citations, flags bare claims.
// Returns the Report — Validate() separately hits the audit log.
func Parse(path string) (Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	sum := sha256.Sum256(raw)
	rpt := Report{
		Path:    path,
		SHA256:  hex.EncodeToString(sum[:]),
		RawSize: len(raw),
	}

	// Collect citations with line numbers.
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()

		// Skip the footnote definitions block at the bottom — those
		// lines start with "[^ev:N]:" and should not be counted as
		// in-prose citations (they would double-count).
		if looksLikeFootnoteDef(text) {
			continue
		}

		matches := footnoteRE.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			c, err := parseCitation(m[1], line)
			if err != nil {
				continue
			}
			rpt.Citations = append(rpt.Citations, c)
		}

		// Bare claim heuristic: lines carrying factual markers
		// without any [^ev:] / [^hash:] marker on the same line.
		if len(matches) == 0 && factPattern.MatchString(text) {
			trig := factPattern.FindString(text)
			rpt.BareClaims = append(rpt.BareClaims, BareClaim{
				Line:    line,
				Text:    strings.TrimSpace(text),
				Trigger: trig,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return rpt, err
	}
	return rpt, nil
}

// looksLikeFootnoteDef recognizes the `[^ev:14]: event #14 @ ...`
// block at the bottom of a report. Those lines are the definitions
// the in-prose `[^ev:14]` markers reference; they must not be
// counted as separate citations.
func looksLikeFootnoteDef(s string) bool {
	s = strings.TrimLeft(s, " \t")
	if !strings.HasPrefix(s, "[^") {
		return false
	}
	// The definition form is `[^MARKER]: ...` with a colon right
	// after the closing bracket.
	close := strings.Index(s, "]")
	if close < 0 {
		return false
	}
	return close+1 < len(s) && s[close+1] == ':'
}

// parseCitation turns a raw marker ID into a Citation shell (without
// the event metadata — Validate fills that in against the log).
func parseCitation(markerID string, line int) (Citation, error) {
	c := Citation{MarkerID: markerID, ClaimLine: line}
	switch {
	case strings.HasPrefix(markerID, "ev:"):
		n, err := strconv.ParseInt(markerID[3:], 10, 64)
		if err != nil {
			return c, err
		}
		c.CitedEventSeq = n
	case strings.HasPrefix(markerID, "hash:"):
		c.CitedEventHash = strings.ToLower(markerID[5:])
	default:
		return c, fmt.Errorf("unknown marker form %q", markerID)
	}
	return c, nil
}

// Validate checks each citation against the audit log. Returns the
// updated Report (with per-citation ValidationResult filled in) and
// a top-level ok flag: all mandatory-severity checks must pass.
//
// bare-policy drives how uncited claims affect ok:
//
//	allow  — ok unaffected
//	warn   — ok unaffected, but bare claims appear in validations
//	strict — ok false when any bare claim exists
func Validate(rpt Report, auditLogPath string, policy BarePolicy) (Report, bool, error) {
	events, eventsByHash, eventsBySeq, err := loadEvents(auditLogPath)
	if err != nil {
		return rpt, false, err
	}
	ok := true
	for i, c := range rpt.Citations {
		res := ValidationResult{Citation: c}
		var ev *audit.Event
		switch {
		case c.CitedEventSeq > 0 || c.MarkerID == "ev:0":
			if e, found := eventsBySeq[c.CitedEventSeq]; found {
				ev = &e
				c.CitedEventHash = leafHashHex(e)
			} else {
				res.Detail = fmt.Sprintf("ev:%d not found in audit log", c.CitedEventSeq)
				ok = false
			}
		case c.CitedEventHash != "":
			for _, e := range matchByHashPrefix(eventsByHash, c.CitedEventHash) {
				ev = &e
				c.CitedEventHash = leafHashHex(e)
				c.CitedEventSeq = int64(e.Seq) //nolint:gosec // audit Seq is a monotonic counter; practical session sizes stay well within int64 range
				break
			}
			if ev == nil {
				res.Detail = fmt.Sprintf("hash:%s does not match any event leaf", c.CitedEventHash)
				ok = false
			}
		default:
			res.Detail = "citation missing both seq and hash"
			ok = false
		}
		if ev != nil {
			c.EventTimestamp = ev.TS
			c.EventTool = ev.Tool
			c.EventSnippet = snippetOf(*ev)
			res.Pass = true
			res.Detail = fmt.Sprintf("event #%d @ %s — %s", ev.Seq, ev.TS, c.EventSnippet)
		}
		res.Citation = c
		rpt.Validations = append(rpt.Validations, res)
		rpt.Citations[i] = c
	}
	_ = events

	if policy == BareStrict && len(rpt.BareClaims) > 0 {
		ok = false
	}
	return rpt, ok, nil
}

// FormatCitation returns the footnote definition block for one
// event — what `jesses cite` prints for the agent to paste into
// the report's footnote section.
func FormatCitation(e audit.Event) string {
	h := leafHashHex(e)
	return fmt.Sprintf(
		"[^ev:%d]: event #%d @ %s — `%s: %s` — sha256 `%s`",
		e.Seq, e.Seq, e.TS, e.Tool, snippetOf(e), h,
	)
}

// GenerateTimeline produces a readable markdown appendix of the
// session: a header summary, a visual timeline in a fenced block
// (one line per event with emoji markers for cited/denied), a
// flagged-events section expanding every deny event with snippet
// and reason, and a cited-events section naming the footnote
// references. Rendered markdown viewers (GitHub, Gitea, etc.)
// preserve spacing inside the fenced block so columns line up.
func GenerateTimeline(auditLogPath string, citations []Citation) (string, error) {
	events, _, _, err := loadEvents(auditLogPath)
	if err != nil {
		return "", err
	}
	citedBySeq := map[uint64]string{}
	for _, c := range citations {
		if c.CitedEventSeq > 0 || c.MarkerID == "ev:0" {
			citedBySeq[uint64(c.CitedEventSeq)] = c.MarkerID
		}
	}

	var (
		allowCount, warnCount, denyCount, commitCount int
		denies                                        []auditEvt
		citeds                                        []auditEvt
	)
	for _, e := range events {
		switch e.Decision {
		case "allow":
			allowCount++
		case "warn":
			warnCount++
		case "deny":
			denyCount++
			denies = append(denies, e)
		case "commit":
			commitCount++
		}
		if _, ok := citedBySeq[e.Seq]; ok {
			citeds = append(citeds, e)
		}
	}
	sessionID := ""
	if len(events) > 0 {
		sessionID = events[0].PolicyRef
	}

	var sb strings.Builder

	sb.WriteString("# Session Timeline\n\n")
	if sessionID != "" {
		sb.WriteString("> scope hash `" + sessionID + "`  \n")
	}
	sb.WriteString(fmt.Sprintf(
		"> %d events · %d allow · %d warn · **%d deny** · %d cited · %s\n\n",
		len(events), allowCount, warnCount, denyCount, len(citeds),
		verdictMarker(denyCount),
	))

	sb.WriteString("## Timeline\n\n")
	sb.WriteString("```\n")
	for _, e := range events {
		marker := "•"
		if e.Decision == "deny" {
			marker = "▼"
		} else if _, ok := citedBySeq[e.Seq]; ok {
			marker = "★"
		}
		ts := shortTime(e.TS)
		decision := strings.ToUpper(e.Decision)
		if len(decision) > 6 {
			decision = decision[:6]
		}
		tool := e.Tool
		if len(tool) > 16 {
			tool = tool[:16]
		}
		sb.WriteString(fmt.Sprintf("%s %s  %s  %-16s  %-6s  %s\n",
			ts, marker,
			fmt.Sprintf("#%-3d", e.Seq),
			tool, decision,
			snippetOf(e),
		))
	}
	sb.WriteString("```\n\n")

	if len(denies) > 0 {
		sb.WriteString("## Flagged events\n\n")
		for _, e := range denies {
			sb.WriteString(fmt.Sprintf("### ▼ #%d  %s\n\n", e.Seq, e.Tool))
			sb.WriteString("- **decision**: deny\n")
			sb.WriteString(fmt.Sprintf("- **reason**: %s\n", e.Reason))
			if len(e.Destinations) > 0 {
				sb.WriteString(fmt.Sprintf("- **destinations**: %s\n", strings.Join(e.Destinations, ", ")))
			}
			sb.WriteString(fmt.Sprintf("- **when**: %s\n\n", e.TS))
			sb.WriteString("```\n")
			sb.WriteString(snippetOf(e))
			sb.WriteString("\n```\n\n")
		}
	}

	if len(citeds) > 0 {
		sb.WriteString("## Cited events (trusted by G7)\n\n")
		for _, e := range citeds {
			marker := citedBySeq[e.Seq]
			sb.WriteString(fmt.Sprintf("- `[^%s]` → #%d  `%s`\n", marker, e.Seq, snippetOf(e)))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// auditEvt is a local type alias used to keep the imports minimal in
// GenerateTimeline's helpers without re-exposing audit.Event at the
// top of the package.
type auditEvt = audit.Event

// verdictMarker returns a one-word status indicator for the timeline
// header, based on whether any deny events were recorded.
func verdictMarker(denyCount int) string {
	if denyCount == 0 {
		return "**verdict: clean**"
	}
	return "**verdict: invalid**"
}

// shortTime extracts the HH:MM:SS portion from an RFC3339Nano
// timestamp for compact timeline rendering. Falls back to the full
// string when parsing fails.
func shortTime(ts string) string {
	if len(ts) >= 19 && ts[10] == 'T' {
		return ts[11:19]
	}
	return ts
}

// loadEvents reads an audit log and returns the events in source
// order plus lookup maps.
func loadEvents(path string) ([]audit.Event, map[string]audit.Event, map[int64]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var events []audit.Event
	byHash := map[string]audit.Event{}
	bySeq := map[int64]audit.Event{}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, nil, nil, err
		}
		events = append(events, ev)
		h := leafHashHex(ev)
		byHash[h] = ev
		bySeq[int64(ev.Seq)] = ev //nolint:gosec // audit Seq is a monotonic counter; practical session sizes stay well within int64 range
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, err
	}
	return events, byHash, bySeq, nil
}

// leafHashHex recomputes the canonical Merkle leaf hash for an
// event. Reuses audit.CanonicalJSON + merkle.HashLeaf.
func leafHashHex(e audit.Event) string {
	canon, err := audit.CanonicalJSON(e)
	if err != nil {
		return ""
	}
	h := merkle.HashLeaf(canon)
	return hex.EncodeToString(h[:])
}

// matchByHashPrefix returns events whose full leaf hash starts with
// the given prefix. Prefix length of 4+ hex chars keeps the odds of
// a collision below 1 in 65k for any realistic session.
func matchByHashPrefix(byHash map[string]audit.Event, prefix string) []audit.Event {
	prefix = strings.ToLower(prefix)
	keys := make([]string, 0, len(byHash))
	for k := range byHash {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []audit.Event
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			out = append(out, byHash[k])
		}
	}
	return out
}

// snippetOf returns a short human-readable summary of an event —
// the tool call's first 80 characters without newlines. Used in
// the timeline view and in cite output.
func snippetOf(e audit.Event) string {
	s := ""
	if e.Input != nil {
		if cmd, ok := e.Input["command"].(string); ok {
			s = cmd
		} else if u, ok := e.Input["url"].(string); ok {
			s = u
		} else if p, ok := e.Input["path"].(string); ok {
			s = p
		} else if p, ok := e.Input["file_path"].(string); ok {
			s = p
		}
	}
	if s == "" {
		s = strings.Join(e.Destinations, ", ")
	}
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

// ErrNoSuchEvent is returned by LookupEvent for missing sequences.
var ErrNoSuchEvent = errors.New("provenance: no such event")

// LookupEvent fetches a single event by seq from an audit log.
// Used by the `jesses cite` subcommand.
func LookupEvent(auditLogPath string, seq int64) (audit.Event, error) {
	_, _, bySeq, err := loadEvents(auditLogPath)
	if err != nil {
		return audit.Event{}, err
	}
	if e, ok := bySeq[seq]; ok {
		return e, nil
	}
	return audit.Event{}, ErrNoSuchEvent
}
