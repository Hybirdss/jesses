package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
)

// runStats implements `jesses stats <file.jes>`. Computes per-session
// hygiene metrics a triage analyst glances at before deciding whether
// to dig into the full timeline:
//
//   - event count, tool distribution, decision ratio
//   - unique hosts / paths touched
//   - deepest nesting level (subshells, bash -c, eval bombs)
//   - number of deny / warn events
//
// Output is a one-screen dashboard in monospace; --json emits
// machine-readable.
func runStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	emitJSON := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses stats: missing envelope path")
		return 2
	}
	envPath := fs.Arg(0)
	env, err := attest.ReadFile(envPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: %v\n", err)
		return 1
	}
	stmt, _, err := attest.Parse(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: parse: %v\n", err)
		return 1
	}

	logPath := envPath[:max(0, len(envPath)-4)] + ".log"
	if !fileExists(logPath) {
		logPath = sibling(envPath, "session.log")
	}
	evs, err := loadEventsForStats(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stats: events: %v\n", err)
		return 1
	}

	s := computeStats(evs)

	if *emitJSON {
		payload := map[string]any{
			"session_id":  stmt.Predicate.SessionID,
			"leaf_count":  stmt.Predicate.LeafCount,
			"stats":       s,
			"scope_hash":  stmt.Predicate.ScopeHash,
			"rekor_index": stmt.Predicate.Precommit.LogEntry.LogIndex,
		}
		out, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("session %s\n\n", stmt.Predicate.SessionID)
	fmt.Printf("  events:       %d\n", s.Total)
	fmt.Printf("  allow:        %d\n", s.Allow)
	fmt.Printf("  warn:         %d\n", s.Warn)
	fmt.Printf("  deny:         %d\n", s.Deny)
	fmt.Printf("  unique hosts: %d\n", s.UniqueHosts)
	fmt.Printf("  unique paths: %d\n", s.UniquePaths)
	fmt.Println()
	fmt.Println("  tools:")
	for _, p := range s.TopTools {
		fmt.Printf("    %-12s %d\n", p.Key, p.Count)
	}
	fmt.Println()
	fmt.Println("  top hosts:")
	for _, p := range s.TopHosts {
		fmt.Printf("    %-40s %d\n", p.Key, p.Count)
	}
	if s.Deny > 0 {
		fmt.Printf("\n  VERDICT: %d policy breach(es) — run `jesses verify` for the full gate report\n", s.Deny)
	} else {
		fmt.Printf("\n  VERDICT: all events in scope\n")
	}
	return 0
}

// Stats is the computed summary shape.
type Stats struct {
	Total       int        `json:"total"`
	Allow       int        `json:"allow"`
	Warn        int        `json:"warn"`
	Deny        int        `json:"deny"`
	UniqueHosts int        `json:"unique_hosts"`
	UniquePaths int        `json:"unique_paths"`
	TopTools    []KeyCount `json:"top_tools"`
	TopHosts    []KeyCount `json:"top_hosts"`
}

// KeyCount is a (name, count) pair used for histograms.
type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func computeStats(evs []audit.Event) Stats {
	var s Stats
	toolC := map[string]int{}
	hostC := map[string]int{}
	pathC := map[string]int{}
	for _, ev := range evs {
		s.Total++
		switch ev.Decision {
		case "allow":
			s.Allow++
		case "warn":
			s.Warn++
		case "deny":
			s.Deny++
		}
		toolC[ev.Tool]++
		for _, d := range ev.Destinations {
			if strings.HasPrefix(d, "path:") {
				pathC[strings.TrimPrefix(d, "path:")]++
			} else if strings.HasPrefix(d, "mcp:") {
				hostC[d]++
			} else {
				hostC[d]++
			}
		}
	}
	s.UniqueHosts = len(hostC)
	s.UniquePaths = len(pathC)
	s.TopTools = topK(toolC, 10)
	s.TopHosts = topK(hostC, 10)
	return s
}

func topK(m map[string]int, k int) []KeyCount {
	out := make([]KeyCount, 0, len(m))
	for key, c := range m {
		out = append(out, KeyCount{Key: key, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// loadEventsForStats is a focused audit-log reader — identical in
// spirit to verify's recomputeMerkleRoot, but only fetching
// decisions/tools/destinations, not recomputing hashes.
func loadEventsForStats(path string) ([]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var evs []audit.Event
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, err
		}
		evs = append(evs, ev)
	}
	return evs, sc.Err()
}
