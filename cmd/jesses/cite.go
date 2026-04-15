package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Hybirdss/jesses/internal/provenance"
)

// runCite implements `jesses cite <seq> [--log <path>]`.
//
// The agent, mid-session, wants to cite an earlier event in the
// report it is writing. This subcommand reads the event at <seq>
// from the audit log, recomputes its canonical Merkle leaf hash,
// and prints a markdown footnote definition the agent pastes into
// its report.md:
//
//	$ jesses cite 14
//	[^ev:14]: event #14 @ 2026-04-16T12:05:22Z — `bash: curl https://api.target.com/v1/users/42` — sha256 `7a3f5c89...`
//
// The line is deterministic in session bytes — an independent
// verifier reading the report and the audit log recomputes the
// same hash and validates the citation.
func runCite(args []string) int {
	fs := flag.NewFlagSet("cite", flag.ContinueOnError)
	logPath := fs.String("log", "", "path to audit log (default session.log in cwd)")
	sessionDir := fs.String("session-dir", ".", "directory holding session.log (used when --log not set)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses cite: missing event sequence number")
		fmt.Fprintln(os.Stderr, "usage: jesses cite <seq> [--log <path>]")
		return 2
	}
	seq, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cite: bad sequence %q: %v\n", fs.Arg(0), err)
		return 2
	}

	path := *logPath
	if path == "" {
		path = filepath.Join(*sessionDir, "session.log")
	}

	ev, err := provenance.LookupEvent(path, seq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cite: %v\n", err)
		return 1
	}
	fmt.Println(provenance.FormatCitation(ev))
	return 0
}
