package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/verify"
)

// runVerify implements `jesses verify <file.jes>`.
//
// Required: the path to the .jes envelope.
// Optional flags:
//
//	-log PATH        path to audit log (enables G2 Merkle + G5 policy)
//	-scope PATH      path to scope.txt (enables G4 scope hash check)
//	-rekor URL       Rekor server URL (default rekor.sigstore.dev)
//	-offline         skip any Rekor network call (G3 local only)
//	-json            emit the Report as JSON rather than human text
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	logPath := fs.String("log", "", "path to audit log (enables G2 and G5)")
	scopePath := fs.String("scope", "", "path to scope.txt (enables G4)")
	rekorURL := fs.String("rekor", "https://rekor.sigstore.dev", "Rekor server URL")
	offline := fs.Bool("offline", false, "skip Rekor network calls (G3 local-only)")
	emitJSON := fs.Bool("json", false, "emit JSON report instead of human text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses verify: missing envelope path")
		fs.Usage()
		return 2
	}
	envPath := fs.Arg(0)

	// Default log/scope paths to siblings of the envelope when not given.
	if *logPath == "" {
		if p := envPath[:max(0, len(envPath)-4)] + ".log"; fileExists(p) {
			*logPath = p
		}
	}
	if *scopePath == "" {
		if p := sibling(envPath, "scope.txt"); fileExists(p) {
			*scopePath = p
		}
	}

	opts := verify.Options{
		EnvelopePath: envPath,
		AuditLogPath: *logPath,
		ScopePath:    *scopePath,
	}
	if !*offline {
		opts.RekorClient = rekor.NewHTTPClient(*rekorURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rpt, err := verify.Verify(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return 1
	}
	if *emitJSON {
		out, _ := json.MarshalIndent(rpt, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Print(verify.Render(rpt))
	}
	if !rpt.OK {
		return 1
	}
	return 0
}

// sibling returns a path in the same directory as p, named to name.
// Used for default scope.txt lookup.
func sibling(p, name string) string {
	slash := strings.LastIndexByte(p, '/')
	if slash < 0 {
		return name
	}
	return p[:slash+1] + name
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
