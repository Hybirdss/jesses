package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/extractors/dispatch"
	"github.com/Hybirdss/jesses/internal/keyring"
	"github.com/Hybirdss/jesses/internal/oplog"
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/policy"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
)

// runHook implements `jesses hook`. Reads tool-use events as line-
// delimited JSON from stdin, evaluates each against the loaded
// scope.txt, writes each to the session audit log, and echoes the
// policy decision on stdout as JSON.
//
// This is the integration point for agent harnesses: Claude Code,
// Cursor, a homebrew harness, etc. pipe their tool events through
// here. The session lifecycle is managed by the caller opening and
// closing the hook process around a logical session.
//
// Special lines:
//
//	{"_action":"close"}  — finalize the session and emit the envelope
//
// Stdin message shape (one JSON object per line):
//
//	{"tool":"bash","input":{"command":"curl https://api.target.com/..."}}
//	{"tool":"write","input":{"path":"/tmp/x","contents":"..."}}
//	{"tool":"read","input":{"path":"/etc/passwd"}}
func runHook(args []string) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	sessionDir := fs.String("session-dir", ".", "directory that holds session.log, scope.txt, session.jes")
	keyPath := fs.String("key", "", "path to ed25519 private key (generated if missing)")
	rekorURL := fs.String("rekor", "https://rekor.sigstore.dev", "Rekor server URL")
	otsCalendar := fs.String("ots", "", "OTS calendar URL (empty = skip OTS anchoring)")
	fake := fs.Bool("fake-rekor", false, "use in-memory FakeClient (testing only; also enables fake OTS)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	scopePath := filepath.Join(*sessionDir, "scope.txt")
	logPath := filepath.Join(*sessionDir, "session.log")
	envPath := filepath.Join(*sessionDir, "session.jes")
	opPath := filepath.Join(*sessionDir, "operational.log")

	scopeBytes, err := os.ReadFile(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: read scope: %v\n", err)
		return 1
	}
	pol, err := policy.ParseBytes(scopeBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: parse scope: %v\n", err)
		return 1
	}

	priv, err := loadOrCreateKey(*keyPath, *sessionDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: key: %v\n", err)
		return 1
	}

	var rc rekor.Client
	var oc ots.Client
	if *fake {
		var err error
		rc, oc, err = newFakeClients()
		if err != nil {
			fmt.Fprintf(os.Stderr, "hook: %v\n", err)
			return 1
		}
	} else {
		rc = rekor.NewHTTPClient(*rekorURL)
		if *otsCalendar != "" {
			oc = ots.NewHTTPClient(*otsCalendar)
		}
	}

	// operational.log is opened BEFORE session so a session-open
	// failure can be recorded. Falls back to a Nop logger if the file
	// cannot be created — we do not want to block hunting on a
	// diagnostic log write failure.
	var op oplog.Writer
	opLogger, opErr := oplog.Open(opPath)
	if opErr != nil {
		fmt.Fprintf(os.Stderr, "hook: operational.log: %v (continuing with no-op logger)\n", opErr)
		op = oplog.Nop{}
	} else {
		op = opLogger
	}
	defer op.Close()

	ctx := context.Background()
	sess, err := session.Open(ctx, session.Config{
		LogPath:    logPath,
		ScopeBytes: scopeBytes,
		PrivateKey: priv,
		Rekor:      rc,
		OTS:        oc,
	})
	if err != nil {
		_ = op.Error("open", err.Error())
		fmt.Fprintf(os.Stderr, "hook: open session: %v\n", err)
		return 1
	}
	_ = op.Info("open", "session opened")

	enc := json.NewEncoder(os.Stdout)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			// Only the error message is logged — never the raw line,
			// which may contain secrets the hook would otherwise never
			// see in clear form.
			_ = op.Warn("parse", err.Error())
			enc.Encode(map[string]any{"decision": "error", "reason": err.Error()})
			continue
		}
		if action, _ := raw["_action"].(string); action == "close" {
			break
		}
		ev := hookBuildEvent(raw, pol)
		if err := sess.Append(ev); err != nil {
			_ = op.ErrorAt(ev.Seq, "append", err.Error())
			enc.Encode(map[string]any{"decision": "error", "reason": err.Error()})
			continue
		}
		enc.Encode(map[string]any{
			"decision":     ev.Decision,
			"reason":       ev.Reason,
			"destinations": ev.Destinations,
		})
	}

	fin, err := sess.Close(ctx)
	if err != nil {
		_ = op.Error("close", err.Error())
		fmt.Fprintf(os.Stderr, "hook: close: %v\n", err)
		return 1
	}
	env, err := attest.Build(fin)
	if err != nil {
		_ = op.Error("build", err.Error())
		fmt.Fprintf(os.Stderr, "hook: build: %v\n", err)
		return 1
	}
	if err := attest.WriteFile(envPath, env); err != nil {
		_ = op.Error("write", err.Error())
		fmt.Fprintf(os.Stderr, "hook: write envelope: %v\n", err)
		return 1
	}
	_ = op.Info("close", fmt.Sprintf("envelope written leaves=%d rekor=%d", fin.LeafCount, fin.Precommit.LogEntry.LogIndex))
	fmt.Fprintf(os.Stderr, "jesses: %s (leaves=%d, rekor=%d)\n",
		envPath, fin.LeafCount, fin.Precommit.LogEntry.LogIndex)
	return 0
}

// hookBuildEvent turns a raw tool-use JSON into an audit.Event with
// destinations extracted (via the dispatch package) and a policy
// decision applied. Any destination blocked by scope causes an
// immediate deny; any warn-eligible destination leaves the event
// marked "warn" but does not short-circuit.
func hookBuildEvent(raw map[string]any, pol *policy.Policy) audit.Event {
	tool, _ := raw["tool"].(string)
	input, _ := raw["input"].(map[string]any)
	inputJSON, _ := json.Marshal(input)
	ih := sha256hex(inputJSON)

	ev := audit.Event{
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		Tool:      tool,
		InputHash: ih,
		Input:     input,
	}

	dsts, err := dispatch.Extract(raw)
	if err != nil {
		ev.Decision = "deny"
		ev.Reason = "extractor error: " + err.Error()
		return ev
	}

	// Fan destinations into the audit record.
	var destStrs []string
	for _, d := range dsts {
		destStrs = append(destStrs, destinationIdentifier(d.Kind, d.Host, d.Path))
	}
	ev.Destinations = destStrs

	// Apply policy: first blocking destination fails the whole event.
	ev.Decision = "allow"
	ev.Reason = "in scope"
	for _, d := range dsts {
		ns, val := classifyKindHost(d.Kind, d.Host, d.Path)
		dec := pol.Evaluate(ns, val)
		switch dec.Verdict {
		case policy.VerdictBlock:
			ev.Decision = "deny"
			ev.Reason = dec.Reason
			return ev
		case policy.VerdictWarn:
			ev.Decision = "warn"
			ev.Reason = dec.Reason
		}
	}
	return ev
}

// destinationIdentifier composes a string the policy layer can read.
// Path-namespace destinations keep the "path:" prefix; mcp keep the
// mcp: prefix they already carry; hosts go as-is.
func destinationIdentifier(kind, host, path string) string {
	switch {
	case strings.HasPrefix(kind, "path:"):
		return "path:" + path
	case kind == "mcp":
		return host
	default:
		if host != "" {
			return host
		}
		return path
	}
}

// classifyKindHost maps an extractors.Destination to a policy
// namespace + value for evaluation.
func classifyKindHost(kind, host, path string) (policy.Namespace, string) {
	switch {
	case strings.HasPrefix(kind, "path:"):
		return policy.NSPath, path
	case kind == "mcp":
		return policy.NSMCP, host
	}
	return classifyDest(host)
}

// classifyDest inspects a destination string and returns the policy
// namespace to match against. A naive shape test is enough for v0.1:
//
//	path:foo        → NSPath
//	mcp:foo         → NSMCP
//	<chain>:0x...   → NSContract
//	<org>/<repo>    → NSRepo
//	<host>          → NSHost
func classifyDest(d string) (policy.Namespace, string) {
	if strings.HasPrefix(d, "path:") {
		return policy.NSPath, strings.TrimPrefix(d, "path:")
	}
	if strings.HasPrefix(d, "mcp:") {
		return policy.NSMCP, d
	}
	// contract address: <chain>:0x[hex]
	if colon := strings.IndexByte(d, ':'); colon > 0 && strings.HasPrefix(d[colon+1:], "0x") {
		return policy.NSContract, d
	}
	// repo shape: contains exactly one /, no dots
	if slash := strings.IndexByte(d, '/'); slash > 0 && !strings.ContainsRune(d, '.') && !strings.ContainsRune(d, ':') {
		return policy.NSRepo, d
	}
	return policy.NSHost, d
}

// loadOrCreateKey loads the ed25519 key at path. If path is empty,
// uses sessionDir/key.priv. If the file does not exist, a fresh key
// is generated and persisted with 0600 permissions via the keyring
// package. A permission warning is emitted to stderr when an existing
// key is group/world-readable.
func loadOrCreateKey(path, sessionDir string) (ed25519.PrivateKey, error) {
	if path == "" {
		path = filepath.Join(sessionDir, "key.priv")
	}
	priv, _, err := keyring.LoadOrCreate(path, os.Stderr)
	return priv, err
}

// sha256hex hashes b and returns lowercase hex.
func sha256hex(b []byte) string {
	return sha256hexRaw(b)
}

// runRun moved to run.go (process-bound wrap semantics).

// runInitScope writes a scope.txt template into the current dir.
func runInitScope(args []string) int {
	fs := flag.NewFlagSet("init-scope", flag.ContinueOnError)
	out := fs.String("out", "scope.txt", "path to write")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fileExists(*out) {
		fmt.Fprintf(os.Stderr, "jesses init-scope: %s already exists\n", *out)
		return 1
	}
	template := `# scope.txt — jesses authorization policy
# Syntax:
#   mode: strict        # unpoliced destinations are blocked
#   mode: advisory      # unpoliced destinations are warned, not blocked
#
#   in:  *.target.com   # allow any subdomain of target.com
#   out: admin.target.com  # explicit block, wins over in:
#   in:  path:/tmp/**       # allow file paths under /tmp
#   in:  mcp:srv            # allow MCP server srv (+ srv:tool)
#   in:  ethereum:0xAbC...  # allow contract address (case-insensitive)
#   in:  owner/repo          # allow GitHub repo owner/repo
#
# Rules: exclusion-first. Every out: is evaluated before any in:.
# First match wins within the in: block.

mode: strict

# Allow your target program's primary domain.
in: *.target.com

# Explicit block for known sensitive endpoints even under target.com.
out: admin.target.com

# File access stays in the repository root.
in: path:.
in: path:/tmp/**
`
	return writeFileOrDie(*out, []byte(template))
}

func writeFileOrDie(path string, data []byte) int {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "jesses: write %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "jesses: wrote %s\n", path)
	return 0
}
