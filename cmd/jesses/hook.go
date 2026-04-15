package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/extractors/bash"
	"github.com/Hybirdss/jesses/internal/policy"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
	"github.com/Hybirdss/jesses/internal/shellparse"
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
	fake := fs.Bool("fake-rekor", false, "use in-memory FakeClient (testing only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	scopePath := filepath.Join(*sessionDir, "scope.txt")
	logPath := filepath.Join(*sessionDir, "session.log")
	envPath := filepath.Join(*sessionDir, "session.jes")

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
	if *fake {
		rc = rekor.NewFakeClient()
	} else {
		rc = rekor.NewHTTPClient(*rekorURL)
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, session.Config{
		LogPath:    logPath,
		ScopeBytes: scopeBytes,
		PrivateKey: priv,
		Rekor:      rc,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: open session: %v\n", err)
		return 1
	}

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
			enc.Encode(map[string]any{"decision": "error", "reason": err.Error()})
			continue
		}
		if action, _ := raw["_action"].(string); action == "close" {
			break
		}
		ev := hookBuildEvent(raw, pol)
		if err := sess.Append(ev); err != nil {
			enc.Encode(map[string]any{"decision": "error", "reason": err.Error()})
			continue
		}
		enc.Encode(map[string]any{
			"decision":     ev.Decision,
			"reason":       ev.Reason,
			"destinations": ev.Destinations,
		})
	}

	fin, err := sess.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: close: %v\n", err)
		return 1
	}
	env, err := attest.Build(fin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook: build: %v\n", err)
		return 1
	}
	if err := attest.WriteFile(envPath, env); err != nil {
		fmt.Fprintf(os.Stderr, "hook: write envelope: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "jesses: %s (leaves=%d, rekor=%d)\n",
		envPath, fin.LeafCount, fin.Precommit.LogEntry.LogIndex)
	return 0
}

// hookBuildEvent turns a raw tool-use JSON into an audit.Event
// with destinations extracted and a policy decision applied.
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
		PolicyRef: "",
	}

	var dests []string
	switch strings.ToLower(tool) {
	case "bash":
		cmd, _ := input["command"].(string)
		toks, err := shellparse.SplitString(cmd)
		if err != nil {
			ev.Decision = "deny"
			ev.Reason = "parse error: " + err.Error()
			return ev
		}
		for _, d := range bash.ExtractAll(toks) {
			dests = append(dests, d.Host)
		}
	case "webfetch", "websearch":
		if u, ok := input["url"].(string); ok {
			dests = append(dests, u)
		}
	case "read", "write", "edit", "glob", "grep":
		if p, ok := input["path"].(string); ok {
			dests = append(dests, "path:"+p)
		}
	}
	ev.Destinations = dests

	// Apply policy: if any destination is blocked, deny.
	ev.Decision = "allow"
	ev.Reason = "in scope"
	for _, d := range dests {
		ns, val := classifyDest(d)
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
// uses sessionDir/key.priv. If the file does not exist, generates a
// fresh key and writes it with 0600 permissions.
func loadOrCreateKey(path, sessionDir string) (ed25519.PrivateKey, error) {
	if path == "" {
		path = filepath.Join(sessionDir, "key.priv")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("jesses: key %s has wrong size %d", path, len(raw))
		}
		return ed25519.PrivateKey(raw), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// sha256hex hashes b and returns lowercase hex.
func sha256hex(b []byte) string {
	return sha256hexRaw(b)
}

// runRun implements `jesses run -- <cmd> [args]`: wrap a single shell
// command, run it, and emit a session-of-one attestation. Useful for
// ad-hoc demos and for users who don't want an agent harness.
func runRun(args []string) int {
	var sep int = -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(args) {
		fmt.Fprintln(os.Stderr, "jesses run: usage: jesses run [flags] -- <command> [args]")
		return 2
	}
	pre := args[:sep]
	cmd := strings.Join(args[sep+1:], " ")

	// Reuse the hook pipeline: synthesize one tool-use event and pipe
	// it through.
	ev := map[string]any{
		"tool":  "bash",
		"input": map[string]any{"command": cmd},
	}
	in, _ := json.Marshal(ev)
	r, w := io.Pipe()
	go func() {
		defer w.Close()
		w.Write(in)
		w.Write([]byte("\n"))
		closeAction, _ := json.Marshal(map[string]any{"_action": "close"})
		w.Write(closeAction)
		w.Write([]byte("\n"))
	}()
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	pipeR, pipeW, _ := os.Pipe()
	os.Stdin = pipeR
	go func() {
		io.Copy(pipeW, r)
		pipeW.Close()
	}()
	return runHook(pre)
}

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
