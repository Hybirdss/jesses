package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/ots"
	"github.com/Hybirdss/jesses/internal/rekor"
	"github.com/Hybirdss/jesses/internal/session"
)

// runRun implements `jesses run [flags] -- <cmd> [args...]`.
//
// Process-bound session model (v0.1). A single command is wrapped:
//
//  1. Session opens (Rekor pre-commit, audit log created).
//  2. Event #1 after the precommit is a synthetic `jesses.wrap_start`
//     event recording the wrapped argv, its concatenated SHA-256,
//     cwd, and parent PID. This is what ties the attestation to a
//     specific launcher invocation.
//  3. The child command is exec'd. Its stdout and stderr are teed to
//     session.stdout.log and session.stderr.log inside the session
//     directory so reviewers have the full captured output.
//  4. On child exit, a `jesses.wrap_end` event records the exit
//     code, signal (if any), and wall-clock duration.
//  5. Session closes, envelope is signed, exit code of the child is
//     returned to the caller.
//
// What this does NOT do at v0.1: intercept the child's own tool
// calls (file ops, network, subprocesses). A child that wants each
// of its tool calls recorded needs to speak the jesses-hook protocol
// on stdin to a separately-running `jesses hook`. The `run`
// subcommand is the simpler model — "wrap one thing, attest that
// it ran."
//
// Why this is what answers Q1 ("when does tracking start and end?"):
// the session's boundary is explicitly the `jesses run` process
// itself. StartedAt = session.Open; wrap_start = exec time; the
// wrapped command exists as a child process between wrap_start and
// wrap_end, with captured IO. Claims outside [StartedAt, EndedAt]
// are not attested — this is stated in the envelope explicitly via
// the wrap event's metadata.
func runRun(args []string) int {
	// Split args on `--` separator. Everything before goes to our
	// flag parser; everything after is the command + its arguments.
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	var preArgs, cmdArgs []string
	if sepIdx < 0 {
		preArgs = args
	} else {
		preArgs = args[:sepIdx]
		cmdArgs = args[sepIdx+1:]
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "jesses run: missing command")
		fmt.Fprintln(os.Stderr, "usage: jesses run [flags] -- <cmd> [args...]")
		return 2
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	sessionDir := fs.String("session-dir", ".", "directory holding session artifacts")
	keyPath := fs.String("key", "", "ed25519 private key path (generated if missing)")
	rekorURL := fs.String("rekor", "https://rekor.sigstore.dev", "Rekor server URL")
	otsCalendar := fs.String("ots", "", "OTS calendar URL (empty = skip OTS)")
	fake := fs.Bool("fake-rekor", false, "use in-memory FakeClient (testing only)")
	bindReport := fs.String("report", "", "bind this markdown report to the envelope on close")
	if err := fs.Parse(preArgs); err != nil {
		return 2
	}

	if err := os.MkdirAll(*sessionDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "run: mkdir %s: %v\n", *sessionDir, err)
		return 1
	}

	scopePath := filepath.Join(*sessionDir, "scope.txt")
	logPath := filepath.Join(*sessionDir, "session.log")
	envPath := filepath.Join(*sessionDir, "session.jes")
	stdoutPath := filepath.Join(*sessionDir, "session.stdout.log")
	stderrPath := filepath.Join(*sessionDir, "session.stderr.log")

	scopeBytes, err := os.ReadFile(scopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: read scope (%s): %v — try `jesses init-scope` first\n", scopePath, err)
		return 1
	}

	priv, err := loadOrCreateKey(*keyPath, *sessionDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: key: %v\n", err)
		return 1
	}

	var rc rekor.Client
	var oc ots.Client
	if *fake {
		rc = rekor.NewFakeClient()
		oc = ots.NewFakeClient()
	} else {
		rc = rekor.NewHTTPClient(*rekorURL)
		if *otsCalendar != "" {
			oc = ots.NewHTTPClient(*otsCalendar)
		}
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, session.Config{
		LogPath:    logPath,
		ScopeBytes: scopeBytes,
		PrivateKey: priv,
		Rekor:      rc,
		OTS:        oc,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: open session: %v\n", err)
		return 1
	}

	// Event — jesses.wrap_start: ties the attestation to the specific
	// process invocation. This is the Q1 answer in audit form: the
	// wrap-start/wrap-end pair bounds the claim's time window.
	argvJoined := joinArgs(cmdArgs)
	argvHash := sha256.Sum256([]byte(argvJoined))
	cwd, _ := os.Getwd()

	wrapStart := time.Now().UTC()
	_ = sess.Append(audit.Event{
		TS:        wrapStart.Format(time.RFC3339Nano),
		Tool:      "jesses.wrap_start",
		InputHash: hex.EncodeToString(argvHash[:]),
		Input: map[string]any{
			"argv":        cmdArgs,
			"argv_sha256": hex.EncodeToString(argvHash[:]),
			"cwd":         cwd,
			"parent_pid":  os.Getpid(),
		},
		Decision: "commit",
		Reason:   "process-bound wrap begin",
	})

	// Exec the child and tee stdout/stderr.
	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	stdoutF, _ := os.Create(stdoutPath)
	stderrF, _ := os.Create(stderrPath)
	defer stdoutF.Close()
	defer stderrF.Close()
	child.Stdout = io.MultiWriter(os.Stdout, stdoutF)
	child.Stderr = io.MultiWriter(os.Stderr, stderrF)
	child.Stdin = os.Stdin
	child.Env = append(os.Environ(),
		"JESSES_SESSION_DIR="+(*sessionDir),
		"JESSES_WRAP_PID="+fmt.Sprint(os.Getpid()),
	)

	childErr := child.Run()
	wrapEnd := time.Now().UTC()

	exitCode := 0
	signalName := ""
	if childErr != nil {
		if ee, ok := childErr.(*exec.ExitError); ok {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
				if ws.Signaled() {
					signalName = ws.Signal().String()
				}
			} else {
				exitCode = 1
			}
		} else {
			exitCode = 1
			fmt.Fprintf(os.Stderr, "run: child exec: %v\n", childErr)
		}
	}

	_ = sess.Append(audit.Event{
		TS:        wrapEnd.Format(time.RFC3339Nano),
		Tool:      "jesses.wrap_end",
		InputHash: hex.EncodeToString(argvHash[:]),
		Input: map[string]any{
			"exit_code":   exitCode,
			"signal":      signalName,
			"duration_ms": wrapEnd.Sub(wrapStart).Milliseconds(),
			"stdout_log":  filepath.Base(stdoutPath),
			"stderr_log":  filepath.Base(stderrPath),
		},
		Decision: "commit",
		Reason:   "process-bound wrap end",
	})

	fin, err := sess.Close(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: close: %v\n", err)
		return 1
	}
	env, err := attest.Build(fin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: build: %v\n", err)
		return 1
	}

	// Write envelope, then optionally bind a report.
	out, _ := json.MarshalIndent(env, "", "  ")
	_ = os.WriteFile(envPath, out, 0o644)

	if *bindReport != "" {
		if rc := runReport([]string{
			"--bind", *bindReport,
			"--session-dir", *sessionDir,
			envPath,
		}); rc != 0 {
			fmt.Fprintf(os.Stderr, "run: report --bind failed with exit %d\n", rc)
			return rc
		}
	}

	fmt.Fprintf(os.Stderr, "jesses: wrapped %q (exit=%d, duration=%dms) → %s\n",
		argvJoined, exitCode, wrapEnd.Sub(wrapStart).Milliseconds(), envPath)
	return exitCode
}

// joinArgs concatenates argv with single spaces for hashing + display.
// Shell-quoting is not applied — the hash is over the exact slice the
// launcher passed, shell-unescaping is irrelevant at this layer.
func joinArgs(args []string) string {
	var b bytes.Buffer
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a)
	}
	return b.String()
}

// ensurePrivKey is a thin re-export of loadOrCreateKey for readability
// inside runRun's call site. The actual implementation lives in
// hook.go because both subcommands need it.
func ensurePrivKey(path, dir string) (ed25519.PrivateKey, error) {
	return loadOrCreateKey(path, dir)
}
