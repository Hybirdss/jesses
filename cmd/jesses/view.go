package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Hybirdss/jesses/internal/attest"
	"github.com/Hybirdss/jesses/internal/audit"
	"github.com/Hybirdss/jesses/internal/verify"
)

//go:embed viewer/index.html
var viewerHTML []byte

// runView implements `jesses view <file.jes>`. It spawns a localhost
// HTTP server on an ephemeral port, renders the envelope's timeline
// as a single-page viewer, and opens the user's default browser.
// After 60 seconds the server exits so the user cannot accidentally
// leave an inspection surface running.
//
// The viewer is one static HTML page embedded in the binary plus
// three JSON endpoints:
//
//	GET /         — static viewer
//	GET /api/envelope  — attest.Envelope + parsed Statement
//	GET /api/events    — parsed audit events (line-delimited JSON)
//	GET /api/verify    — verify.Report (re-run each load)
func runView(args []string) int {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 60*time.Second, "how long the server stays up")
	follow := fs.Bool("follow", false, "live mode: re-read log on every request (use while session is still active)")
	reportPath := fs.String("report", "", "path to a bound report markdown (shows side-by-side with timeline)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "jesses view: missing envelope or log path")
		return 2
	}
	envPath := fs.Arg(0)

	var (
		env  attest.Envelope
		stmt attest.Statement
		err  error
	)
	// In --follow mode the envelope may not exist yet (session still
	// open). We allow a missing envelope and render the log alone.
	if fileExists(envPath) {
		env, err = attest.ReadFile(envPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "view: %v\n", err)
			return 1
		}
		stmt, _, err = attest.Parse(env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "view: parse: %v\n", err)
			return 1
		}
	} else if !*follow {
		fmt.Fprintf(os.Stderr, "view: %s not found (use --follow for live session)\n", envPath)
		return 1
	}

	// Collect events from the sibling audit log if present.
	logPath := sibling(envPath, "session.log")
	if !fileExists(logPath) {
		logPath = envPath[:max(0, len(envPath)-4)] + ".log"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Write(viewerHTML)
	})
	mux.HandleFunc("/api/envelope", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Re-read in follow mode so the viewer sees the envelope
		// appear once the session closes while the browser is open.
		if *follow && fileExists(envPath) {
			if fresh, ferr := attest.ReadFile(envPath); ferr == nil {
				env = fresh
				if s, _, perr := attest.Parse(fresh); perr == nil {
					stmt = s
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"envelope":  env,
			"statement": stmt,
			"follow":    *follow,
		})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// In follow mode, re-read on every request so the timeline
		// grows as the session appends events.
		events, _ := readEvents(logPath)
		json.NewEncoder(w).Encode(events)
	})
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if *reportPath == "" || !fileExists(*reportPath) {
			json.NewEncoder(w).Encode(map[string]any{
				"present": false,
			})
			return
		}
		raw, err := os.ReadFile(*reportPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"present": true,
			"path":    *reportPath,
			"body":    string(raw),
		})
	})

	mux.HandleFunc("/api/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// In follow mode the envelope may not exist yet; return 404
		// so the client shows "verification unavailable" rather than
		// a 500.
		if !fileExists(envPath) {
			http.Error(w, "envelope not yet written", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		rpt, verr := verify.Verify(ctx, verify.Options{
			EnvelopePath: envPath,
			AuditLogPath: logPath,
			ReportPath:   *reportPath,
			// Offline-by-default for the viewer; hitting Rekor on
			// every page load is noise for the triage workflow.
			RekorClient: nil,
		})
		if verr != nil {
			http.Error(w, verr.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(rpt)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "view: listen: %v\n", err)
		return 1
	}
	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	fmt.Printf("jesses viewer → %s (exits in %s)\n", url, *ttl)
	openBrowser(url)

	srv := &http.Server{Handler: mux}
	go func() {
		time.Sleep(*ttl)
		_ = srv.Shutdown(context.Background())
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "view: serve: %v\n", err)
		return 1
	}
	fmt.Println("jesses viewer closed.")
	return 0
}

// readEvents loads an audit log file into a slice of events. A
// missing file is not an error — the viewer simply shows "no events".
func readEvents(path string) ([]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var evs []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
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

// openBrowser best-effort launches the user's default browser at url.
// Errors are non-fatal; the user can always copy-paste.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}
