package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAppendAndReadBack writes a handful of events and verifies the file
// contains exactly that many valid JSON lines, each round-trippable into an
// Event.
func TestAppendAndReadBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	events := []Event{
		{
			Seq:          0,
			TS:           "2026-04-16T12:00:00.000Z",
			Tool:         "Bash",
			InputHash:    "sha256:aa",
			Destinations: []string{"api.target.com"},
			Decision:     "allow",
			Reason:       "host_in_scope",
			PolicyRef:    "sha256:policy0",
		},
		{
			Seq:       1,
			TS:        "2026-04-16T12:00:01.000Z",
			Tool:      "Read",
			InputHash: "sha256:bb",
			Input:     map[string]any{"file_path": "/tmp/foo"},
			Decision:  "allow",
			Reason:    "path_in_scope",
			PolicyRef: "sha256:policy0",
		},
		{
			Seq:       2,
			TS:        "2026-04-16T12:00:02.000Z",
			Tool:      "Bash",
			InputHash: "sha256:cc",
			Decision:  "block",
			Reason:    "oos_host",
			PolicyRef: "sha256:policy0",
		},
	}
	for _, e := range events {
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != len(events) {
		t.Fatalf("got %d lines, want %d", len(lines), len(events))
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
			continue
		}
		if e.Seq != events[i].Seq {
			t.Errorf("line %d: got seq %d, want %d", i, e.Seq, events[i].Seq)
		}
		if e.Decision != events[i].Decision {
			t.Errorf("line %d: got decision %q, want %q", i, e.Decision, events[i].Decision)
		}
	}
}

// TestCanonicalDeterministic verifies that Canonicalizing an Event with the
// same content twice produces byte-identical output.
func TestCanonicalDeterministic(t *testing.T) {
	e := Event{
		Seq:       42,
		TS:        "2026-04-16T12:00:00.000Z",
		Tool:      "Bash",
		InputHash: "sha256:abc",
		Input:     map[string]any{"cmd": "curl https://api.target.com"},
		Decision:  "allow",
		Reason:    "host_in_scope",
		PolicyRef: "sha256:policy0",
	}
	a, err := CanonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("CanonicalJSON non-deterministic:\n  a=%s\n  b=%s", a, b)
	}
}

// TestCanonicalMapOrderStable verifies that rebuilding an Event from
// semantically equivalent inputs produces the same canonical output,
// including for maps whose keys would naturally hash in non-deterministic
// order.
func TestCanonicalMapOrderStable(t *testing.T) {
	e1 := Event{
		Seq:       1,
		TS:        "2026-04-16T12:00:00.000Z",
		Tool:      "Read",
		InputHash: "sha256:aa",
		Input: map[string]any{
			"zebra":  1,
			"alpha":  2,
			"middle": 3,
		},
		Decision:  "allow",
		Reason:    "path_in_scope",
		PolicyRef: "sha256:policy0",
	}
	e2 := e1
	e2.Input = map[string]any{
		"middle": 3,
		"alpha":  2,
		"zebra":  1,
	}

	a, err := CanonicalJSON(e1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(e2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("CanonicalJSON sensitive to map insertion order:\n  a=%s\n  b=%s", a, b)
	}
}

// TestConcurrentAppend writes N events across W goroutines, each with its
// own Writer on the same file. Exactly N newline-terminated records should
// end up in the file, each parseable as a valid Event.
//
// This exercises the flock acquisition path and the O_APPEND write-atomicity
// guarantee. Any bug in locking will produce interleaved or lost lines,
// which parse as invalid JSON or a wrong line count.
func TestConcurrentAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	const workers = 8
	const perWorker = 50
	total := workers * perWorker

	var seq atomic.Uint64
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			writer, err := NewWriter(path)
			if err != nil {
				errCh <- err
				return
			}
			defer writer.Close()
			for i := 0; i < perWorker; i++ {
				e := Event{
					Seq:       seq.Add(1) - 1,
					TS:        time.Now().UTC().Format(time.RFC3339Nano),
					Tool:      "Bash",
					InputHash: "sha256:concurrent",
					Decision:  "allow",
					Reason:    "test",
					PolicyRef: "sha256:policy0",
				}
				if err := writer.Append(e); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("worker error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != total {
		t.Fatalf("got %d lines, want %d", len(lines), total)
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Errorf("line %d: invalid JSON: %v (line=%q)", i, err, line)
		}
	}
}

// TestCloseIdempotent verifies Close can be called multiple times safely.
func TestCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestAppendAfterClose verifies Append returns ErrWriterClosed once Close
// has been called.
func TestAppendAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	err = w.Append(Event{Seq: 0, TS: "2026-01-01T00:00:00Z", Tool: "Bash", InputHash: "sha256:x", Decision: "allow", Reason: "x", PolicyRef: "sha256:x"})
	if err != ErrWriterClosed {
		t.Errorf("got %v, want ErrWriterClosed", err)
	}
}
