package oplog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpen_CreatesFile_0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operational.log")
	lg, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer lg.Close()
	if err := lg.Info("open", "session started"); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("operational.log mode = %04o, want 0600", mode)
		}
	}
}

func TestLogger_AppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operational.log")
	lg, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	mustOK := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	mustOK(lg.Info("open", "session started"))
	mustOK(lg.Warn("parse", "line dropped — malformed json"))
	mustOK(lg.WarnAt(42, "append", "extractor returned partial destinations"))
	mustOK(lg.Error("close", "rekor upload timed out"))
	mustOK(lg.ErrorAt(43, "append", "disk full"))
	mustOK(lg.Close())

	// Read back; each line must be valid JSON with the expected fields.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var entries []Entry
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	if sc.Err() != nil {
		t.Fatal(sc.Err())
	}
	if got, want := len(entries), 5; got != want {
		t.Fatalf("entry count = %d, want %d", got, want)
	}
	cases := []struct {
		level Level
		phase string
		seq   uint64
		msg   string
	}{
		{LevelInfo, "open", 0, "session started"},
		{LevelWarn, "parse", 0, "line dropped — malformed json"},
		{LevelWarn, "append", 42, "extractor returned partial destinations"},
		{LevelError, "close", 0, "rekor upload timed out"},
		{LevelError, "append", 43, "disk full"},
	}
	for i, c := range cases {
		got := entries[i]
		if got.Level != c.level {
			t.Errorf("entry %d level = %q, want %q", i, got.Level, c.level)
		}
		if got.Phase != c.phase {
			t.Errorf("entry %d phase = %q, want %q", i, got.Phase, c.phase)
		}
		if got.Seq != c.seq {
			t.Errorf("entry %d seq = %d, want %d", i, got.Seq, c.seq)
		}
		if got.Msg != c.msg {
			t.Errorf("entry %d msg = %q, want %q", i, got.Msg, c.msg)
		}
		if _, err := time.Parse(time.RFC3339Nano, got.TS); err != nil {
			t.Errorf("entry %d ts %q not RFC3339Nano: %v", i, got.TS, err)
		}
	}
}

func TestLogger_OmitEmptySeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "op.log")
	lg, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()
	if err := lg.Info("open", "start"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seq is zero; must NOT appear in the JSON line.
	if strings.Contains(string(raw), `"seq"`) {
		t.Errorf("zero seq leaked into JSON: %s", raw)
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "op.log")
	lg, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()

	// Fire 50 concurrent writes from 10 goroutines. Each line must
	// be a complete, parseable JSON object — the mutex prevents
	// interleaved bytes.
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_ = lg.Warn("parse", "concurrent")
			}
		}(g)
	}
	wg.Wait()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Errorf("line %d not parseable: %q — %v", lines, sc.Text(), err)
		}
		lines++
	}
	if lines != 50 {
		t.Errorf("line count = %d, want 50", lines)
	}
}

func TestLogger_ClosedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "op.log")
	lg, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lg.Info("x", "y"); err == nil {
		t.Errorf("write after close: want error, got nil")
	}
	// Second Close is a no-op.
	if err := lg.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestNop_Silent(t *testing.T) {
	var n Nop
	// All methods must not panic, must return nil.
	ops := []func() error{
		func() error { return n.Info("x", "y") },
		func() error { return n.Warn("x", "y") },
		func() error { return n.WarnAt(1, "x", "y") },
		func() error { return n.Error("x", "y") },
		func() error { return n.ErrorAt(1, "x", "y") },
		n.Close,
	}
	for i, op := range ops {
		if err := op(); err != nil {
			t.Errorf("Nop op %d: err = %v, want nil", i, err)
		}
	}
}

func TestWriterInterface(t *testing.T) {
	// Compile-time assertion: *Logger and Nop satisfy Writer.
	var _ Writer = (*Logger)(nil)
	var _ Writer = Nop{}
}
