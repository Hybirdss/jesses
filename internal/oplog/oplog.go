// Package oplog is the append-only OPERATIONAL log — separate from the
// signed audit log that feeds the Merkle tree.
//
// Why two logs?
//
// The audit log (`session.log`) is the thing `jesses verify` checks.
// Every byte of it is in a Merkle leaf, signed, pre-committed, and
// anchored. If an event cannot land in the audit log cleanly (malformed
// input, extractor crash, filesystem hiccup), writing a half-record
// would silently rehash every downstream leaf and invalidate the
// envelope. So audit-log writes are all-or-nothing.
//
// But half-records still matter for diagnostics: a researcher whose
// hook dropped two events because a malformed JSON line came in wants
// to know that AFTER the session, even though those events are not
// part of the signed session. That's what operational.log is for.
//
// Trust properties:
//
//   - NOT part of the signed envelope. A malicious submitter can delete
//     operational.log and verification will still pass. This is
//     acceptable: the audit log is the integrity artifact; operational
//     log is the operator diagnostic surface.
//   - NOT subject to canonical encoding. Line order is append order.
//     A jesses version bump may add fields without breaking readers.
//   - PRIVACY AWARE. The logger deliberately does NOT accept raw input
//     bytes. Callers pass the error MESSAGE (which rarely contains the
//     secret) and the PHASE. If you need to redact further, redact at
//     the call site.
//
// Format: JSONL, one Entry per line.
package oplog

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Level mirrors standard logging severities. Entries at Info level are
// session lifecycle markers ("opened", "closed"); Warn is a dropped
// event that did not halt the session; Error is a condition that
// halted or will halt the session.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Entry is one line of the operational log.
type Entry struct {
	// TS is RFC 3339Nano UTC. Populated by the logger, not the caller.
	TS string `json:"ts"`

	// Level is one of info / warn / error.
	Level Level `json:"level"`

	// Phase names the session stage: "open", "parse", "append",
	// "close", "build", "write". A small fixed vocabulary keeps
	// downstream grep predictable.
	Phase string `json:"phase"`

	// Seq is the audit-log sequence number most-proximate to the
	// event. Zero (omitted) when the entry predates event assignment
	// (e.g. the malformed-JSON case, where Seq has not been set).
	Seq uint64 `json:"seq,omitempty"`

	// Msg is the human-readable error text. Callers SHOULD pass the
	// sanitized error message, not raw input. The logger does not
	// attempt to sanitize content further — that is the caller's job,
	// because only the caller knows what the value means.
	Msg string `json:"msg"`
}

// Logger is a narrow append-only JSONL writer. Safe for concurrent
// calls: an internal mutex serializes writes. Every Write flushes
// through the OS write syscall; the file is NOT explicitly fsynced
// because an operator who loses the last few lines to a crash has
// bigger problems (same crash likely took the audit log with it).
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// Open creates or appends to the operational log at path. File is
// created with 0600; existing file is opened in append mode. Returns
// a Logger ready for concurrent Write calls.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("oplog: open %s: %w", path, err)
	}
	return &Logger{f: f}, nil
}

// Info logs an info-level lifecycle marker.
func (l *Logger) Info(phase, msg string) error {
	return l.write(Entry{Level: LevelInfo, Phase: phase, Msg: msg})
}

// Warn logs a recoverable anomaly (event dropped, extractor returned
// partial data, etc.). The session continues.
func (l *Logger) Warn(phase, msg string) error {
	return l.write(Entry{Level: LevelWarn, Phase: phase, Msg: msg})
}

// WarnAt is Warn with a seq attached, used when the anomaly can be
// localized to a specific audit-log event.
func (l *Logger) WarnAt(seq uint64, phase, msg string) error {
	return l.write(Entry{Level: LevelWarn, Phase: phase, Seq: seq, Msg: msg})
}

// Error logs a condition that halted (or is about to halt) the
// session. The session is NOT auto-closed — the caller decides.
func (l *Logger) Error(phase, msg string) error {
	return l.write(Entry{Level: LevelError, Phase: phase, Msg: msg})
}

// ErrorAt is Error with a seq attached.
func (l *Logger) ErrorAt(seq uint64, phase, msg string) error {
	return l.write(Entry{Level: LevelError, Phase: phase, Seq: seq, Msg: msg})
}

// Close closes the underlying file. Further Write calls return an
// error. Idempotent: a second Close is a no-op.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// write serializes the Entry to JSON + "\n" and appends. The TS is
// stamped inside the mutex so line order matches timestamp order.
func (l *Logger) write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return fmt.Errorf("oplog: logger closed")
	}
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("oplog: marshal: %w", err)
	}
	line = append(line, '\n')
	_, err = l.f.Write(line)
	return err
}

// Nop is a Logger that discards everything. Use when operational
// logging is explicitly disabled — keeps call sites uniform.
type Nop struct{}

// Info, Warn, WarnAt, Error, ErrorAt, Close all no-op.
func (Nop) Info(_, _ string) error              { return nil }
func (Nop) Warn(_, _ string) error              { return nil }
func (Nop) WarnAt(_ uint64, _, _ string) error  { return nil }
func (Nop) Error(_, _ string) error             { return nil }
func (Nop) ErrorAt(_ uint64, _, _ string) error { return nil }
func (Nop) Close() error                        { return nil }

// Writer is the narrow interface satisfied by both *Logger and Nop.
// Consumers should type against this so test harnesses can drop in
// a Nop without importing *os.File.
type Writer interface {
	Info(phase, msg string) error
	Warn(phase, msg string) error
	WarnAt(seq uint64, phase, msg string) error
	Error(phase, msg string) error
	ErrorAt(seq uint64, phase, msg string) error
	Close() error
}
