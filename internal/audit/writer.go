package audit

import (
	"errors"
	"os"
	"sync"
)

// ErrWriterClosed is returned when Append is called on a closed Writer.
var ErrWriterClosed = errors.New("audit: writer is closed")

// Writer appends Event records to a per-session audit.log file.
//
// Concurrent writers on the same path are safe: an advisory file lock
// (flock) is acquired for each Append call and released before return.
// Within a single process, an internal mutex serializes Append calls.
//
// The writer is designed for the short-lived hook model — one Writer per
// "jesses hook" invocation, appending exactly one record. For long-running
// daemons it also supports many Append calls per instance with the same
// locking semantics.
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	path   string
	closed bool
}

// NewWriter opens path for appending and returns a Writer. The file is
// created with mode 0600 if it does not exist. Callers must Close the
// Writer.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, path: path}, nil
}

// Append serializes the event to canonical JSON, acquires an exclusive
// advisory lock on the file, writes one line, and releases the lock.
//
// The canonical JSON for the event plus a trailing '\n' is written in a
// single write syscall. POSIX guarantees that writes to an O_APPEND file
// are atomic up to PIPE_BUF bytes; for larger records the flock prevents
// interleaving across processes.
func (w *Writer) Append(e Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriterClosed
	}

	line, err := CanonicalJSON(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if err := lockFile(int(w.f.Fd())); err != nil {
		return err
	}
	defer func() {
		// Best-effort unlock; if the unlock fails, closing the file
		// releases the lock anyway.
		_ = unlockFile(int(w.f.Fd()))
	}()

	if _, err := w.f.Write(line); err != nil {
		return err
	}
	return nil
}

// Sync flushes the file contents to stable storage.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriterClosed
	}
	return w.f.Sync()
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	_ = w.f.Sync()
	return w.f.Close()
}
