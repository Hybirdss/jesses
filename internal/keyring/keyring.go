// Package keyring centralizes ed25519 private-key handling for the
// jesses CLI and Go SDK.
//
// v0.1 stores one key per machine at `~/.jesses/key`, or at a caller-
// supplied path. The package exposes a narrow Signer interface so a
// future v0.3 TEE-backed implementation (Intel TDX, AWS Nitro Enclaves,
// Apple Secure Enclave) can drop in without changing call sites. See
// ADR 0006 for the v0.1 posture and ADR 0009 for the canonical-JSON
// assumption signatures are taken over.
//
// Scope of this package:
//   - Resolve the canonical key location (DefaultPath)
//   - Load an existing key, with a permission-mode health check
//   - Generate-and-persist on first use (LoadOrCreate)
//   - Wrap an ed25519 private key behind a Signer interface
//
// Out of scope:
//   - Passphrase or age encryption (ADR 0006 rejects these for v0.1)
//   - Key rotation protocol — researchers handle rotation by publishing
//     a new pubkey; this package only writes the key file
//   - Hardware attestation — v0.3 concern
package keyring

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrWrongSize is returned when a key file does not hold exactly
// ed25519.PrivateKeySize bytes. Key corruption, truncated write, or a
// file that is not a jesses key file all surface here.
var ErrWrongSize = errors.New("keyring: key file has wrong size")

// Signer is the single signing primitive jesses needs. The software
// implementation returned by Wrap is v0.1; a TEE implementation will
// satisfy this interface in v0.3 without call-site changes.
type Signer interface {
	// Sign produces an ed25519 signature over data.
	Sign(data []byte) ([]byte, error)

	// Public returns the public key associated with this signer.
	Public() ed25519.PublicKey
}

// Wrap converts an ed25519.PrivateKey into a Signer. A key of wrong
// size returns ErrWrongSize so the caller surfaces a user-legible
// error before any signing attempt.
func Wrap(priv ed25519.PrivateKey) (Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			ErrWrongSize, len(priv), ed25519.PrivateKeySize)
	}
	return softwareSigner{priv: priv}, nil
}

// softwareSigner signs with an in-memory ed25519 key. Satisfies
// ADR 0006's "software ed25519 for v0.1" decision.
type softwareSigner struct {
	priv ed25519.PrivateKey
}

// Sign is ed25519.Sign over the raw message — no prehash. ed25519's
// internal SHA-512 is the hash; prehashing would break cross-language
// verifiers that pass the message directly.
func (s softwareSigner) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// Public returns the public half of the keypair.
func (s softwareSigner) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// DefaultPath returns the canonical per-user key location:
// `$HOME/.jesses/key`. Callers SHOULD prefer this over any
// session-local path so a researcher's identity stays stable across
// sessions. When $HOME cannot be determined, returns the empty string
// and the caller is expected to fall back to a session-dir key.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".jesses", "key")
}

// Load reads the key file at path. Returns ErrWrongSize if the file is
// not exactly ed25519.PrivateKeySize bytes. If the file is readable by
// group or world (permission bits 0077 set) a warning line is written
// to warnTo — this is informational only and does not fail the load;
// setting warnTo to nil suppresses the warning.
//
// A successful Load writes nothing. The file's existing permissions
// are preserved.
func Load(path string, warnTo io.Writer) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: %s has %d bytes",
			ErrWrongSize, path, len(raw))
	}
	if warnTo != nil {
		checkPerm(path, warnTo)
	}
	return ed25519.PrivateKey(raw), nil
}

// LoadOrCreate is the common call shape: load the key at path if it
// exists, otherwise generate a fresh ed25519 keypair and persist it
// with 0600 permissions. The parent directory is created (0700) when
// missing.
//
// A generated key is written atomically — create-tmp + rename — so a
// crash mid-write never leaves a half-written key in place.
//
// The returned bool is true iff a new key was created. Callers wire
// this into UX (e.g. "generated new key at ~/.jesses/key — back this
// up").
func LoadOrCreate(path string, warnTo io.Writer) (priv ed25519.PrivateKey, created bool, err error) {
	priv, err = Load(path, warnTo)
	switch {
	case err == nil:
		return priv, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}

	// File does not exist — generate and persist.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("keyring: mkdir parent: %w", err)
	}
	_, gen, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("keyring: generate: %w", err)
	}
	if err := writeKeyAtomic(path, gen); err != nil {
		return nil, false, err
	}
	return gen, true, nil
}

// writeKeyAtomic creates `path` with 0600 mode via a sibling temp
// file and rename. On the same filesystem the rename is atomic, so
// either the key is fully persisted or nothing changes.
func writeKeyAtomic(path string, priv ed25519.PrivateKey) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jesses-key-*")
	if err != nil {
		return fmt.Errorf("keyring: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("keyring: chmod tmp: %w", err)
	}
	if _, err := tmp.Write(priv); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("keyring: write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("keyring: close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("keyring: rename: %w", err)
	}
	return nil
}

// checkPerm writes a one-line warning to w if the file at path is
// readable by group or other. A jesses key with mode 0644 — common
// after git clone, scp, or a cloud-backup restore — is not a
// correctness bug but it IS an exposure the user should know about.
func checkPerm(path string, w io.Writer) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		fmt.Fprintf(w,
			"jesses: warning: key %s has mode %04o; group/world-readable — run `chmod 600 %s`\n",
			path, mode, path)
	}
}
