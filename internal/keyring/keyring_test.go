package keyring

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreate_NewKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "key")

	priv, created, err := LoadOrCreate(path, io.Discard)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true on first call")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	// Parent dir should exist with 0700 perms (owner-only).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("stat parent: %v", err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("parent dir mode = %04o; want 0700 (owner-only)", mode)
		}
	}

	// Key file should exist with 0600 perms.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("key mode = %04o; want 0600", mode)
		}
	}
}

func TestLoadOrCreate_ExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	// First call creates.
	priv1, created1, err := LoadOrCreate(path, io.Discard)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if !created1 {
		t.Fatalf("first call: want created=true")
	}

	// Second call must load the existing key byte-for-byte.
	priv2, created2, err := LoadOrCreate(path, io.Discard)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if created2 {
		t.Errorf("second call: want created=false, got true — key was regenerated")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Errorf("key drift: first and second load returned different bytes")
	}
}

func TestLoad_WrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, io.Discard)
	if !errors.Is(err, ErrWrongSize) {
		t.Errorf("Load wrong-size file: err = %v, want wrap of ErrWrongSize", err)
	}
}

func TestLoad_NotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(filepath.Join(dir, "missing"), io.Discard)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load missing file: err = %v, want wrap of os.ErrNotExist", err)
	}
}

func TestLoad_PermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics do not apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	// Write a valid-sized key with world-readable mode.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, priv, 0o644); err != nil {
		t.Fatal(err)
	}

	var warn bytes.Buffer
	got, err := Load(path, &warn)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Errorf("Load returned different bytes than were written")
	}
	out := warn.String()
	if !strings.Contains(out, "group/world-readable") {
		t.Errorf("expected permission warning, got %q", out)
	}
	if !strings.Contains(out, "chmod 600") {
		t.Errorf("warning should suggest chmod 600, got %q", out)
	}
}

func TestLoad_PermissionOK_NoWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics do not apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatal(err)
	}

	var warn bytes.Buffer
	if _, err := Load(path, &warn); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if warn.Len() != 0 {
		t.Errorf("expected no warning for 0600, got %q", warn.String())
	}
}

func TestWrap_Sign_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := Wrap(priv)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	msg := []byte("jesses v0.1 attestation")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(signer.Public(), msg, sig) {
		t.Errorf("signature from Signer does not verify against Signer.Public()")
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Errorf("signature does not verify against the original public key")
	}
}

func TestWrap_WrongSize(t *testing.T) {
	_, err := Wrap(ed25519.PrivateKey{1, 2, 3})
	if !errors.Is(err, ErrWrongSize) {
		t.Errorf("Wrap short key: err = %v, want wrap of ErrWrongSize", err)
	}
}

func TestDefaultPath(t *testing.T) {
	// The default path must end in `.jesses/key` when $HOME is set.
	// We don't assert the full path because it varies per OS.
	p := DefaultPath()
	if p == "" {
		t.Skip("HOME not resolvable in this environment")
	}
	if !strings.HasSuffix(p, filepath.Join(".jesses", "key")) {
		t.Errorf("DefaultPath = %q, want suffix %q", p, filepath.Join(".jesses", "key"))
	}
}
