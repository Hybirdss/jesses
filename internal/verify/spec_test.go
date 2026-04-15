package verify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hybirdss/jesses/internal/verify"
)

// TestSpecConformance iterates every vector directory under
// spec/test-vectors/v0.1 and checks that the Go verifier produces a
// Report byte-identical to the `expected_report` field in the
// vector's vector.json.
//
// This is the reference-implementation conformance test. A second
// implementation (verifier-js, a future Rust verifier, etc.) passes
// conformance when it produces the same Report JSON for the same
// inputs. That is the meaning of "standard" — same inputs, same
// output, across implementations.
//
// Regenerating the corpus: `go run ./tools/specgen ./spec/test-vectors/v0.1`.
// Any diff against the committed vectors is a spec-breaking change
// and requires a coordinated version bump.
func TestSpecConformance(t *testing.T) {
	root, err := specRoot()
	if err != nil {
		t.Skipf("spec vectors not found: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("spec corpus is empty — run tools/specgen")
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			runSpecVector(t, filepath.Join(root, name))
		})
	}
}

func runSpecVector(t *testing.T, dir string) {
	t.Helper()
	vecRaw, err := os.ReadFile(filepath.Join(dir, "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ExpectedReport verify.Report `json:"expected_report"`
	}
	if err := json.Unmarshal(vecRaw, &meta); err != nil {
		t.Fatal(err)
	}
	// Re-run Verify with no Rekor client (offline) so this test
	// does not need network. The vector was generated the same way.
	got, err := verify.Verify(context.Background(), verify.Options{
		EnvelopePath: filepath.Join(dir, "session.jes"),
		AuditLogPath: filepath.Join(dir, "session.log"),
		ScopePath:    filepath.Join(dir, "scope.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}

	wantJSON, _ := json.Marshal(meta.ExpectedReport)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Errorf("report mismatch\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}

// specRoot locates the test-vector directory relative to the module
// root. Walks up from CWD until it finds spec/test-vectors/v0.1.
func specRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(wd, "spec", "test-vectors", "v0.1")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}
