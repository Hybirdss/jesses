package shellparse

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update regenerates the expected .json files. Invoke as:
//
//	go test ./internal/shellparse/ -run TestGoldenSegments -update
//
// Review the resulting JSON diff carefully before committing — every
// change in the golden output is a change in canonical extraction
// behavior.
var update = flag.Bool("update", false, "regenerate golden JSON")

// TestGoldenSegments loads every .sh fixture in testdata/segments,
// runs SplitString on its contents, marshals the result with
// deterministic indentation, and compares byte-exact with the paired
// .json file. Mismatches fail with a diff-ready message.
//
// The fixtures are the canonical real-world corpus: each one is a
// shell snippet that an attacker (or an attacker-influenced LLM) might
// produce when attempting to exfiltrate data, escalate privileges, or
// bypass the jesses policy layer. The parser's behavior on these
// inputs is what downstream extractors build on, and the audit record
// hashes depend on it.
func TestGoldenSegments(t *testing.T) {
	matches, err := filepath.Glob("testdata/segments/*.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no fixtures in testdata/segments")
	}
	for _, shPath := range matches {
		shPath := shPath
		name := strings.TrimSuffix(filepath.Base(shPath), ".sh")
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(shPath)
			if err != nil {
				t.Fatal(err)
			}
			// Trim trailing newline the editor added so the input is
			// treated as one shell snippet, not one terminated by a
			// newline separator with an empty segment after.
			text := strings.TrimRight(string(input), "\n")

			cmds, err := SplitString(text)
			if err != nil {
				t.Fatalf("SplitString: %v", err)
			}

			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			if err := enc.Encode(cmds); err != nil {
				t.Fatal(err)
			}
			got := buf.Bytes()

			jsonPath := strings.TrimSuffix(shPath, ".sh") + ".json"
			if *update {
				if err := os.WriteFile(jsonPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with -update to create)", jsonPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("golden mismatch for %s\n\n--- got ---\n%s\n--- want ---\n%s",
					name, got, want)
			}
		})
	}
}
