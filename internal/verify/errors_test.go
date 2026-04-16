package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyError_PopulatedOnFailure constructs a deliberately
// broken envelope (bad signature + missing audit log) and asserts
// that the resulting Gate.Error fields carry the stable Code values
// documented in errors.go. This test exists independently of the
// golden-vector suite so a refactor that accidentally drops the
// VerifyError population from one of the failure sites trips here
// even if the goldens are regenerated.
func TestVerifyError_PopulatedOnFailure(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "broken.jes")

	// Envelope with a structurally invalid ed25519 public key (wrong
	// length). Triggers G1 ErrCodeInvalidPubKey.
	envJSON := []byte(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiIn1dLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9qZXNzZXMuZGV2L3YwLjEvYWN0aW9uLWVudmVsb3BlIiwicHJlZGljYXRlIjp7InB1Yl9rZXkiOiJkZWFkYmVlZiJ9fQ==",
  "signatures": [{"keyid": "x", "sig": ""}]
}`)
	if err := os.WriteFile(envPath, envJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	rpt, err := Verify(context.Background(), Options{EnvelopePath: envPath})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	g1 := findGate(t, rpt, "G1")
	if g1.Error == nil {
		t.Fatalf("G1 failed but Error is nil; Detail=%q", g1.Detail)
	}
	if g1.Error.Code != ErrCodeInvalidPubKey {
		t.Errorf("G1 code = %q, want %q", g1.Error.Code, ErrCodeInvalidPubKey)
	}
	if g1.Error.Gate != "G1" {
		t.Errorf("G1 error.Gate = %q, want G1", g1.Error.Gate)
	}
}

// TestVerifyError_JSONRoundTrip asserts the Error field serializes
// and round-trips cleanly. A consumer receiving JSON from
// `jesses verify --json` relies on stable field names; a rename in
// errors.go that forgot to update the json tag would break every
// downstream triage bot.
func TestVerifyError_JSONRoundTrip(t *testing.T) {
	original := VerifyError{
		Gate:      "G2",
		Code:      ErrCodeMerkleMismatch,
		Expected:  "abc123",
		Got:       "def456",
		LeafIdx:   42,
		LogOffset: 1024,
		Count:     3,
		Total:     7,
		ProofPath: []string{"hash1", "hash2"},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Spot-check that every field we care about is present under its
	// documented wire name.
	want := []string{
		`"gate":"G2"`,
		`"code":"merkle_root_mismatch"`,
		`"expected":"abc123"`,
		`"got":"def456"`,
		`"leaf_idx":42`,
		`"log_offset":1024`,
		`"count":3`,
		`"total":7`,
		`"proof_path":["hash1","hash2"]`,
	}
	for _, w := range want {
		if !strings.Contains(string(raw), w) {
			t.Errorf("JSON missing expected substring %q\n  got: %s", w, raw)
		}
	}

	var back VerifyError
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !equalVerifyError(back, original) {
		t.Errorf("round-trip drift:\n  got:  %+v\n  want: %+v", back, original)
	}
}

// TestVerifyError_OmitEmptyZero ensures fields that are zero-valued
// do not clutter the JSON output. A passing gate emits NO error
// field at all (Gate.Error is nil, rendered as omitted). A failing
// gate with no comparison data emits only Gate+Code, not a bunch of
// empty "", 0 fields.
func TestVerifyError_OmitEmptyZero(t *testing.T) {
	minimal := VerifyError{Gate: "G1", Code: ErrCodeNoSignatures}
	raw, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)
	// These fields are zero-valued; must be omitted.
	forbidden := []string{`"expected"`, `"got"`, `"leaf_idx"`, `"log_offset"`,
		`"count"`, `"total"`, `"proof_path"`}
	for _, f := range forbidden {
		if strings.Contains(got, f) {
			t.Errorf("zero-valued field %s leaked into JSON: %s", f, got)
		}
	}
	// Gate + Code must be present — they are mandatory, not omitempty.
	mustHave := []string{`"gate":"G1"`, `"code":"no_signatures"`}
	for _, m := range mustHave {
		if !strings.Contains(got, m) {
			t.Errorf("mandatory field missing: %q not in %s", m, got)
		}
	}
}

func findGate(t *testing.T, rpt Report, name string) Gate {
	t.Helper()
	for _, g := range rpt.Gates {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("gate %s not found in report", name)
	return Gate{}
}

// equalVerifyError compares two VerifyError values element-wise. Go
// structs with slice fields don't compare with == so we do it by
// hand; keeps the test free of reflect.DeepEqual imports.
func equalVerifyError(a, b VerifyError) bool {
	if a.Gate != b.Gate || a.Code != b.Code ||
		a.Expected != b.Expected || a.Got != b.Got ||
		a.LeafIdx != b.LeafIdx || a.LogOffset != b.LogOffset ||
		a.Count != b.Count || a.Total != b.Total {
		return false
	}
	if len(a.ProofPath) != len(b.ProofPath) {
		return false
	}
	for i := range a.ProofPath {
		if a.ProofPath[i] != b.ProofPath[i] {
			return false
		}
	}
	return true
}
