package canonical_test

import (
	"encoding/hex"
	"testing"

	"github.com/Hybirdss/jesses/internal/canonical"
)

// The tests in this file lock in the canonical JSON byte sequences
// for specific input shapes. They exist to catch drift in THREE
// directions at once:
//
//  1. A future edit to canonical.JSON() that "improves" formatting.
//     The tests fail with a byte-level diff.
//
//  2. A Go toolchain change to encoding/json that alters map key
//     ordering, number formatting, or string escaping. The tests
//     fail and we either pin the Go version or migrate.
//
//  3. A verifier-js (or third-party) implementation drift. Since
//     verifier-js/canonical.mjs is byte-exact with this file, any
//     edit there without a matching Go-side spec test ripple is
//     caught by CI.
//
// New vectors go at the bottom, numbered, with a one-line rationale
// describing which rule the vector tests.

// vec is a minimal vector. expected is hex so reviewers can see the
// exact bytes (including embedded whitespace, if any) in the test
// table.
type vec struct {
	name     string
	input    any
	expected string // hex-encoded canonical bytes
}

func TestJSON_Conformance(t *testing.T) {
	vectors := []vec{
		// V1 — primitives: tests null / true / false / zero.
		{
			name:     "primitive_null",
			input:    nil,
			expected: hexOf(`null`),
		},
		{
			name:     "primitive_true",
			input:    true,
			expected: hexOf(`true`),
		},
		{
			name:     "primitive_false",
			input:    false,
			expected: hexOf(`false`),
		},
		{
			name:     "primitive_zero",
			input:    0,
			expected: hexOf(`0`),
		},

		// V2 — string escapes: covers every dangerous codepoint.
		// Tests that <, >, & get \u003c \u003e \u0026 (default
		// Go encoding/json behavior, NOT JCS which leaves them raw).
		{
			name:     "string_html_escapes",
			input:    "<script>alert(1)&x=y</script>",
			expected: hexOf(`"\u003cscript\u003ealert(1)\u0026x=y\u003c/script\u003e"`),
		},
		{
			name:     "string_control_chars",
			input:    "\x00\x01\x08\x09\x0a\x1f",
			expected: hexOf(`"\u0000\u0001\b\t\n\u001f"`),
		},
		{
			name:     "string_quote_backslash",
			input:    `a"b\c`,
			expected: hexOf(`"a\"b\\c"`),
		},

		// V3 — UTF-8 passthrough for BMP codepoints that have no
		// special treatment. U+00E9 (é) and U+4E2D (中) stay raw.
		{
			name:     "string_utf8_passthrough",
			input:    "café 中",
			expected: "22636166c3a920e4b8ad22",
		},

		// V4 — U+2028 / U+2029 must escape. These break JSONP in
		// older JS engines; Go's default emits them as \u2028/\u2029.
		{
			name:     "string_line_separator_escapes",
			input:    "a\u2028b\u2029c",
			expected: hexOf(`"a\u2028b\u2029c"`),
		},

		// V5 — map key sort order. Input keys are NOT alphabetical
		// here; expected output sorts them "a","b","c" in byte order.
		{
			name: "map_keys_sorted",
			input: map[string]any{
				"c": 3,
				"a": 1,
				"b": 2,
			},
			expected: hexOf(`{"a":1,"b":2,"c":3}`),
		},

		// V6 — nested map sorting. The inner map's keys also sort.
		{
			name: "map_nested_keys_sorted",
			input: map[string]any{
				"outer": map[string]any{
					"z": 1,
					"a": 2,
				},
			},
			expected: hexOf(`{"outer":{"a":2,"z":1}}`),
		},

		// V7 — byte-order (NOT locale) sort. "B" (0x42) < "a" (0x61).
		{
			name: "map_keys_byte_order_not_locale",
			input: map[string]any{
				"a": 1,
				"B": 2,
			},
			expected: hexOf(`{"B":2,"a":1}`),
		},

		// V8 — integer has no trailing .0, no exponent.
		{
			name:     "number_integer",
			input:    42,
			expected: hexOf(`42`),
		},

		// V9 — empty slice is NOT omitempty-eligible at this layer
		// (this is testing raw canonical.JSON, not Event omitempty).
		// Emits [], not null.
		{
			name:     "slice_empty",
			input:    []int{},
			expected: hexOf(`[]`),
		},

		// V10 — array preserves element order (arrays are ordered).
		{
			name:     "slice_order_preserved",
			input:    []string{"z", "a", "m"},
			expected: hexOf(`["z","a","m"]`),
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := canonical.JSON(v.input)
			if err != nil {
				t.Fatalf("canonical.JSON: %v", err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != v.expected {
				t.Errorf("canonical bytes drifted:\n  want (hex) %s\n  got  (hex) %s\n  got  (utf8) %q",
					v.expected, gotHex, string(got))
			}
		})
	}
}

// TestJSON_StructFieldDeclarationOrder asserts that struct fields
// emit in Go declaration order, not alphabetical. This is the
// rule that jesses relies on most heavily — audit.Event's field
// order is encoded in record.go and every .jes file's Merkle
// leaves depend on it.
func TestJSON_StructFieldDeclarationOrder(t *testing.T) {
	// Field order: zebra, alpha, middle — deliberately NOT
	// alphabetical, NOT reverse-alphabetical, NOT length-ordered.
	type decl struct {
		Zebra  int    `json:"zebra"`
		Alpha  string `json:"alpha"`
		Middle bool   `json:"middle"`
	}
	got, err := canonical.JSON(decl{Zebra: 1, Alpha: "x", Middle: true})
	if err != nil {
		t.Fatalf("canonical.JSON: %v", err)
	}
	want := `{"zebra":1,"alpha":"x","middle":true}`
	if string(got) != want {
		t.Errorf("struct fields did not emit in declaration order:\n  want %q\n  got  %q", want, string(got))
	}
}

// TestJSON_Determinism runs 100 iterations on a map-containing
// struct and asserts byte-exact output. Defends against a future
// Go release randomizing map iteration at the encoder level (the
// current encoding/json sorts explicitly — if that ever changes,
// this test catches it before conformance vectors regenerate
// non-deterministically).
func TestJSON_Determinism(t *testing.T) {
	input := map[string]any{
		"one":   1,
		"two":   2,
		"three": 3,
		"four":  4,
		"five":  5,
		"six":   6,
		"seven": 7,
		"eight": 8,
	}
	first, err := canonical.JSON(input)
	if err != nil {
		t.Fatalf("canonical.JSON: %v", err)
	}
	for i := 0; i < 100; i++ {
		got, err := canonical.JSON(input)
		if err != nil {
			t.Fatalf("canonical.JSON iter %d: %v", i, err)
		}
		if string(got) != string(first) {
			t.Fatalf("iter %d drifted: %q → %q", i, string(first), string(got))
		}
	}
}

// hexOf is a test helper: returns the hex-encoded bytes of a Go
// string literal. Keeps the vector table readable.
func hexOf(s string) string {
	return hex.EncodeToString([]byte(s))
}
