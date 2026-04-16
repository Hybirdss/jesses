package canonical_test

import (
	"encoding/json"
	"testing"

	"github.com/Hybirdss/jesses/internal/canonical"
)

// FuzzJSON_Roundtrip drives the canonical encoder with arbitrary
// JSON-shaped byte sequences decoded via encoding/json into a generic
// `any`. The three invariants the fuzzer proves hold universally:
//
//  1. No panic. For every value Go's encoder will accept, ours does
//     too — we are a thin wrapper, so any panic here means a panic in
//     encoding/json, which is already a CVE-class Go bug we'd want to
//     surface.
//
//  2. Output is valid JSON. A canonical byte sequence that fails
//     json.Unmarshal would mean the sibling verifier-js.mjs would
//     also fail to parse it, and a `.jes` file would be unreadable
//     by any third-party reviewer.
//
//  3. Round-trip determinism. Encoding, decoding, re-encoding must
//     produce byte-identical output. This catches a class of bug
//     where map iteration order or numeric parsing drifts between
//     runs — which would silently rehash Merkle leaves.
//
// Seed corpus picks values that exercise the parts of the spec most
// likely to drift: map key sort (byte-order not locale), nested
// structures, HTML-escape codepoints, UTF-8, number formats.
func FuzzJSON_Roundtrip(f *testing.F) {
	seeds := [][]byte{
		[]byte(`null`),
		[]byte(`true`),
		[]byte(`false`),
		[]byte(`0`),
		[]byte(`-1`),
		[]byte(`42`),
		[]byte(`"x"`),
		[]byte(`""`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`[1,2,3]`),
		[]byte(`{"a":1,"b":2,"c":3}`),
		[]byte(`{"z":1,"a":2,"m":3}`),     // unsorted keys
		[]byte(`{"B":1,"a":2}`),           // byte-order vs locale
		[]byte(`{"outer":{"z":1,"a":2}}`), // nested sort
		[]byte(`"<script>alert(1)&x=y</script>"`), // HTML escapes
		[]byte(`"\u2028\u2029"`),                  // line-separators
		[]byte(`"café 中"`),                        // UTF-8 passthrough
		[]byte(`{"k":"\u0000\u0001\u001f"}`),      // control chars
		[]byte(`["z","a","m"]`),                   // array order
		[]byte(`{"a":[1,{"b":"c"}],"d":null}`),    // deep nest
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Only care about inputs that parse as JSON. Everything else
		// is noise the fuzzer can skip without shrinking on it.
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return
		}

		// Invariant 1: encoding a value the stdlib accepted must not
		// panic. A returned error is fine (unsupported type), but a
		// panic escapes the test harness.
		out, err := canonical.JSON(v)
		if err != nil {
			// stdlib accepted input — encoder should too. If not,
			// surface it: it means canonical.JSON rejects a shape
			// that the sibling spec document does not exclude.
			t.Fatalf("canonical.JSON returned error on json-parseable input %q: %v",
				raw, err)
		}

		// Invariant 2: output parses as JSON.
		var v2 any
		if err := json.Unmarshal(out, &v2); err != nil {
			t.Fatalf("canonical output does not parse as JSON:\n  input:  %q\n  output: %q\n  err:    %v",
				raw, out, err)
		}

		// Invariant 3: re-encoding the parsed value yields the same
		// bytes. If this fails, the encoder is non-deterministic or
		// the decode+encode path is lossy for some value shape. Either
		// is fatal for Merkle-leaf stability.
		out2, err := canonical.JSON(v2)
		if err != nil {
			t.Fatalf("second encode failed: %v", err)
		}
		if string(out) != string(out2) {
			t.Fatalf("canonical JSON not round-trip stable:\n  input:   %q\n  first:   %q\n  second:  %q",
				raw, out, out2)
		}
	})
}

// FuzzJSON_Determinism is a narrower invariant: for any single input,
// encoding the SAME value twice must always give the same bytes. This
// catches map-iteration non-determinism bugs at a tighter loop than
// FuzzJSON_Roundtrip, where the parse step could in principle mask
// drift.
func FuzzJSON_Determinism(f *testing.F) {
	f.Add([]byte(`{"z":1,"a":2,"m":3,"b":4,"y":5}`))
	f.Add([]byte(`{"nested":{"z":1,"a":2}}`))
	f.Add([]byte(`[{"a":1},{"b":2},{"c":3}]`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return
		}
		first, err := canonical.JSON(v)
		if err != nil {
			return
		}
		for i := 0; i < 10; i++ {
			got, err := canonical.JSON(v)
			if err != nil {
				t.Fatalf("iter %d returned error after first succeeded: %v", i, err)
			}
			if string(got) != string(first) {
				t.Fatalf("iter %d drifted:\n  first: %q\n  got:   %q", i, first, got)
			}
		}
	})
}
