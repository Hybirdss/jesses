package attest_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Hybirdss/jesses/internal/attest"
)

// FuzzParseEnvelope drives the envelope parser with arbitrary bytes
// shaped like — or deliberately unlike — an in-toto envelope.
//
// The parser runs on every .jes file a verifier opens; a crash here
// means a hostile artifact can DoS the verifier before any gate runs.
// The invariant we prove: for ANY seed, attest.Parse either returns
// an error or returns a Statement + body — never panics.
//
// Seed strategy:
//   - valid envelopes (baseline)
//   - truncated JSON (parse partway then EOF)
//   - wrong payload type (must reject cleanly)
//   - invalid base64 in payload (must reject cleanly)
//   - base64-decoded but non-JSON payload (must reject cleanly)
//   - well-formed envelope but malformed predicate
func FuzzParseEnvelope(f *testing.F) {
	// V1: minimal valid shape — empty statement, passes the type
	// check but payload decodes to `null`.
	valid := attest.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`null`)),
		Signatures:  []attest.Signature{{KeyID: "x", Sig: base64.StdEncoding.EncodeToString([]byte{0})}},
	}
	validBytes, _ := json.Marshal(valid)
	f.Add(validBytes)

	// V2: wrong payload type — must reject.
	wrongType := attest.Envelope{
		PayloadType: "text/plain",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{}`)),
	}
	wrongTypeBytes, _ := json.Marshal(wrongType)
	f.Add(wrongTypeBytes)

	// V3: invalid base64 payload — must reject.
	invalidB64 := attest.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "!!!not-base64!!!",
	}
	invalidB64Bytes, _ := json.Marshal(invalidB64)
	f.Add(invalidB64Bytes)

	// V4: base64-decoded payload that is not JSON.
	garbageJSON := attest.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte("}}}{not json}}}")),
	}
	garbageJSONBytes, _ := json.Marshal(garbageJSON)
	f.Add(garbageJSONBytes)

	// V5: truncated JSON envelope (stops mid-payload).
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":`))

	// V6: deeply nested JSON — tests that the parser doesn't blow
	// the stack on hostile nesting.
	deep := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` +
		base64.StdEncoding.EncodeToString([]byte(
			`{"_type":"x","predicate":{"a":{"b":{"c":{"d":{"e":1}}}}}}`,
		)) + `"}`)
	f.Add(deep)

	// V7: empty input.
	f.Add([]byte{})

	// V8: not JSON at all.
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, raw []byte) {
		var env attest.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			// Not a well-formed envelope JSON — outside Parse's
			// contract, exit without asserting.
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("attest.Parse panicked on envelope %q: %v", raw, r)
			}
		}()

		stmt, body, err := attest.Parse(env)
		if err != nil {
			// Rejection is a valid outcome — the envelope was
			// malformed but the parser reported the malformation
			// rather than crashing. That's exactly what we want.
			return
		}

		// If parsing succeeded, the body must be non-nil and the
		// statement type must be something a caller can inspect
		// without crashing on a nil pointer. Minimal sanity.
		if body == nil {
			t.Fatalf("Parse succeeded but returned nil body; env=%q", raw)
		}
		_ = stmt // statement may have zero fields — that's legal for null payload
	})
}

// FuzzReadEnvelope is Parse's wire-level sibling: it tests that the
// JSON-unmarshal step that precedes Parse (what ReadFile does
// internally) also does not panic on arbitrary bytes. We don't use
// ReadFile directly because it requires a file on disk, but the
// unmarshal is what runs against untrusted bytes regardless.
func FuzzReadEnvelope(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"payloadType":"x","payload":"y","signatures":[]}`))
	f.Add([]byte(`{"payloadType":null,"payload":null,"signatures":null}`))
	f.Add([]byte(`[]`))   // wrong top-level type
	f.Add([]byte(`null`)) // valid JSON, wrong shape
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("envelope unmarshal panicked on %q: %v", raw, r)
			}
		}()
		var env attest.Envelope
		_ = json.Unmarshal(raw, &env)
	})
}
