// Package canonical is the single source of truth for jesses'
// canonical JSON serialization — the bytes that become Merkle
// leaves and whose SHA-256 is signed, anchored to Rekor, and
// cross-verified by second-language implementations.
//
// The serialization rules are frozen and documented in
// spec/canonical.md. This package IS the reference Go
// implementation; verifier-js/canonical.mjs is its byte-exact
// sibling. A third implementation (Python, Rust, …) conforms iff
// its output matches this package's output for every vector in
// spec/test-vectors/v0.1/.
//
// Why a dedicated package:
//
//   - Gives the canonical encoder a stable, discoverable API that
//     downstream callers (audit writer, verifier, provenance
//     binder) depend on directly, rather than through an
//     audit-package accident.
//
//   - Makes the spec boundary explicit. audit.Event is a domain
//     type; canonical.JSON is a format. Mixing them in one package
//     — as internal/audit/canonical.go did — made it tempting to
//     "helpfully" tweak one without updating the other. This
//     package is intentionally upstream of any struct definition.
//
//   - Gives conformance tests a natural home. Any change here must
//     move the goldens in conformance_test.go and
//     spec/test-vectors/v0.1/ in the same commit, or CI fails.
package canonical

import "encoding/json"

// JSON returns the canonical JSON encoding of v.
//
// Canonical rules (full spec: spec/canonical.md):
//
//   - Struct fields emit in their Go declaration order (NOT
//     alphabetical). Callers are responsible for not reordering
//     fields in the Go source — doing so silently rehashes every
//     Merkle leaf in every existing .jes file.
//
//   - `json:"name,omitempty"` elides the zero value of the field
//     type: "" for strings, 0 for numerics, nil for slices/maps,
//     empty for composite types.
//
//   - map[string]T is emitted with keys sorted in byte order
//     (this is a frozen Go 1.12+ guarantee, not a happy accident).
//
//   - No inter-token whitespace, no trailing newline. The leaf
//     hash is SHA-256(canonical_bytes), nothing else.
//
//   - Strings escape as encoding/json defaults:
//     U+0022 ("\"")   → \"
//     U+005C ("\\")   → \\
//     U+0008..U+000D  → \b \t \n \f \r (short forms)
//     U+0000..U+001F  → \u00XX (others)
//     U+003C ("<")    → \u003c
//     U+003E (">")    → \u003e
//     U+0026 ("&")    → \u0026
//     U+2028, U+2029  → \u2028, \u2029
//     everything else → UTF-8 passthrough
//
//   - Numbers use the shortest ECMAScript round-trip. Integer
//     uint64 values below 2^53 fit exactly; audit.Event.Seq is
//     bounded well below that ceiling by the session's event count.
//
//   - null / true / false emit as lowercase keywords.
//
// The implementation delegates to encoding/json. The rules above
// are not implementation artifacts — they ARE the specification,
// and encoding/json's adherence to them is the Go compatibility
// surface we depend on. A conformance test (see conformance_test.go)
// locks in specific input→output byte sequences so that any
// regression — Go's, ours, or a merged PR's — trips the test suite
// before it ships.
func JSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
