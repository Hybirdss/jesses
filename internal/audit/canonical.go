package audit

import "github.com/Hybirdss/jesses/internal/canonical"

// CanonicalJSON serializes an Event in the canonical form used as a
// Merkle leaf.
//
// Thin wrapper over canonical.JSON — the canonical encoder and its
// spec live in internal/canonical. This function remains here so
// the audit package has an ergonomic, type-specific entry point,
// but the spec, tests, and guarantees live alongside the encoder.
// Field-order stability for Event is locked in record.go; the
// sorting, escaping, and number-format rules are locked in
// canonical/conformance_test.go.
func CanonicalJSON(e Event) ([]byte, error) {
	return canonical.JSON(e)
}
