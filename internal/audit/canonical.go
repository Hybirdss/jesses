package audit

import "encoding/json"

// CanonicalJSON serializes an Event in the canonical form used as a Merkle
// leaf. The canonical form is deterministic: Go's encoding/json encodes
// struct fields in declaration order (fixed in record.go) and map keys in
// lexicographic byte order (stable since Go 1.12). No whitespace is added.
//
// Any two Events with semantically identical content produce identical bytes
// under this function. This is a strict subset of RFC 8785 (JCS) sufficient
// for jesses v0.1. A future version may migrate to full RFC 8785 compliance
// without changing the on-the-wire bytes for the current predicate type, at
// which point the canonical bytes for a given Event are unchanged and
// v0.1 audit logs remain valid.
func CanonicalJSON(e Event) ([]byte, error) {
	return json.Marshal(e)
}
