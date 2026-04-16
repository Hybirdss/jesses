package verify

// VerifyError is the machine-readable detail for a failed gate. When
// a mandatory gate fails, the verifier populates one of these on the
// corresponding Gate.Error field so that downstream consumers —
// triage bots, H1/BC/Immunefi ingest webhooks, CI pipelines — can
// pivot off the Code field and the typed value pair without parsing
// the human-readable Detail string.
//
// The struct is deliberately flat. Every field other than Gate and
// Code is optional and only populated when relevant to the specific
// failure mode. A generator MUST NOT populate a field with a
// placeholder such as "<unknown>" or "n/a"; leave it zero.
//
// Stability contract: Code values are frozen in v0.1 and must not
// change between patch releases. New failure modes in v0.2+ MAY add
// new Code values but MUST NOT reuse or rename existing ones.
type VerifyError struct {
	// Gate is the gate that failed — "G1" through "G7". Mirrors
	// Gate.Name for convenience so a consumer that only looks at
	// the Error field has full context.
	Gate string `json:"gate"`

	// Code is a short stable identifier for the failure class.
	// See package constants (ErrCode*) for the complete set.
	Code string `json:"code"`

	// Expected is the value the verifier was computing or looking
	// up, formatted as the envelope carried it (usually hex-encoded
	// SHA-256, a path, or a log index). Empty when the failure is
	// not a comparison.
	Expected string `json:"expected,omitempty"`

	// Got is the verifier's recomputed or fetched value, same
	// encoding conventions as Expected.
	Got string `json:"got,omitempty"`

	// LeafIdx is the zero-based audit-log leaf index most proximate
	// to the failure. Meaningful for G2 (merkle) and G5 (policy)
	// when the failure can be localized to a single leaf. Zero when
	// not applicable — callers distinguish by checking Code.
	LeafIdx int `json:"leaf_idx,omitempty"`

	// LogOffset is the byte offset into the audit.log file where
	// the failing event begins. Useful for operators to jump to
	// the exact line with `head -c N | tail -c M`. Zero means
	// not applicable.
	LogOffset int64 `json:"log_offset,omitempty"`

	// Count is a generic counter used when the failure is best
	// described by a tally rather than a single value — e.g. G5
	// reports the number of policy breaches. Zero when not in use.
	Count int `json:"count,omitempty"`

	// Total is the denominator paired with Count when both make
	// sense — e.g. "3 of 4201 events breached policy". Zero when
	// Count is not set.
	Total int `json:"total,omitempty"`

	// ProofPath holds hex-encoded RFC 6962 audit-path hashes walked
	// during a failed inclusion-proof verification. Populated by G2
	// in the specific sub-path that fails to reconstruct the root.
	// Empty for non-merkle failures.
	ProofPath []string `json:"proof_path,omitempty"`
}

// Stable failure codes. Grouped by gate.
//
// G1 — envelope signature
const (
	ErrCodeInvalidPubKey = "invalid_pubkey"
	ErrCodeNoSignatures  = "no_signatures"
	ErrCodeSigDecode     = "signature_decode"
	ErrCodeSigMismatch   = "signature_mismatch"
)

// G2 — merkle root.
const (
	ErrCodeAuditRead         = "audit_log_read"
	ErrCodeMerkleMismatch    = "merkle_root_mismatch"
	ErrCodeLeafCountMismatch = "leaf_count_mismatch"
)

// G3 — rekor pre-commit.
const (
	ErrCodePrecommitInvalid = "precommit_invalid"
	ErrCodeRekorFetch       = "rekor_fetch"
	ErrCodeRekorBodyHash    = "rekor_body_hash_mismatch"
)

// G4 — scope hash.
const (
	ErrCodeScopeRead     = "scope_read"
	ErrCodeScopeMismatch = "scope_hash_mismatch"
)

// G5 — policy compliance.
const (
	ErrCodePolicyScan   = "policy_scan"
	ErrCodePolicyBreach = "policy_breach"
)

// G7 — deliverable provenance.
const (
	ErrCodeReportRead        = "report_read"
	ErrCodeReportHash        = "report_hash_mismatch"
	ErrCodeReportParse       = "report_parse"
	ErrCodeReportValidate    = "report_validate"
	ErrCodeMissingAuditForG7 = "missing_audit_log_for_g7"
	ErrCodeMissingReport     = "missing_report"
	ErrCodeCitationInvalid   = "citation_invalid"
)
