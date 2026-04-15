package audit

// Event is the canonical tool-event record per SPEC.md §5.
//
// The struct field order is stable and intentional. Changing the order
// changes the JSON serialization (since Go's json package encodes struct
// fields in declaration order), which would change every Merkle leaf hash
// and invalidate every past .jes file. Do not reorder.
type Event struct {
	// Seq is a monotonic session-local counter starting at 0.
	Seq uint64 `json:"seq"`

	// TS is the RFC 3339 Nano UTC timestamp of the tool invocation.
	TS string `json:"ts"`

	// Tool is the Claude Code tool name exactly as dispatched by the hook
	// (e.g., "Bash", "Read", "Edit", "mcp__foo__bar").
	Tool string `json:"tool"`

	// InputHash is the SHA-256 of the canonical JSON of the raw tool input,
	// written as "sha256:<hex>". Present in both privacy modes.
	InputHash string `json:"input_hash"`

	// Input is the raw tool input. Present only in privacy=off mode.
	// When omitted, the record's Merkle leaf hash differs from the
	// privacy=off form — the mode is fixed per session.
	Input map[string]any `json:"input,omitempty"`

	// Destinations is a tool-specific list of extracted destinations:
	// hosts for Bash/WebFetch, paths for Read/Write/Edit, repos for Agent.
	Destinations []string `json:"destinations,omitempty"`

	// Decision is one of "allow", "warn", "block".
	Decision string `json:"decision"`

	// Reason identifies the matching rule or "unpoliced".
	Reason string `json:"reason"`

	// PolicyRef is the SHA-256 of the active scope.txt at the moment of the
	// event, written as "sha256:<hex>".
	PolicyRef string `json:"policy_ref"`
}
