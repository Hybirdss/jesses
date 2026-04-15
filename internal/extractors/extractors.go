// Package extractors defines the shared destination types and the
// dispatcher that routes a raw tool-use input to the right per-tool
// extractor sub-package.
//
// Each agent harness (Claude Code, Cursor, Cline, etc.) feeds the
// hook line-delimited JSON tool events. The tool name (bash, read,
// write, webfetch, mcp, ...) determines which extractor runs. Having
// the dispatcher in one place keeps hook.go and the public API
// (pkg/jesses) free of tool-name switch logic that would otherwise
// drift out of sync.
//
// Every sub-package exposes a single `Extract(raw map[string]any)
// ([]Destination, error)` function. Results from all sub-packages
// share the same Destination shape so policy evaluation is uniform.
package extractors

// Destination is the shared cross-package shape for a single thing
// a tool would touch. It is intentionally wider than
// bash.Destination: the path, host, and proxy namespaces each need a
// slightly different set of fields, and collapsing them into one
// struct means the dispatcher and policy layers can walk a single
// []Destination slice.
//
// Kind taxonomy (extended from bash):
//
//	"http" / "https"                   — network request
//	"tcp" / "udp" / "dns" / "ssh"      — network (non-HTTP)
//	"git"                              — git clone/fetch/push URL
//	"proxy" / "proxy:<scheme>"         — proxy override
//	"resolve-override" / "resolved-ip" — curl --resolve
//	"connect-to-logical"  / "...-physical"
//	"ssh-jump" / "ssh-proxy-command"
//	"scan-target"                      — nmap/masscan target
//	"path:read"  / "path:write"        — file access (from Read/Write/Edit)
//	"path:glob"  / "path:grep"         — directory traversal (from Glob/Grep)
//	"mcp"                              — MCP server / tool invocation
//	"agent"                            — nested Agent/Task invocation
//	"unknown"                          — extractor could not classify
//
// Source identifies where in the raw input the destination came
// from: "argv[N]" | "input.url" | "input.path" | "input.server" | ...
type Destination struct {
	Kind   string `json:"kind"`
	Host   string `json:"host,omitempty"`
	Port   string `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	Raw    string `json:"raw"`
	Source string `json:"source"`
	Depth  int    `json:"depth"`
}

// ExtractorFn is the per-tool extraction function signature. raw is
// the JSON-decoded map from the tool-use event. Implementations MUST
// be side-effect free and MUST NOT panic on malformed input.
type ExtractorFn func(raw map[string]any) ([]Destination, error)
