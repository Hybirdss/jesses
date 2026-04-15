// Package mcp extracts destinations from MCP (Model Context Protocol)
// tool-use events.
//
// Each MCP tool call is identified by its server and tool name in
// the form "mcp:<server>[:<tool>]". The policy layer matches this
// against `in: mcp:server[:tool]` or `out: mcp:server` rules.
//
// This extractor does NOT walk into the MCP tool's input payload —
// that is per-server-type work and is deferred to v0.2. At v0.1 we
// emit one destination per MCP call, correctly namespaced, so policy
// can allow or block server-by-server.
package mcp

import (
	"strings"

	"github.com/Hybirdss/jesses/internal/extractors"
)

// Extract pulls the MCP server + tool name from a raw tool-use event.
// Agent harnesses use slightly different field names — the common
// ones are "server" / "tool_name" (Claude Code) and "mcp_server" /
// "mcp_tool" (Cline, Cursor). We accept both.
func Extract(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	server := pickStr(input, "server", "mcp_server")
	tool := pickStr(input, "tool_name", "mcp_tool", "name")
	if server == "" {
		// Some harnesses pass the combined identifier as tool.
		name, _ := raw["tool"].(string)
		if strings.HasPrefix(name, "mcp:") {
			server = strings.TrimPrefix(name, "mcp:")
		} else if strings.HasPrefix(name, "mcp__") {
			// Legacy Claude Code scheme: mcp__<server>__<tool>
			rest := strings.TrimPrefix(name, "mcp__")
			if idx := strings.Index(rest, "__"); idx > 0 {
				server = rest[:idx]
				tool = rest[idx+2:]
			} else {
				server = rest
			}
		}
	}
	if server == "" {
		return nil, nil
	}
	identifier := "mcp:" + server
	if tool != "" {
		identifier += ":" + tool
	}
	return []extractors.Destination{{
		Kind:   "mcp",
		Host:   identifier,
		Raw:    identifier,
		Source: "input",
	}}, nil
}

// pickStr returns the first non-empty string value from the given
// keys in the map. Used to tolerate harness variation without a
// brittle canonical schema.
func pickStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
