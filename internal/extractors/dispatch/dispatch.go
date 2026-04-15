// Package dispatch routes a raw tool-use event to the right per-tool
// extractor sub-package and produces a flat []extractors.Destination.
//
// The tool name in the raw event (bash / read / write / webfetch /
// mcp / agent / ...) determines the route. Unknown tool names fall
// through to a no-op that still returns empty destinations so the
// caller can continue without special-casing unsupported tools.
//
// This is the single place where tool-name strings are hardcoded —
// adding a new tool means editing the table here and adding the
// extractor sub-package. hook.go and pkg/jesses never see raw tool
// names directly.
package dispatch

import (
	"strings"

	"github.com/Hybirdss/jesses/internal/extractors"
	"github.com/Hybirdss/jesses/internal/extractors/bash"
	"github.com/Hybirdss/jesses/internal/extractors/mcp"
	"github.com/Hybirdss/jesses/internal/extractors/path"
	"github.com/Hybirdss/jesses/internal/extractors/web"
	"github.com/Hybirdss/jesses/internal/shellparse"
)

// Extract routes the raw event to the right extractor and returns
// the destinations. Always returns a (possibly empty) slice and nil
// error on well-formed input; the sub-extractors are tolerant of
// missing fields and shape drift.
//
// The supported tool names are the union of Claude Code, Cursor,
// Cline, and the Claude Agent SDK conventions; adding an agent
// harness requires only updating the switch here.
func Extract(raw map[string]any) ([]extractors.Destination, error) {
	tool, _ := raw["tool"].(string)
	tl := strings.ToLower(tool)

	switch tl {
	case "bash", "shell", "run":
		return extractBash(raw)
	case "read":
		return path.ExtractRead(raw)
	case "write", "edit", "notebookedit":
		return path.ExtractWrite(raw)
	case "glob":
		return path.ExtractGlob(raw)
	case "grep":
		return path.ExtractGrep(raw)
	case "webfetch":
		return web.ExtractFetch(raw)
	case "websearch":
		return web.ExtractSearch(raw)
	case "task", "agent":
		// Nested agents are noted but carry no destination at this
		// layer (per-tool events from the nested agent are dispatched
		// through their own hook instance).
		return nil, nil
	}

	// MCP tools arrive under various naming conventions — we dispatch
	// anything matching a recognized MCP shape.
	if strings.HasPrefix(tl, "mcp:") || strings.HasPrefix(tl, "mcp__") {
		return mcp.Extract(raw)
	}
	return nil, nil
}

// extractBash is the bash-specific path: the raw input has
// input.command as the shell string. We run shellparse + bash
// extractor and convert bash.Destination → extractors.Destination.
func extractBash(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	cmd, _ := input["command"].(string)
	if cmd == "" {
		return nil, nil
	}
	cmds, err := shellparse.SplitString(cmd)
	if err != nil {
		return nil, err
	}
	bashDsts := bash.ExtractAll(cmds)
	out := make([]extractors.Destination, len(bashDsts))
	for i, d := range bashDsts {
		out[i] = extractors.Destination{
			Kind:   d.Kind,
			Host:   d.Host,
			Port:   d.Port,
			Path:   d.Path,
			Raw:    d.Raw,
			Source: "input.command." + d.Source,
			Depth:  d.Depth,
		}
	}
	return out, nil
}
