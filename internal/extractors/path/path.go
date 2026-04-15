// Package path extracts file-path destinations from Read / Write /
// Edit / Glob / Grep tool-use events.
//
// Unlike the bash extractor this one is trivial: the tool input
// carries a single well-named field and the destination is that
// string. The main value-add here is normalizing the path (resolving
// `.` / `..`, collapsing `//`, tracking absolute vs relative) so
// policy matchers see a consistent shape.
//
// Read-only tools (Read, Glob, Grep) emit Kind "path:read".
// Write / Edit emit Kind "path:write".
package path

import (
	"path/filepath"

	"github.com/Hybirdss/jesses/internal/extractors"
)

// Extract pulls the path field from a Read / Glob / Grep event. The
// returned Destination has Kind="path:read".
func ExtractRead(raw map[string]any) ([]extractors.Destination, error) {
	return extractPath(raw, "path:read", "input.path")
}

// ExtractWrite handles Write / Edit / NotebookEdit events. Kind is
// "path:write" so policy can allow reads globally and tighten writes.
func ExtractWrite(raw map[string]any) ([]extractors.Destination, error) {
	return extractPath(raw, "path:write", "input.path")
}

// ExtractGlob handles Glob events. Pattern field becomes the Path;
// Kind="path:glob". The matching filesystem is implicitly the agent's
// CWD — we do not attempt to resolve globs here, only to surface the
// pattern itself as a scope-checkable thing.
func ExtractGlob(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	pattern, _ := input["pattern"].(string)
	if pattern == "" {
		return nil, nil
	}
	return []extractors.Destination{{
		Kind:   "path:glob",
		Path:   pattern,
		Raw:    pattern,
		Source: "input.pattern",
	}}, nil
}

// ExtractGrep is the same shape as ExtractGlob — path is the target
// directory, Kind="path:grep".
func ExtractGrep(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	// Grep's target may appear under "path" or default to cwd when
	// omitted. The pattern field describes content, not a destination.
	p, _ := input["path"].(string)
	if p == "" {
		p = "."
	}
	cleaned := filepath.Clean(p)
	return []extractors.Destination{{
		Kind:   "path:grep",
		Path:   cleaned,
		Raw:    p,
		Source: "input.path",
	}}, nil
}

// extractPath is the shared worker for Read/Write/Edit which all
// carry the path under input.path.
func extractPath(raw map[string]any, kind, source string) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	p, _ := input["path"].(string)
	if p == "" {
		// Look for file_path (some agent harnesses use that spelling)
		p, _ = input["file_path"].(string)
	}
	if p == "" {
		return nil, nil
	}
	cleaned := filepath.Clean(p)
	return []extractors.Destination{{
		Kind:   kind,
		Path:   cleaned,
		Raw:    p,
		Source: source,
	}}, nil
}
