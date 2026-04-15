package dispatch

import (
	"testing"
)

func TestDispatchBash(t *testing.T) {
	raw := map[string]any{
		"tool":  "bash",
		"input": map[string]any{"command": "curl https://api.target.com/users"},
	}
	dsts, err := Extract(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(dsts) != 1 || dsts[0].Host != "api.target.com" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchRead(t *testing.T) {
	raw := map[string]any{
		"tool":  "read",
		"input": map[string]any{"file_path": "/etc/passwd"},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Kind != "path:read" || dsts[0].Path != "/etc/passwd" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchWrite(t *testing.T) {
	raw := map[string]any{
		"tool":  "write",
		"input": map[string]any{"path": "/tmp/foo"},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Kind != "path:write" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchWebFetch(t *testing.T) {
	raw := map[string]any{
		"tool":  "webfetch",
		"input": map[string]any{"url": "https://api.target.com/users?id=1"},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Host != "api.target.com" || dsts[0].Path != "/users" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchMCPLegacyName(t *testing.T) {
	raw := map[string]any{
		"tool":  "mcp__supabase__list_tables",
		"input": map[string]any{},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Host != "mcp:supabase:list_tables" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchMCPNewName(t *testing.T) {
	raw := map[string]any{
		"tool": "mcp:supabase:list_tables",
		"input": map[string]any{
			"server":    "supabase",
			"tool_name": "list_tables",
		},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Host != "mcp:supabase:list_tables" {
		t.Errorf("got %+v", dsts)
	}
}

func TestDispatchUnknownToolIsNoop(t *testing.T) {
	raw := map[string]any{"tool": "exotic_custom_tool", "input": map[string]any{}}
	dsts, err := Extract(raw)
	if err != nil {
		t.Error(err)
	}
	if len(dsts) != 0 {
		t.Errorf("want empty, got %+v", dsts)
	}
}

func TestDispatchGlobPattern(t *testing.T) {
	raw := map[string]any{
		"tool":  "glob",
		"input": map[string]any{"pattern": "**/*.go"},
	}
	dsts, _ := Extract(raw)
	if len(dsts) != 1 || dsts[0].Kind != "path:glob" || dsts[0].Path != "**/*.go" {
		t.Errorf("got %+v", dsts)
	}
}
