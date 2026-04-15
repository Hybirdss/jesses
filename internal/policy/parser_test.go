package policy

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	src := `# example policy
mode: strict

in:  *.target.com
in:  api.example.com
out: blog.target.com
in:  path:/home/user/project/**
in:  arb:0x489ee077994B6658eAfA855C308275EAd8097C4A
in:  lidofinance/core
in:  mcp:context7
`
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if p.Mode != ModeStrict {
		t.Errorf("mode = %v, want strict", p.Mode)
	}
	if len(p.Rules) != 7 {
		t.Fatalf("got %d rules, want 7", len(p.Rules))
	}
	expected := []struct {
		action Action
		ns     Namespace
		patt   string
	}{
		{ActionIn, NSHost, "*.target.com"},
		{ActionIn, NSHost, "api.example.com"},
		{ActionOut, NSHost, "blog.target.com"},
		{ActionIn, NSPath, "/home/user/project/**"},
		{ActionIn, NSContract, "arb:0x489ee077994B6658eAfA855C308275EAd8097C4A"},
		{ActionIn, NSRepo, "lidofinance/core"},
		{ActionIn, NSMCP, "mcp:context7"},
	}
	for i, e := range expected {
		if p.Rules[i].Action != e.action {
			t.Errorf("rule %d: action = %v, want %v", i, p.Rules[i].Action, e.action)
		}
		if p.Rules[i].Namespace != e.ns {
			t.Errorf("rule %d: ns = %v, want %v", i, p.Rules[i].Namespace, e.ns)
		}
		if p.Rules[i].Pattern != e.patt {
			t.Errorf("rule %d: pattern = %q, want %q", i, p.Rules[i].Pattern, e.patt)
		}
	}
}

func TestParseDefaultMode(t *testing.T) {
	p, err := ParseBytes([]byte("in: example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeAdvisory {
		t.Errorf("default mode should be advisory, got %v", p.Mode)
	}
}

func TestParseInlineComment(t *testing.T) {
	src := "in:  *.target.com # main scope\n"
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(p.Rules))
	}
	if p.Rules[0].Pattern != "*.target.com" {
		t.Errorf("inline comment not stripped: %q", p.Rules[0].Pattern)
	}
}

func TestParseHashComment(t *testing.T) {
	src := "# full line comment\nin: example.com\n# another\n"
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(p.Rules))
	}
}

func TestParseBlankLines(t *testing.T) {
	src := "\n\nin: example.com\n\n\nout: blog.example.com\n"
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(p.Rules))
	}
}

func TestParseInvalidMode(t *testing.T) {
	_, err := ParseBytes([]byte("mode: lax\n"))
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1", pe.Line)
	}
}

func TestParseInvalidLine(t *testing.T) {
	_, err := ParseBytes([]byte("something_else\n"))
	if err == nil {
		t.Fatal("expected error for unknown directive")
	}
}

func TestParseEmptyRule(t *testing.T) {
	_, err := ParseBytes([]byte("in:\n"))
	if err == nil {
		t.Fatal("expected error for empty rule value")
	}
}

func TestParseSHA256(t *testing.T) {
	p, err := ParseBytes([]byte("in: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SHA256) != 64 {
		t.Errorf("SHA256 should be 64 hex chars, got %d", len(p.SHA256))
	}
}

func TestParseLineNumbers(t *testing.T) {
	src := `# comment on line 1
# comment on line 2
in: a.com
# comment on line 4
in: b.com
`
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(p.Rules))
	}
	if p.Rules[0].Line != 3 {
		t.Errorf("first rule line = %d, want 3", p.Rules[0].Line)
	}
	if p.Rules[1].Line != 5 {
		t.Errorf("second rule line = %d, want 5", p.Rules[1].Line)
	}
}

func TestClassifyShapes(t *testing.T) {
	cases := []struct {
		input   string
		wantNS  Namespace
		wantPat string
	}{
		// Domains
		{"example.com", NSHost, "example.com"},
		{"*.example.com", NSHost, "*.example.com"},
		{"api.sub.example.com", NSHost, "api.sub.example.com"},

		// Paths
		{"path:/src/**/*.go", NSPath, "/src/**/*.go"},
		{"path:/tmp/foo", NSPath, "/tmp/foo"},

		// MCP
		{"mcp:context7", NSMCP, "mcp:context7"},
		{"mcp:context7:query", NSMCP, "mcp:context7:query"},

		// Contracts
		{"arb:0x489ee077994B6658eAfA855C308275EAd8097C4A", NSContract, "arb:0x489ee077994B6658eAfA855C308275EAd8097C4A"},
		{"eth:0xDEADBEEF", NSContract, "eth:0xDEADBEEF"},
		{"base:0xabc123", NSContract, "base:0xabc123"},

		// Repos
		{"lidofinance/core", NSRepo, "lidofinance/core"},
		{"org/sub-repo", NSRepo, "org/sub-repo"},

		// Garbage fallback: malformed contract-looking input falls back to host.
		// (This is valid-by-design — users writing garbage get host classification
		// and the matcher will simply not find it.)
		{"eth:0xGARBAGE", NSHost, "eth:0xGARBAGE"},
	}
	for _, c := range cases {
		ns, pat := classify(c.input)
		if ns != c.wantNS {
			t.Errorf("classify(%q): ns = %v, want %v", c.input, ns, c.wantNS)
		}
		if pat != c.wantPat {
			t.Errorf("classify(%q): pattern = %q, want %q", c.input, pat, c.wantPat)
		}
	}
}

func TestParseFromReader(t *testing.T) {
	p, err := Parse(strings.NewReader("in: example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(p.Rules))
	}
}

func TestParseModeAnywhere(t *testing.T) {
	// mode: directive can appear after rules; last write wins.
	src := "in: a.com\nmode: strict\n"
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeStrict {
		t.Errorf("mode = %v, want strict", p.Mode)
	}
}
