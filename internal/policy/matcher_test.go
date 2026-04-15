package policy

import "testing"

// TestAnchoredSubdomain is the critical regression test: *.target.com MUST
// NOT match evil-target.com. This is the bug that scope_checker.py in the
// bb/ harness specifically guards against, and the same invariant holds for
// jesses v0.1 host matching.
func TestAnchoredSubdomain(t *testing.T) {
	matches := []string{
		"sub.target.com",
		"a.b.target.com",
		"very.deep.sub.target.com",
		"Sub.TARGET.COM", // case-insensitive
	}
	for _, h := range matches {
		if !matchHost("*.target.com", h) {
			t.Errorf("*.target.com should match %q", h)
		}
	}

	notMatches := []string{
		"target.com",      // base domain itself must NOT match
		"evil-target.com", // subdomain confusion — the bug we're defending against
		"notarget.com",    // prefix confusion
		"target.com.evil.com",
		"",
	}
	for _, h := range notMatches {
		if matchHost("*.target.com", h) {
			t.Errorf("*.target.com must NOT match %q", h)
		}
	}
}

func TestHostExactMatch(t *testing.T) {
	if !matchHost("api.target.com", "api.target.com") {
		t.Error("exact match failed")
	}
	if matchHost("api.target.com", "api.target.com.evil.com") {
		t.Error("exact match must not allow suffix")
	}
	if !matchHost("API.target.com", "api.TARGET.com") {
		t.Error("host matching should be case-insensitive")
	}
}

func TestHostEmptyWildcard(t *testing.T) {
	// "*." by itself is nonsense; verify it does not match anything.
	if matchHost("*.", "foo") {
		t.Error("*. should not match anything")
	}
}

func TestPathGlob(t *testing.T) {
	cases := []struct {
		pattern, input string
		want           bool
	}{
		// Exact paths.
		{"/src/main.go", "/src/main.go", true},
		{"/src/main.go", "/src/main.py", false},

		// Single-star matches within one segment.
		{"/src/*.go", "/src/main.go", true},
		{"/src/*.go", "/src/sub/main.go", false}, // * does not cross /

		// Double-star crosses segments.
		{"/src/**/*.go", "/src/main.go", true},
		{"/src/**/*.go", "/src/sub/main.go", true},
		{"/src/**/*.go", "/src/a/b/c/main.go", true},
		{"/src/**", "/src/anything/at/all", true},
		{"/src/**", "/other/path", false},

		// Double-star in the middle.
		{"/**/secrets/**", "/home/user/secrets/key.txt", true},
		{"/**/secrets/**", "/home/user/secrets/deep/key.txt", true},
		{"/**/secrets/**", "/home/user/not-secrets/key.txt", false},

		// Question mark matches single char.
		{"/src/?.go", "/src/a.go", true},
		{"/src/?.go", "/src/ab.go", false},

		// Character class via path.Match.
		{"/src/[ab].go", "/src/a.go", true},
		{"/src/[ab].go", "/src/b.go", true},
		{"/src/[ab].go", "/src/c.go", false},
	}
	for _, c := range cases {
		got := matchPath(c.pattern, c.input)
		if got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.input, got, c.want)
		}
	}
}

func TestPathGlobEdgeCases(t *testing.T) {
	// ** at the start.
	if !matchPath("**/*.key", "etc/foo/bar.key") {
		t.Error("leading ** failed to match")
	}
	// ** as the only segment.
	if !matchPath("**", "anything/at/all") {
		t.Error("sole ** failed to match")
	}
	// Empty input.
	if matchPath("*.go", "") {
		t.Error("empty input should not match *.go")
	}
}

func TestRepoMatch(t *testing.T) {
	if !matchRepo("lidofinance/core", "lidofinance/core") {
		t.Error("exact repo match failed")
	}
	if matchRepo("lidofinance/core", "lidofinance/cli") {
		t.Error("repo match should not allow different repo")
	}
	if matchRepo("lidofinance/core", "LidoFinance/core") {
		t.Error("v0.1 repo match is case-sensitive by design")
	}
}

func TestContractMatch(t *testing.T) {
	if !matchContract("arb:0xDEADBEEF", "arb:0xdeadbeef") {
		t.Error("contract match should be case-insensitive")
	}
	if matchContract("arb:0xDEADBEEF", "eth:0xDEADBEEF") {
		t.Error("contract match must respect chain prefix")
	}
}

func TestMCPMatch(t *testing.T) {
	cases := []struct {
		pattern, input string
		want           bool
	}{
		{"mcp:context7", "mcp:context7", true},
		{"mcp:context7", "mcp:context7:query", true},
		{"mcp:context7", "mcp:context7:resolve", true},
		{"mcp:context7", "mcp:other", false},
		{"mcp:context7:query", "mcp:context7:query", true},
		{"mcp:context7:query", "mcp:context7:resolve", false},
		// Prefix must be followed by ':' — "mcp:context7-v2" must not match "mcp:context7".
		{"mcp:context7", "mcp:context7-v2", false},
	}
	for _, c := range cases {
		got := matchMCP(c.pattern, c.input)
		if got != c.want {
			t.Errorf("matchMCP(%q, %q) = %v, want %v", c.pattern, c.input, got, c.want)
		}
	}
}

func TestRuleMatch(t *testing.T) {
	r := Rule{Action: ActionIn, Namespace: NSHost, Pattern: "*.target.com"}
	if !r.Match("api.target.com") {
		t.Error("Rule.Match host wildcard failed")
	}
	if r.Match("evil-target.com") {
		t.Error("Rule.Match must not confuse subdomain")
	}
}
