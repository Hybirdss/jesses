package policy

import "testing"

func TestEvaluateExclusionFirst(t *testing.T) {
	src := `mode: advisory
in:  *.target.com
out: blog.target.com
`
	p := mustParse(t, src)

	// blog.target.com is matched by both in: *.target.com AND out: blog.target.com.
	// Exclusion-first means VerdictBlock.
	d := p.Evaluate(NSHost, "blog.target.com")
	if d.Verdict != VerdictBlock {
		t.Errorf("blog.target.com verdict = %v, want block", d.Verdict)
	}

	// api.target.com is matched by in: only.
	d = p.Evaluate(NSHost, "api.target.com")
	if d.Verdict != VerdictAllow {
		t.Errorf("api.target.com verdict = %v, want allow", d.Verdict)
	}
}

func TestEvaluateFirstMatchWinsWithinIn(t *testing.T) {
	src := `in: *.target.com
in: *.target.com
`
	p := mustParse(t, src)
	d := p.Evaluate(NSHost, "api.target.com")
	if d.RuleLine != 1 {
		t.Errorf("first-match-wins: got line %d, want 1", d.RuleLine)
	}
}

func TestEvaluateUnpolicedAdvisory(t *testing.T) {
	p := mustParse(t, "mode: advisory\nin: *.target.com\n")
	d := p.Evaluate(NSHost, "unknown.example.com")
	if d.Verdict != VerdictWarn {
		t.Errorf("unpoliced advisory = %v, want warn", d.Verdict)
	}
}

func TestEvaluateUnpolicedStrict(t *testing.T) {
	p := mustParse(t, "mode: strict\nin: *.target.com\n")
	d := p.Evaluate(NSHost, "unknown.example.com")
	if d.Verdict != VerdictBlock {
		t.Errorf("unpoliced strict = %v, want block", d.Verdict)
	}
}

func TestEvaluateNamespaceIsolation(t *testing.T) {
	// A host rule should not match a path lookup, even if the textual
	// value happens to look the same.
	p := mustParse(t, "in: example.com\n")
	d := p.Evaluate(NSPath, "example.com")
	if d.Verdict == VerdictAllow {
		t.Error("host rule should not match in path namespace")
	}
}

func TestEvaluateMixedNamespaces(t *testing.T) {
	src := `in:  *.target.com
in:  path:/home/user/**
out: path:/home/user/secrets/**
in:  lidofinance/core
in:  arb:0xDEADBEEF
in:  mcp:context7
`
	p := mustParse(t, src)

	cases := []struct {
		ns    Namespace
		value string
		want  Verdict
	}{
		{NSHost, "api.target.com", VerdictAllow},
		{NSHost, "evil.com", VerdictWarn},
		{NSPath, "/home/user/project/main.go", VerdictAllow},
		{NSPath, "/home/user/secrets/aws.key", VerdictBlock},
		{NSPath, "/etc/passwd", VerdictWarn},
		{NSRepo, "lidofinance/core", VerdictAllow},
		{NSRepo, "other/repo", VerdictWarn},
		{NSContract, "arb:0xdeadbeef", VerdictAllow},
		{NSContract, "eth:0xDEADBEEF", VerdictWarn},
		{NSMCP, "mcp:context7", VerdictAllow},
		{NSMCP, "mcp:context7:query", VerdictAllow},
		{NSMCP, "mcp:other", VerdictWarn},
	}
	for _, c := range cases {
		d := p.Evaluate(c.ns, c.value)
		if d.Verdict != c.want {
			t.Errorf("Evaluate(%v, %q) = %v, want %v", c.ns, c.value, d.Verdict, c.want)
		}
	}
}

func TestEvaluateDecisionReasons(t *testing.T) {
	p := mustParse(t, "out: blog.target.com\nin: *.target.com\n")

	d := p.Evaluate(NSHost, "blog.target.com")
	if d.RuleLine != 1 {
		t.Errorf("blocked by line 1, got %d", d.RuleLine)
	}
	if d.Reason == "" {
		t.Error("block decision should have a reason")
	}

	d = p.Evaluate(NSHost, "api.target.com")
	if d.RuleLine != 2 {
		t.Errorf("allowed by line 2, got %d", d.RuleLine)
	}
}

// TestStringerMethods exercises the String() helpers on each enum so that
// any stringer drift is caught at test time rather than in log output.
func TestStringerMethods(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{ActionIn.String(), "in"},
		{ActionOut.String(), "out"},
		{NSHost.String(), "host"},
		{NSPath.String(), "path"},
		{NSRepo.String(), "repo"},
		{NSContract.String(), "contract"},
		{NSMCP.String(), "mcp"},
		{ModeStrict.String(), "strict"},
		{ModeAdvisory.String(), "advisory"},
		{VerdictAllow.String(), "allow"},
		{VerdictWarn.String(), "warn"},
		{VerdictBlock.String(), "block"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("stringer: got %q, want %q", c.got, c.want)
		}
	}
}

// mustParse is a test helper.
func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
