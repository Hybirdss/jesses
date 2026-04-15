package shellparse

import (
	"errors"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Segment walking
// ----------------------------------------------------------------------------

func TestSplitEmpty(t *testing.T) {
	cmds, err := SplitString("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("want 0 commands, got %d", len(cmds))
	}
}

func TestSplitWhitespace(t *testing.T) {
	cmds, err := SplitString("   \t   ")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("want 0 commands, got %d", len(cmds))
	}
}

func TestSplitSingleCommand(t *testing.T) {
	cmds := mustSplit(t, "curl https://api.target.com/users")
	if len(cmds) != 1 {
		t.Fatalf("want 1 command, got %d", len(cmds))
	}
	expectArgv(t, cmds[0], "curl", "https://api.target.com/users")
	if cmds[0].Depth != 0 || cmds[0].Origin != "top" {
		t.Errorf("depth=%d origin=%q", cmds[0].Depth, cmds[0].Origin)
	}
}

func TestSplitSemicolon(t *testing.T) {
	cmds := mustSplit(t, "a foo ; b bar")
	if len(cmds) != 2 {
		t.Fatalf("want 2 commands, got %d", len(cmds))
	}
	expectArgv(t, cmds[0], "a", "foo")
	expectArgv(t, cmds[1], "b", "bar")
	if cmds[0].Terminator != TokSemicolon {
		t.Errorf("term[0] = %v, want TokSemicolon", cmds[0].Terminator)
	}
	if cmds[1].Terminator != TokNewline {
		t.Errorf("term[1] = %v, want TokNewline", cmds[1].Terminator)
	}
}

func TestSplitPipeline(t *testing.T) {
	cmds := mustSplit(t, "a | b | c")
	if len(cmds) != 3 {
		t.Fatalf("want 3 commands, got %d", len(cmds))
	}
	for i, term := range []TokenType{TokPipe, TokPipe, TokNewline} {
		if cmds[i].Terminator != term {
			t.Errorf("cmds[%d].Terminator = %v, want %v", i, cmds[i].Terminator, term)
		}
	}
}

func TestSplitLogicalChain(t *testing.T) {
	cmds := mustSplit(t, "a && b || c")
	if len(cmds) != 3 {
		t.Fatalf("want 3 commands, got %d", len(cmds))
	}
	if cmds[0].Terminator != TokAndAnd || cmds[1].Terminator != TokOrOr {
		t.Errorf("terminators = %v %v", cmds[0].Terminator, cmds[1].Terminator)
	}
}

func TestSplitBackground(t *testing.T) {
	cmds := mustSplit(t, "long-running & echo done")
	if len(cmds) != 2 {
		t.Fatalf("want 2 commands, got %d", len(cmds))
	}
	if cmds[0].Terminator != TokAmp {
		t.Errorf("terminator[0] = %v, want TokAmp", cmds[0].Terminator)
	}
}

func TestSplitMultiline(t *testing.T) {
	cmds := mustSplit(t, "a\nb\nc")
	if len(cmds) != 3 {
		t.Fatalf("want 3 commands, got %d", len(cmds))
	}
}

// ----------------------------------------------------------------------------
// Env assignment splitting
// ----------------------------------------------------------------------------

func TestEnvAssignmentSingle(t *testing.T) {
	cmds := mustSplit(t, "HTTPS_PROXY=http://evil.com:8080 curl https://api.target.com/users")
	cmd := cmds[0]
	if len(cmd.Env) != 1 || cmd.Env[0] != "HTTPS_PROXY=http://evil.com:8080" {
		t.Errorf("env = %v", cmd.Env)
	}
	expectArgv(t, cmd, "curl", "https://api.target.com/users")
}

func TestEnvAssignmentMultiple(t *testing.T) {
	cmds := mustSplit(t, "A=1 B=2 C=3 curl evil.com")
	cmd := cmds[0]
	if len(cmd.Env) != 3 {
		t.Errorf("env = %v, want 3 entries", cmd.Env)
	}
	expectArgv(t, cmd, "curl", "evil.com")
}

func TestEnvAssignmentNotConfusedWithArg(t *testing.T) {
	// --flag=value starts with '-', not a valid identifier. Must not
	// be mistaken for env assignment.
	cmds := mustSplit(t, "curl --header=X-Foo:bar evil.com")
	cmd := cmds[0]
	if len(cmd.Env) != 0 {
		t.Errorf("env = %v, want empty", cmd.Env)
	}
	expectArgv(t, cmd, "curl", "--header=X-Foo:bar", "evil.com")
}

func TestIsEnvAssignment(t *testing.T) {
	cases := map[string]bool{
		"FOO=bar":     true,
		"_FOO=bar":    true,
		"foo_bar=baz": true,
		"X=":          true,
		"1FOO=bar":    false,
		"--foo=bar":   false,
		"-x=1":        false,
		"":            false,
		"foo":         false,
		"foo bar=baz": false,
		"FOO-BAR=baz": false,
	}
	for in, want := range cases {
		if got := isEnvAssignment(in); got != want {
			t.Errorf("isEnvAssignment(%q) = %v, want %v", in, got, want)
		}
	}
}

// ----------------------------------------------------------------------------
// MaxDepth and recursion guard
// ----------------------------------------------------------------------------

func TestMaxDepthExceeded(t *testing.T) {
	// build depth 9: 9 layers of $(...)
	payload := "echo hi"
	for i := 0; i < 9; i++ {
		payload = "$(" + payload + ")"
	}
	input := "curl " + payload
	_, err := SplitString(input)
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Errorf("got err=%v, want ErrMaxDepthExceeded", err)
	}
}

func TestDepthWithinLimit(t *testing.T) {
	// depth 3 should pass cleanly
	payload := "echo hi"
	for i := 0; i < 3; i++ {
		payload = "$(" + payload + ")"
	}
	_, err := SplitString("curl " + payload)
	if err != nil {
		t.Fatal(err)
	}
}

// ----------------------------------------------------------------------------
// Terminator tracking
// ----------------------------------------------------------------------------

func TestMixedTerminators(t *testing.T) {
	cmds := mustSplit(t, "a ; b | c && d || e & f")
	wants := []TokenType{TokSemicolon, TokPipe, TokAndAnd, TokOrOr, TokAmp, TokNewline}
	if len(cmds) != len(wants) {
		t.Fatalf("want %d cmds, got %d", len(wants), len(cmds))
	}
	for i, w := range wants {
		if cmds[i].Terminator != w {
			t.Errorf("cmds[%d].Terminator = %v, want %v", i, cmds[i].Terminator, w)
		}
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func mustSplit(t *testing.T, input string) []Command {
	t.Helper()
	cmds, err := SplitString(input)
	if err != nil {
		t.Fatalf("SplitString(%q): %v", input, err)
	}
	return cmds
}

func expectArgv(t *testing.T, cmd Command, want ...string) {
	t.Helper()
	if len(cmd.Argv) != len(want) {
		t.Errorf("argv len = %d, want %d (argv=%v)", len(cmd.Argv), len(want), cmd.Argv)
		return
	}
	for i, w := range want {
		if cmd.Argv[i] != w {
			t.Errorf("argv[%d] = %q, want %q", i, cmd.Argv[i], w)
		}
	}
}

func expectContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%q does not contain %q", s, sub)
	}
}
