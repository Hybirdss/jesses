package shellparse

import "testing"

// ----------------------------------------------------------------------------
// Bare wrappers
// ----------------------------------------------------------------------------

func TestWrapperSudo(t *testing.T) {
	cmds := mustSplit(t, "sudo curl -X POST https://api.target.com/users")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "-X", "POST", "https://api.target.com/users")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "sudo" {
		t.Errorf("wrappers = %v, want [sudo]", cmd.Wrappers)
	}
}

func TestWrapperSudoWithUser(t *testing.T) {
	// -u USER consumes the next token
	cmds := mustSplit(t, "sudo -u root curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "sudo -u root" {
		t.Errorf("wrappers = %v, want [sudo -u root]", cmd.Wrappers)
	}
}

func TestWrapperSudoDoubleDash(t *testing.T) {
	cmds := mustSplit(t, "sudo -- curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "sudo --" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

func TestWrapperTimeout(t *testing.T) {
	// timeout DURATION COMMAND
	cmds := mustSplit(t, "timeout 30 curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "timeout 30" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

func TestWrapperTimeoutWithFlag(t *testing.T) {
	// timeout -k 5 30 curl evil.com
	cmds := mustSplit(t, "timeout -k 5 30 curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "timeout -k 5 30" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

func TestWrapperEnvWithAssignment(t *testing.T) {
	// `env` wrapper: env X=y COMMAND. X=y becomes part of the wrapper,
	// COMMAND is the tail.
	cmds := mustSplit(t, "env HTTPS_PROXY=http://evil.com curl api.target.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "api.target.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "env HTTPS_PROXY=http://evil.com" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

func TestWrapperEnvDashI(t *testing.T) {
	cmds := mustSplit(t, "env -i X=1 curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "env -i X=1" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

func TestWrapperChroot(t *testing.T) {
	cmds := mustSplit(t, "chroot /srv curl evil.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "evil.com")
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "chroot /srv" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}

// ----------------------------------------------------------------------------
// Stacked wrappers
// ----------------------------------------------------------------------------

func TestWrappersStacked(t *testing.T) {
	// sudo → env → timeout → curl
	cmds := mustSplit(t, "sudo env HTTPS_PROXY=x timeout 30 curl api.target.com")
	cmd := cmds[0]
	expectArgv(t, cmd, "curl", "api.target.com")
	want := []string{"sudo", "env HTTPS_PROXY=x", "timeout 30"}
	if len(cmd.Wrappers) != len(want) {
		t.Fatalf("wrappers = %v, want %v", cmd.Wrappers, want)
	}
	for i, w := range want {
		if cmd.Wrappers[i] != w {
			t.Errorf("wrappers[%d] = %q, want %q", i, cmd.Wrappers[i], w)
		}
	}
}

func TestWrappersNothingWrapped(t *testing.T) {
	cmds := mustSplit(t, "curl evil.com")
	cmd := cmds[0]
	if len(cmd.Wrappers) != 0 {
		t.Errorf("wrappers = %v, want empty", cmd.Wrappers)
	}
	expectArgv(t, cmd, "curl", "evil.com")
}

// ----------------------------------------------------------------------------
// Edge case: wrapper with nothing after
// ----------------------------------------------------------------------------

func TestWrapperDanglingSudo(t *testing.T) {
	// `sudo` alone - no tail command
	cmds := mustSplit(t, "sudo")
	cmd := cmds[0]
	if len(cmd.Argv) != 0 {
		t.Errorf("argv = %v, want empty", cmd.Argv)
	}
	if len(cmd.Wrappers) != 1 || cmd.Wrappers[0] != "sudo" {
		t.Errorf("wrappers = %v", cmd.Wrappers)
	}
}
