package bash

import (
	"strings"

	"github.com/Hybirdss/jesses/internal/shellparse"
)

// Destination is the normalized form of one network target that a
// command could contact. It is what the policy layer evaluates
// against scope.txt rules.
//
// Kind is a short tag describing the protocol or transport shape:
//
//	"http"  / "https"   - fetched via HTTP(S)
//	"tcp"   / "udp"     - raw socket (nc, /dev/tcp, /dev/udp)
//	"dns"               - DNS lookup via dig/host/nslookup
//	"ssh"               - SSH login or SSH tunneling
//	"git"               - git clone/fetch/push target
//	"proxy"             - proxy server (not the request target)
//	"unknown"           - parser could not classify
//
// Host is the hostname or IP address. Port is the port number as a
// string; empty means "default for Kind" (443 for https, 22 for ssh,
// 53 for dns, and so on).
//
// Raw is the original token the destination came from, preserved for
// audit trace. Source identifies where in the Command the token
// appeared: "argv[3]", "env[HTTPS_PROXY]", "wrapper[env]",
// "redirect[<]", "subst[0].argv[2]", etc.
//
// Depth carries Command.Depth so that downstream consumers can tell
// destinations at the top level from destinations inside a subshell
// or bash -c payload.
type Destination struct {
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Port   string `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	Raw    string `json:"raw"`
	Source string `json:"source"`
	Depth  int    `json:"depth"`
}

// Extract returns every network destination reachable from a single
// shellparse.Command. It recurses into Subst and Reentry trees so
// destinations hidden inside $(...), <(...), `...`, bash -c, or eval
// are all surfaced at the top-level result.
func Extract(cmd shellparse.Command) []Destination {
	var dsts []Destination
	dsts = extractCommand(cmd, dsts)
	return dsts
}

// ExtractAll is the slice-level convenience for callers that already
// have a []Command from shellparse.Split. Destinations are returned
// in source order, preserving command order at the top level and
// emission order within each command.
func ExtractAll(cmds []shellparse.Command) []Destination {
	var dsts []Destination
	for _, c := range cmds {
		dsts = extractCommand(c, dsts)
	}
	return dsts
}

// extractCommand is the recursive worker: it processes one Command
// plus everything reachable from it.
func extractCommand(cmd shellparse.Command, dsts []Destination) []Destination {
	// Proxy env assignments — both plain Env (prefix-attached) and
	// assignments inside an `env` wrapper are extracted.
	dsts = appendProxyFromEnv(cmd.Env, "env", cmd.Depth, dsts)
	for _, w := range cmd.Wrappers {
		dsts = appendProxyFromEnvWrapper(w, cmd.Depth, dsts)
	}

	// Redirect destinations — /dev/tcp and /dev/udp in particular.
	for i, r := range cmd.Redirects {
		if h, p, kind, ok := shellparse.IsDevTCP(r.Target); ok {
			dsts = append(dsts, Destination{
				Kind:   kind,
				Host:   h,
				Port:   p,
				Raw:    r.Target,
				Source: fmtSource("redirect", i, r.Op),
				Depth:  cmd.Depth,
			})
		}
	}

	// argv itself — /dev/tcp can appear as a plain arg to `cat`, too.
	for i, a := range cmd.Argv {
		if h, p, kind, ok := shellparse.IsDevTCP(a); ok {
			dsts = append(dsts, Destination{
				Kind:   kind,
				Host:   h,
				Port:   p,
				Raw:    a,
				Source: fmtIndexedSource("argv", i),
				Depth:  cmd.Depth,
			})
		}
	}

	// Per-tool destination parsing: dispatch on argv[0].
	if len(cmd.Argv) > 0 {
		if fn, ok := toolParsers[basename(cmd.Argv[0])]; ok {
			dsts = fn(cmd, dsts)
		}
	}

	// Recurse into substitution bodies.
	for i, s := range cmd.Subst {
		for _, inner := range s.Parsed {
			dsts = extractWithSource(inner, dsts, fmtSubstSource(i, s.Kind))
		}
	}

	// Recurse into re-entry payloads (bash -c / eval).
	for i, inner := range cmd.Reentry {
		dsts = extractWithSource(inner, dsts, fmtIndexedSource("reentry", i))
	}

	return dsts
}

// extractWithSource calls extractCommand and prefixes Source on each
// newly appended destination so recursion is traceable ("subst[0].argv[2]"
// rather than just "argv[2]" in the flat result).
func extractWithSource(cmd shellparse.Command, dsts []Destination, prefix string) []Destination {
	before := len(dsts)
	dsts = extractCommand(cmd, dsts)
	for i := before; i < len(dsts); i++ {
		dsts[i].Source = prefix + "." + dsts[i].Source
	}
	return dsts
}

// basename strips a directory prefix from argv[0] so "/bin/curl"
// dispatches to the "curl" parser. It also strips a trailing version
// suffix in rare cases ("python3.11" → "python3.11", but "git-lfs"
// stays distinct).
func basename(arg string) string {
	if i := strings.LastIndexByte(arg, '/'); i >= 0 {
		arg = arg[i+1:]
	}
	return arg
}

// fmtSource composes a dotted source path with an index and operator,
// used for redirect provenance: fmtSource("redirect", 1, ">&") →
// "redirect[1:>&]".
func fmtSource(kind string, i int, op string) string {
	return kind + "[" + itoa(i) + ":" + op + "]"
}

// fmtIndexedSource returns "<kind>[<i>]".
func fmtIndexedSource(kind string, i int) string {
	return kind + "[" + itoa(i) + "]"
}

// fmtSubstSource returns "subst[<i>:<kind>]" where kind is one of the
// substitution kinds ("cmd", "backtick", "proc-in", "proc-out").
func fmtSubstSource(i int, kind string) string {
	return "subst[" + itoa(i) + ":" + kind + "]"
}

// itoa is a tiny integer-to-string helper to avoid fmt.Sprintf in the
// hot path (this code runs once per tool event in the hook).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
