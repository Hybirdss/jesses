package shellparse

import "strings"

// extractRedirects walks argv and peels off redirection operators,
// returning the cleaned argv and a redirects list in source order.
//
// Both spaced ("cat < file") and unspaced ("2>&1", ">>out.log") forms
// are recognized. When an operator appears alone, the next argv token
// is consumed as its target. When an operator is glued to its target
// ("2>err.log"), the glued suffix is the target and no extra token is
// consumed.
//
// Unparseable tokens (a bare ">" with no following argv) are recorded
// as a Redirect with an empty Target so that an audit reader still
// sees the malformed operator.
func extractRedirects(argv []string) ([]string, []Redirect) {
	var out []string
	var redirs []Redirect
	for i := 0; i < len(argv); i++ {
		op, rest, fd, ok := matchRedirOperator(argv[i])
		if !ok {
			out = append(out, argv[i])
			continue
		}
		if rest != "" {
			redirs = append(redirs, Redirect{Op: op, FD: fd, Target: rest})
			continue
		}
		if i+1 >= len(argv) {
			redirs = append(redirs, Redirect{Op: op, FD: fd})
			continue
		}
		redirs = append(redirs, Redirect{Op: op, FD: fd, Target: argv[i+1]})
		i++
	}
	return out, redirs
}

// matchRedirOperator tries to parse tok as a shell redirection operator.
//
// The return values are:
//
//	op   — the operator text ("<", ">", ">>", "<<", "<<<",
//	       ">&", "<&", "&>", "&>>")
//	rest — any trailing target text glued to the operator ("2>out" → "out")
//	fd   — the file descriptor being redirected. Defaults: 0 for reads
//	       (<, <<, <<<, <&), 1 for writes (>, >>, >&, &>, &>>). A leading
//	       digit in tok overrides the default ("2>" → fd=2).
//	ok   — false when tok is not a redirection operator at all.
//
// Tokens that begin with a digit but contain no recognized operator
// (like "123" or "1log") return ok=false so they remain in argv.
func matchRedirOperator(tok string) (op, rest string, fd int, ok bool) {
	i := 0
	for i < len(tok) && tok[i] >= '0' && tok[i] <= '9' {
		i++
	}
	fdStr := tok[:i]
	body := tok[i:]

	prefixes := []struct {
		p   string
		def int
	}{
		{"<<<", 0},
		{"<<", 0},
		{"&>>", 1},
		{"&>", 1},
		{">>", 1},
		{">&", 1},
		{"<&", 0},
		{">", 1},
		{"<", 0},
	}
	for _, d := range prefixes {
		if !strings.HasPrefix(body, d.p) {
			continue
		}
		rest = body[len(d.p):]
		// `<(` and `>(` are process substitutions, not redirects.
		// Reject when the remainder begins with '(' and the base
		// prefix is the single-char < or >.
		if (d.p == "<" || d.p == ">") && strings.HasPrefix(rest, "(") {
			continue
		}
		op = d.p
		if fdStr != "" {
			for _, c := range fdStr {
				fd = fd*10 + int(c-'0')
			}
		} else {
			fd = d.def
		}
		return op, rest, fd, true
	}
	return "", "", 0, false
}

// IsDevTCP reports whether target is a /dev/tcp/HOST/PORT or
// /dev/udp/HOST/PORT bash raw-socket path. These are not filesystem
// paths — bash opens a network socket when they appear in a
// redirection or as a filename to read/write.
//
// The split is on '/'; HOST is taken verbatim (may be a dotted IP, an
// IPv6 address, or a DNS name), PORT is numeric or a service name.
// Returns the host and port along with ok=true for recognized forms.
func IsDevTCP(target string) (host, port string, kind string, ok bool) {
	for _, k := range []string{"/dev/tcp/", "/dev/udp/"} {
		if !strings.HasPrefix(target, k) {
			continue
		}
		rest := target[len(k):]
		slash := strings.LastIndexByte(rest, '/')
		if slash <= 0 || slash == len(rest)-1 {
			return "", "", "", false
		}
		return rest[:slash], rest[slash+1:], strings.TrimSuffix(strings.TrimPrefix(k, "/dev/"), "/"), true
	}
	return "", "", "", false
}
