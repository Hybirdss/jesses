package bash

import (
	"strings"
)

// parseURL decomposes a string that might be a URL (scheme://host:port/path),
// a host-only form (host or host:port), or an SSH-style scp target
// (user@host:path). It never reports an error — unrecognizable input
// returns kind="unknown" and host set to the original raw string.
//
// Recognized schemes produce the canonical Kind tag:
//
//	http   → "http"
//	https  → "https"
//	git    → "git"
//	ssh    → "ssh"
//	rsync  → "rsync"
//	ftp    → "ftp"
//	tcp    → "tcp"
//	udp    → "udp"
//
// Schemeless forms (host:port, host/path) are returned as Kind="host"
// so the caller's per-tool parser can impose the protocol
// (e.g. httpx → "https", dig → "dns").
func parseURL(raw string) (kind, host, port, path string) {
	s := raw
	// Strip a leading user@ for scp-style destinations; capture host
	// up to the first ':' or end.
	if scheme, rest, ok := splitScheme(s); ok {
		kind = normalizeScheme(scheme)
		s = rest
	} else {
		kind = "host"
	}
	// Handle user@host
	if at := strings.IndexByte(s, '@'); at >= 0 {
		// For ssh/rsync/ftp/scp, user@host[:port][:path] is allowed.
		// We drop the user and keep the host portion.
		s = s[at+1:]
	}
	// Path
	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		path = s[slash:]
		s = s[:slash]
	}
	// IPv6 bracket form: [::1]:8080
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end > 0 {
			host = s[1:end]
			rest := s[end+1:]
			if strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return kind, host, port, path
		}
	}
	// host[:port]
	if colon := strings.LastIndexByte(s, ':'); colon >= 0 {
		// scp-style "host:path" means the colon is NOT port. For
		// unknown kind and no digits after the colon, treat it as
		// path.
		tail := s[colon+1:]
		if looksLikePort(tail) {
			host = s[:colon]
			port = tail
			return kind, host, port, path
		}
		// scp-style colon: rest becomes path
		host = s[:colon]
		if tail != "" {
			if path == "" {
				path = "/" + tail
			} else {
				path = "/" + tail + path
			}
		}
		return kind, host, port, path
	}
	host = s
	return kind, host, port, path
}

// splitScheme extracts a leading "scheme://" from s. Returns the
// scheme, remainder, and ok. When s has no recognized scheme prefix
// the function returns ("", s, false).
func splitScheme(s string) (scheme, rest string, ok bool) {
	// Scheme chars: [a-zA-Z][a-zA-Z0-9+.-]*
	if len(s) == 0 {
		return "", s, false
	}
	c := s[0]
	if !isAlpha(c) {
		return "", s, false
	}
	i := 1
	for i < len(s) {
		c := s[i]
		if isAlphaNum(c) || c == '+' || c == '-' || c == '.' {
			i++
			continue
		}
		break
	}
	if i+2 >= len(s) || s[i] != ':' || s[i+1] != '/' || s[i+2] != '/' {
		return "", s, false
	}
	return s[:i], s[i+3:], true
}

// normalizeScheme maps known URL schemes to canonical Kind tags.
// Unknown schemes pass through lowercased.
func normalizeScheme(scheme string) string {
	s := strings.ToLower(scheme)
	switch s {
	case "http", "https", "ssh", "git", "rsync", "ftp", "sftp", "tcp", "udp", "ws", "wss":
		return s
	}
	return s
}

// looksLikePort reports whether s is entirely ASCII digits in the
// port range. Non-digit suffixes (a hostname, path, or service name)
// make this false.
func looksLikePort(s string) bool {
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n <= 65535
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlphaNum(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9')
}

// looksLikeHost reports whether s plausibly is a hostname or IP.
// Used as a final-resort filter before emitting a Destination, so a
// URL fragment like "?foo=bar" is not mistaken for a host.
func looksLikeHost(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n?#") {
		return false
	}
	// IPv4 shape: digits and dots only
	if ipv4OnlyDigits(s) {
		return true
	}
	// IPv6 bracket form
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return true
	}
	// DNS label: letters, digits, dots, hyphens; must have at least
	// one letter so "12345" is not accepted as a host.
	hasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) {
			hasLetter = true
			continue
		}
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == ':' {
			continue
		}
		return false
	}
	return hasLetter
}

func ipv4OnlyDigits(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
