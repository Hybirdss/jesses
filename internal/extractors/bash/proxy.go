package bash

import "strings"

// proxyEnvVars is the set of environment variables whose values are
// proxy URLs. Both uppercase and lowercase forms are checked because
// some tools honor only one spelling.
var proxyEnvVars = map[string]bool{
	"HTTPS_PROXY": true, "HTTP_PROXY": true, "ALL_PROXY": true,
	"FTP_PROXY": true, "SOCKS_PROXY": true,
	"https_proxy": true, "http_proxy": true, "all_proxy": true,
	"ftp_proxy": true, "socks_proxy": true,
}

// appendProxyFromEnv scans a flat list of NAME=VALUE assignments and
// emits one Destination of kind "proxy" for each proxy-related
// variable found. origin names the source context ("env" for plain
// Command.Env, the wrapper string for env-wrapper assignments).
func appendProxyFromEnv(env []string, origin string, depth int, dsts []Destination) []Destination {
	for i, e := range env {
		name, val, ok := splitAssignment(e)
		if !ok {
			continue
		}
		if !proxyEnvVars[name] {
			continue
		}
		kind, host, port, path := parseURL(val)
		if kind == "host" {
			kind = "proxy"
		}
		d := Destination{
			Kind:   "proxy",
			Host:   host,
			Port:   port,
			Path:   path,
			Raw:    val,
			Source: origin + "[" + itoa(i) + ":" + name + "]",
			Depth:  depth,
		}
		// If the URL carries its own scheme, preserve it in Kind as a
		// suffix so policy can distinguish proxy over http vs https
		// vs socks. Example: kind="proxy:https".
		if kind != "proxy" && kind != "host" {
			d.Kind = "proxy:" + kind
		}
		dsts = append(dsts, d)
	}
	return dsts
}

// appendProxyFromEnvWrapper is called with a wrapper string like
// "env HTTPS_PROXY=http://a.com:8080 FOO=bar". It splits the wrapper
// into its argv tokens and forwards the assignment-shaped tokens to
// appendProxyFromEnv. The wrapper string "sudo" or "timeout 30" is
// a no-op.
func appendProxyFromEnvWrapper(wrapper string, depth int, dsts []Destination) []Destination {
	parts := strings.Fields(wrapper)
	if len(parts) == 0 || parts[0] != "env" {
		return dsts
	}
	var assigns []string
	for _, p := range parts[1:] {
		if _, _, ok := splitAssignment(p); ok {
			assigns = append(assigns, p)
		}
	}
	return appendProxyFromEnv(assigns, "wrapper[env]", depth, dsts)
}

// splitAssignment breaks "NAME=VALUE" into name and value. Returns
// ok=false for tokens that do not match the shell identifier form on
// the left-hand side.
func splitAssignment(s string) (name, value string, ok bool) {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return "", "", false
	}
	// Validate identifier on the LHS.
	for i := 0; i < eq; i++ {
		c := s[i]
		if i == 0 {
			if !(c == '_' || isAlpha(c)) {
				return "", "", false
			}
			continue
		}
		if !(c == '_' || isAlpha(c) || (c >= '0' && c <= '9')) {
			return "", "", false
		}
	}
	return s[:eq], s[eq+1:], true
}
