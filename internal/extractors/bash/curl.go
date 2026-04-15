package bash

import (
	"strings"

	"github.com/Hybirdss/jesses/internal/shellparse"
)

// parseCurl extracts destinations from a `curl` invocation.
//
// Destinations recognized:
//   - URL positional arguments (one or more — curl accepts a list)
//   - `-x` / `--proxy` / `--preproxy` — proxy override (Kind="proxy")
//   - `--connect-to HOST:PORT:CONNECT_HOST:CONNECT_PORT` — override
//     where the request actually connects
//   - `--resolve HOST:PORT:IP` — overrides DNS for HOST:PORT to IP;
//     emitted as Kind="resolve-override"
//   - `-K` / `--config` FILE — config file is itself a path; not
//     emitted as a network destination but acknowledged
//
// Flags that consume a value (--data, -H, -F, --cacert, ...) are
// tracked by a small whitelist so their values are not mistaken for
// the URL argument.
func parseCurl(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	i := 1
	for i < len(argv) {
		a := argv[i]
		// Proxy overrides
		if a == "-x" || a == "--proxy" || a == "--preproxy" {
			if i+1 < len(argv) {
				dsts = emitProxy(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
				i += 2
				continue
			}
		}
		if strings.HasPrefix(a, "--proxy=") {
			val := strings.TrimPrefix(a, "--proxy=")
			dsts = emitProxy(val, fmtIndexedSource("argv", i), cmd.Depth, dsts)
			i++
			continue
		}
		if strings.HasPrefix(a, "-x") && len(a) > 2 {
			val := a[2:]
			dsts = emitProxy(val, fmtIndexedSource("argv", i), cmd.Depth, dsts)
			i++
			continue
		}
		// DNS override
		if a == "--resolve" {
			if i+1 < len(argv) {
				dsts = emitResolveOverride(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
				i += 2
				continue
			}
		}
		// Connect-to override
		if a == "--connect-to" {
			if i+1 < len(argv) {
				dsts = emitConnectTo(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
				i += 2
				continue
			}
		}
		// Value-consuming flags whose values must be skipped
		if curlValueConsuming[a] {
			i += 2
			continue
		}
		// Merged short flags with a value, like "-Hfoo" for -H foo
		if len(a) > 2 && a[0] == '-' && a[1] != '-' {
			if curlShortValueConsuming[a[:2]] {
				i++
				continue
			}
		}
		// Any other flag (no value)
		if len(a) > 0 && a[0] == '-' {
			i++
			continue
		}
		// Positional — assume URL.
		dsts = emitHTTPURL(a, fmtIndexedSource("argv", i), cmd.Depth, dsts)
		i++
	}
	return dsts
}

// curlValueConsuming is the set of curl long options whose value is
// the very next argv token. This list is not exhaustive — we include
// the ones common enough that their values are frequently mistaken
// for a URL by a naive parser.
var curlValueConsuming = map[string]bool{
	"-H": true, "--header": true,
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true,
	"--data-urlencode": true, "--data-ascii": true,
	"-F": true, "--form": true, "--form-string": true,
	"-o": true, "--output": true,
	"-A": true, "--user-agent": true,
	"-e": true, "--referer": true,
	"-u": true, "--user": true,
	"-b": true, "--cookie": true,
	"-c": true, "--cookie-jar": true,
	"-K": true, "--config": true,
	"-X": true, "--request": true,
	"-T": true, "--upload-file": true,
	"-Y": true, "--speed-limit": true,
	"-y": true, "--speed-time": true,
	"--cacert": true, "--capath": true,
	"--cert": true, "--key": true,
	"--cert-type": true, "--key-type": true, "--pass": true,
	"--interface": true, "--dns-servers": true,
	"--max-time": true, "--connect-timeout": true,
	"--retry": true, "--retry-delay": true, "--retry-max-time": true,
	"--local-port": true, "--ciphers": true,
	"--range": true, "-r": true,
	"--limit-rate": true,
}

// curlShortValueConsuming is the set of curl short flags where a
// glued value (like "-Ofoo" or "-Hheader") is still one argv.
var curlShortValueConsuming = map[string]bool{
	"-H": true, "-d": true, "-F": true, "-o": true, "-A": true,
	"-e": true, "-u": true, "-b": true, "-c": true, "-K": true,
	"-X": true, "-T": true, "-Y": true, "-y": true, "-r": true,
}

// emitHTTPURL classifies a curl positional arg as an http(s) URL or
// a bare host (curl accepts "example.com" and assumes http://).
func emitHTTPURL(raw, source string, depth int, dsts []Destination) []Destination {
	kind, host, port, path := parseURL(raw)
	if kind == "host" || kind == "" {
		kind = "http"
	}
	if host == "" || !looksLikeHost(host) {
		dsts = append(dsts, Destination{
			Kind:   "unknown",
			Raw:    raw,
			Source: source,
			Depth:  depth,
		})
		return dsts
	}
	dsts = append(dsts, Destination{
		Kind:   kind,
		Host:   host,
		Port:   port,
		Path:   path,
		Raw:    raw,
		Source: source,
		Depth:  depth,
	})
	return dsts
}

// emitProxy classifies a proxy override value.
func emitProxy(raw, source string, depth int, dsts []Destination) []Destination {
	kind, host, port, path := parseURL(raw)
	d := Destination{
		Kind:   "proxy",
		Host:   host,
		Port:   port,
		Path:   path,
		Raw:    raw,
		Source: source,
		Depth:  depth,
	}
	if kind != "host" && kind != "" {
		d.Kind = "proxy:" + kind
	}
	return append(dsts, d)
}

// emitResolveOverride parses curl's --resolve HOST:PORT:IP and emits
// a Destination of Kind="resolve-override". Policy can treat this as
// an instruction that the client will skip DNS for HOST:PORT and
// connect directly to IP — frequently used to pin a host at a
// specific IP.
func emitResolveOverride(raw, source string, depth int, dsts []Destination) []Destination {
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return append(dsts, Destination{Kind: "unknown", Raw: raw, Source: source, Depth: depth})
	}
	return append(dsts, Destination{
		Kind:   "resolve-override",
		Host:   parts[0],
		Port:   parts[1],
		Raw:    raw,
		Source: source,
		Depth:  depth,
	}, Destination{
		Kind:   "resolved-ip",
		Host:   parts[2],
		Raw:    raw,
		Source: source,
		Depth:  depth,
	})
}

// emitConnectTo parses curl's --connect-to HOST:PORT:CONNECT_HOST:CONNECT_PORT
// and emits both the logical and physical destinations.
func emitConnectTo(raw, source string, depth int, dsts []Destination) []Destination {
	parts := strings.SplitN(raw, ":", 4)
	if len(parts) != 4 {
		return append(dsts, Destination{Kind: "unknown", Raw: raw, Source: source, Depth: depth})
	}
	return append(dsts,
		Destination{
			Kind: "connect-to-logical", Host: parts[0], Port: parts[1],
			Raw: raw, Source: source, Depth: depth,
		},
		Destination{
			Kind: "connect-to-physical", Host: parts[2], Port: parts[3],
			Raw: raw, Source: source, Depth: depth,
		},
	)
}
