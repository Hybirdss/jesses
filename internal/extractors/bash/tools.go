package bash

import (
	"strings"

	"github.com/Hybirdss/jesses/internal/shellparse"
)

// parserFn is the per-tool destination-extraction function signature.
type parserFn func(cmd shellparse.Command, dsts []Destination) []Destination

// toolParsers is the dispatch table keyed by argv[0]'s basename.
// Entries cover the highest-value tools for detecting agent-generated
// network activity. Tools not listed fall through to a conservative
// no-op — the extract.go layer still surfaces /dev/tcp, substitution
// bodies, and proxy env assignments regardless of which tool wraps
// them.
var toolParsers = map[string]parserFn{
	// HTTP clients
	"curl":  parseCurl,
	"wget":  parseWget,
	"wget2": parseWget,
	"httpx": parseGenericURL,
	"http":  parseGenericURL, // HTTPie
	"https": parseGenericURL,

	// Security tooling (URL-as-arg generic)
	"nuclei":      parseGenericURL,
	"subfinder":   parseGenericURL,
	"amass":       parseGenericURL,
	"waybackurls": parseGenericURL,
	"gau":         parseGenericURL,
	"katana":      parseGenericURL,
	"sqlmap":      parseSQLMap,
	"ffuf":        parseFFUF,
	"gobuster":    parseGobuster,

	// DNS
	"dig":      parseDig,
	"host":     parseDig,
	"nslookup": parseDig,
	"drill":    parseDig,
	"delv":     parseDig,

	// Raw socket
	"nc":   parseNetcat,
	"ncat": parseNetcat,

	// Network scan
	"nmap":    parseNmap,
	"masscan": parseNmap,

	// SSH family
	"ssh":   parseSSH,
	"scp":   parseSCP,
	"sftp":  parseSCP,
	"rsync": parseRsync,

	// Source control
	"git": parseGit,

	// Package managers (URLs commonly inside args)
	"npm":   parsePackageManager,
	"pnpm":  parsePackageManager,
	"yarn":  parsePackageManager,
	"pip":   parsePackageManager,
	"pip3":  parsePackageManager,
	"cargo": parsePackageManager,
	"go":    parsePackageManager,

	// Web3 tooling
	"cast": parseGenericURL,
}

// parseGenericURL is the fallback parser for tools whose destinations
// are simply URL-shaped positional arguments. It iterates argv past
// flags and emits one Destination per argument that looks like a
// URL or hostname.
func parseGenericURL(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if len(a) == 0 {
			continue
		}
		// Flag: skip. If the flag is known to consume a value, skip
		// its value too.
		if a[0] == '-' {
			if genericValueFlag[a] {
				i++
			}
			continue
		}
		dsts = emitURLOrHost(a, fmtIndexedSource("argv", i), cmd.Depth, dsts)
	}
	return dsts
}

// genericValueFlag is the minimal set of flags across popular tools
// whose value is the next argv. Kept narrow on purpose — the cost of
// skipping a destination (false negative) is lower than the cost of
// emitting a header or cert path as a destination (false positive).
var genericValueFlag = map[string]bool{
	"-H": true, "--header": true, "-o": true, "--output": true,
	"-u": true, "--user": true, "-t": true, "--target": true,
	"-l": true, "-w": true, "--wordlist": true,
	"-i": true, "--input": true, "--config": true,
	"-a": true, "--agent": true, "--user-agent": true,
	"-p": true, "--port": true,
}

func emitURLOrHost(raw, source string, depth int, dsts []Destination) []Destination {
	kind, host, port, path := parseURL(raw)
	if host == "" || !looksLikeHost(host) {
		return dsts
	}
	if kind == "host" || kind == "" {
		// Heuristic: if path begins with / or is empty, treat as http.
		kind = "http"
	}
	return append(dsts, Destination{
		Kind:   kind,
		Host:   host,
		Port:   port,
		Path:   path,
		Raw:    raw,
		Source: source,
		Depth:  depth,
	})
}

// parseWget handles wget's flag grammar. Destinations are one or more
// URL positionals at the tail; value-consuming flags are modelled so
// their values are not mistaken for URLs.
func parseWget(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	i := 1
	for i < len(argv) {
		a := argv[i]
		if a == "-e" || a == "--execute" || a == "-o" || a == "-O" ||
			a == "--output-document" || a == "--output-file" ||
			a == "-a" || a == "--append-output" ||
			a == "-i" || a == "--input-file" ||
			a == "-U" || a == "--user-agent" ||
			a == "--header" ||
			a == "--referer" ||
			a == "--limit-rate" || a == "--timeout" ||
			a == "-t" || a == "--tries" {
			i += 2
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			i++
			continue
		}
		dsts = emitHTTPURL(a, fmtIndexedSource("argv", i), cmd.Depth, dsts)
		i++
	}
	return dsts
}

// parseDig handles dig/host/nslookup/drill. Destinations are DNS
// queries: the name to resolve becomes Kind="dns", and any `@server`
// argument becomes Kind="dns-server".
func parseDig(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if len(a) == 0 {
			continue
		}
		// @server
		if a[0] == '@' && len(a) > 1 {
			dsts = append(dsts, Destination{
				Kind: "dns-server", Host: a[1:], Raw: a,
				Source: fmtIndexedSource("argv", i), Depth: cmd.Depth,
			})
			continue
		}
		// Flags or dig plus-options (+short, +trace, ...)
		if a[0] == '-' || a[0] == '+' {
			continue
		}
		// Query type (A, AAAA, MX, TXT, ...) — short uppercase word
		if isDigQueryType(a) {
			continue
		}
		if !looksLikeHost(a) {
			continue
		}
		dsts = append(dsts, Destination{
			Kind: "dns", Host: a, Raw: a,
			Source: fmtIndexedSource("argv", i), Depth: cmd.Depth,
		})
	}
	return dsts
}

func isDigQueryType(s string) bool {
	switch s {
	case "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "ANY",
		"CAA", "DNSKEY", "DS", "RRSIG", "SRV", "SSHFP", "TLSA", "HTTPS",
		"SVCB", "NAPTR", "HINFO", "LOC", "SPF":
		return true
	}
	return false
}

// parseNetcat handles `nc` / `ncat`. Canonical forms:
//
//	nc HOST PORT
//	nc -l -p PORT          (listen, no remote destination)
//	nc -z HOST PORT1-PORT2 (port scan)
//
// The last two positional args are treated as host+port.
func parseNetcat(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	// Collect positionals, skipping flags. nc's flags mostly don't
	// consume values except -s SOURCE, -p PORT, -e CMD, -w SEC.
	valueFlags := map[string]bool{
		"-s": true, "-p": true, "-e": true, "-w": true, "-i": true,
		"-I": true, "-O": true, "-q": true, "-T": true, "-X": true,
		"-x": true,
	}
	var positionals []int
	isListen := false
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-l" {
			isListen = true
			continue
		}
		if valueFlags[a] {
			i++
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		positionals = append(positionals, i)
	}
	if isListen || len(positionals) < 2 {
		return dsts
	}
	// Last two positionals are HOST PORT.
	hi := positionals[len(positionals)-2]
	pi := positionals[len(positionals)-1]
	host := argv[hi]
	port := argv[pi]
	if !looksLikeHost(host) {
		return dsts
	}
	kind := "tcp"
	for i := 1; i < len(argv); i++ {
		if argv[i] == "-u" {
			kind = "udp"
			break
		}
	}
	return append(dsts, Destination{
		Kind: kind, Host: host, Port: port, Raw: host + ":" + port,
		Source: fmtIndexedSource("argv", hi), Depth: cmd.Depth,
	})
}

// parseNmap extracts scan targets. Nmap target syntax is rich
// (CIDR, ranges, lists) — we emit the raw token as Host and let the
// policy layer expand if needed.
func parseNmap(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	valueFlags := map[string]bool{
		"-p": true, "-iL": true, "-oN": true, "-oX": true, "-oS": true,
		"-oG": true, "-oA": true, "--script": true, "--script-args": true,
		"-e": true, "--source-port": true, "-g": true, "-S": true,
		"--proxies": true, "--data": true, "--data-string": true,
		"--data-length": true, "--max-retries": true, "--host-timeout": true,
		"-T": true, "--min-rate": true, "--max-rate": true,
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if valueFlags[a] {
			if a == "--proxies" && i+1 < len(argv) {
				dsts = emitProxy(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
			}
			i++
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		if !looksLikeHost(a) && !strings.ContainsAny(a, "/,-") {
			continue
		}
		dsts = append(dsts, Destination{
			Kind: "scan-target", Host: a, Raw: a,
			Source: fmtIndexedSource("argv", i), Depth: cmd.Depth,
		})
	}
	return dsts
}

// parseSSH extracts the ssh destination, including user@host[:port]
// and `-p PORT` / `-l USER` / `-J JUMPHOST` / `-o ProxyCommand=`.
func parseSSH(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	port := ""
	var jumps []string
	valueFlags := map[string]bool{
		"-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
		"-F": true, "-I": true, "-i": true, "-J": true, "-L": true,
		"-l": true, "-m": true, "-O": true, "-o": true, "-p": true,
		"-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-p" && i+1 < len(argv) {
			port = argv[i+1]
			i++
			continue
		}
		if a == "-J" && i+1 < len(argv) {
			jumps = append(jumps, argv[i+1])
			i++
			continue
		}
		if a == "-o" && i+1 < len(argv) {
			if strings.HasPrefix(argv[i+1], "ProxyCommand=") {
				val := strings.TrimPrefix(argv[i+1], "ProxyCommand=")
				dsts = append(dsts, Destination{
					Kind: "ssh-proxy-command", Raw: val,
					Source: fmtIndexedSource("argv", i+1), Depth: cmd.Depth,
				})
			}
			i++
			continue
		}
		if valueFlags[a] {
			i++
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		// First non-flag positional is the destination.
		_, host, _, _ := parseURL(a)
		if host == "" || !looksLikeHost(host) {
			continue
		}
		d := Destination{
			Kind: "ssh", Host: host, Port: port, Raw: a,
			Source: fmtIndexedSource("argv", i), Depth: cmd.Depth,
		}
		dsts = append(dsts, d)
		// Record jump hosts
		for j, jh := range jumps {
			_, jhost, jport, _ := parseURL(jh)
			dsts = append(dsts, Destination{
				Kind: "ssh-jump", Host: jhost, Port: jport, Raw: jh,
				Source: fmtIndexedSource("argv", i) + ".jump[" + itoa(j) + "]",
				Depth:  cmd.Depth,
			})
		}
		// Remaining argv is the remote command; stop.
		break
	}
	return dsts
}

// parseSCP handles scp and sftp targets in USER@HOST:PATH form.
func parseSCP(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-P" && i+1 < len(argv) {
			i++
			continue
		}
		if a == "-i" || a == "-o" || a == "-F" || a == "-c" ||
			a == "-l" || a == "-s" || a == "-S" {
			if i+1 < len(argv) {
				i++
			}
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		if !strings.ContainsRune(a, ':') && !strings.HasPrefix(a, "scp://") &&
			!strings.HasPrefix(a, "sftp://") {
			continue
		}
		kind, host, port, path := parseURL(a)
		if kind == "host" || kind == "" {
			kind = "ssh"
		}
		if host == "" {
			continue
		}
		dsts = append(dsts, Destination{
			Kind: kind, Host: host, Port: port, Path: path, Raw: a,
			Source: fmtIndexedSource("argv", i), Depth: cmd.Depth,
		})
	}
	return dsts
}

// parseRsync recognizes rsync destinations, including SSH-tunneled
// (user@host:path) and rsync:// URLs.
func parseRsync(cmd shellparse.Command, dsts []Destination) []Destination {
	return parseSCP(cmd, dsts)
}

// parseGit handles the destination URLs in common git subcommands:
//
//	git clone URL ...
//	git fetch REMOTE
//	git push REMOTE REF
//	git remote add NAME URL
//
// For fetch/push with a remote name (not URL), no destination is
// emitted — resolving a remote name requires the repo's config,
// which is out of scope for a static parser.
func parseGit(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	if len(argv) < 2 {
		return dsts
	}
	// Walk past global flags to the subcommand.
	subIdx := 1
	for subIdx < len(argv) && strings.HasPrefix(argv[subIdx], "-") {
		subIdx++
	}
	if subIdx >= len(argv) {
		return dsts
	}
	sub := argv[subIdx]
	switch sub {
	case "clone":
		for i := subIdx + 1; i < len(argv); i++ {
			a := argv[i]
			if strings.HasPrefix(a, "-") {
				continue
			}
			if isGitURL(a) {
				dsts = emitGitURL(a, fmtIndexedSource("argv", i), cmd.Depth, dsts)
				return dsts
			}
		}
	case "fetch", "push", "pull":
		for i := subIdx + 1; i < len(argv); i++ {
			a := argv[i]
			if strings.HasPrefix(a, "-") {
				continue
			}
			if isGitURL(a) {
				dsts = emitGitURL(a, fmtIndexedSource("argv", i), cmd.Depth, dsts)
				return dsts
			}
		}
	case "remote":
		// git remote add NAME URL
		for i := subIdx + 1; i+1 < len(argv); i++ {
			if argv[i] == "add" && i+2 < len(argv) {
				url := argv[i+2]
				if isGitURL(url) {
					dsts = emitGitURL(url, fmtIndexedSource("argv", i+2), cmd.Depth, dsts)
				}
				return dsts
			}
		}
	}
	return dsts
}

// isGitURL heuristically identifies a string as a git URL. Covers
// https://, git://, ssh://, scp-style user@host:path, and
// file:// paths.
func isGitURL(s string) bool {
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git://") || strings.HasPrefix(s, "ssh://") ||
		strings.HasPrefix(s, "file://") {
		return true
	}
	if strings.Contains(s, "@") && strings.Contains(s, ":") {
		return true
	}
	return false
}

func emitGitURL(raw, source string, depth int, dsts []Destination) []Destination {
	kind, host, port, path := parseURL(raw)
	if kind == "host" || kind == "" {
		kind = "git"
	}
	if host == "" {
		return dsts
	}
	return append(dsts, Destination{
		Kind:   kind,
		Host:   host,
		Port:   port,
		Path:   path,
		Raw:    raw,
		Source: source,
		Depth:  depth,
	})
}

// parseSQLMap covers sqlmap's -u URL flag form.
func parseSQLMap(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if (a == "-u" || a == "--url") && i+1 < len(argv) {
			dsts = emitHTTPURL(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
			i++
			continue
		}
		if strings.HasPrefix(a, "-u=") || strings.HasPrefix(a, "--url=") {
			val := a[strings.IndexByte(a, '=')+1:]
			dsts = emitHTTPURL(val, fmtIndexedSource("argv", i), cmd.Depth, dsts)
			continue
		}
	}
	return dsts
}

// parseFFUF handles ffuf -u URL.
func parseFFUF(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-u" && i+1 < len(argv) {
			dsts = emitHTTPURL(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
			i++
			continue
		}
	}
	return dsts
}

// parseGobuster covers `gobuster MODE -u URL`.
func parseGobuster(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-u" && i+1 < len(argv) {
			dsts = emitHTTPURL(argv[i+1], fmtIndexedSource("argv", i+1), cmd.Depth, dsts)
			i++
			continue
		}
	}
	return dsts
}

// parsePackageManager scans npm/pip/cargo/go commands for URL-shaped
// args. These tools often fetch packages from registries; the URL
// form is less common but appears for direct tarball or VCS installs
// ("npm install https://...", "go install pkg@VERSION" (not a URL),
// "pip install git+https://...").
func parsePackageManager(cmd shellparse.Command, dsts []Destination) []Destination {
	argv := cmd.Argv
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "https://") || strings.HasPrefix(a, "http://") ||
			strings.HasPrefix(a, "git+") {
			v := strings.TrimPrefix(a, "git+")
			dsts = emitHTTPURL(v, fmtIndexedSource("argv", i), cmd.Depth, dsts)
		}
	}
	return dsts
}
