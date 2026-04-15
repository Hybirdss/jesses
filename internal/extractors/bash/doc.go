// Package bash extracts network destinations from shell commands
// structured by the internal/shellparse package.
//
// The input is one or more shellparse.Command values, each carrying
// the effective argv, env assignments, wrappers, redirects, and
// recursive substitution / re-entry trees. The output is a flat slice
// of Destination records — one per host/port/path pair the command
// could contact, with a Source field naming exactly where in the
// argv or env each destination came from.
//
// Per-tool parsers live in curl.go (the workhorse), dns.go
// (dig / host / nslookup), ssh.go (ssh / scp / sftp / rsync), net.go
// (nc / ncat), git.go, and a URL-argument generic parser in
// generic.go that covers wget, httpx, nuclei, and any other tool
// whose destination is just a URL positional arg.
//
// Proxy extraction is first-class: HTTPS_PROXY / HTTP_PROXY /
// ALL_PROXY / NO_PROXY from both the Command.Env list and from `env`
// wrapper assignments produce Destination records of kind "proxy".
// Policy layers frequently want to allowlist proxies separately from
// primary request destinations.
//
// /dev/tcp/HOST/PORT and /dev/udp/HOST/PORT redirection targets and
// argv tokens are recognized as raw-socket destinations of kind
// "tcp" or "udp".
//
// Everything is best-effort: when a parser cannot determine the
// destination (tool-specific flag not yet modeled, unusual syntax,
// dynamic URL from substitution output), the extractor emits a
// Destination with Kind="unknown" and Raw set to the argv fragment
// so policy can still make a conservative decision.
//
// Zero external dependencies. Stdlib only.
package bash
