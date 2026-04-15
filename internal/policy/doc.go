// Package policy parses and evaluates jesses scope.txt files.
//
// A scope.txt file declares the action envelope an LLM agent is permitted
// to operate within during a session. It is a plain-text, line-oriented
// format designed to be grep-able, diff-able, and trivially version-controlled:
//
//	mode: advisory
//	in:  *.target.com
//	in:  path:/home/user/project/**
//	in:  arb:0x489ee077994B6658eAfA855C308275EAd8097C4A
//	in:  lidofinance/core
//	in:  mcp:context7
//	out: blog.target.com
//	out: path:**/secrets/**
//
// Five namespaces are recognized, distinguished by the shape of the rule
// value:
//
//	host       - bare hostname or *.suffix.tld       (Bash, WebFetch)
//	path:      - filesystem path glob                 (Read, Write, Edit, Glob, Grep)
//	mcp:       - MCP server/tool prefix               (mcp__* tool uses)
//	contract   - <chain>:0x<hex> address              (web3 tool invocations)
//	repo       - org/repo (no dot, no colon)          (Agent spawning, repository access)
//
// Rules are evaluated with exclusion-first precedence: every "out:" rule in
// the file is considered before any "in:" rule. An unmatched destination is
// "unpoliced"; in strict mode it is blocked, in advisory mode (default) it
// is warned and allowed.
//
// This package has zero external dependencies. Stdlib only.
package policy
