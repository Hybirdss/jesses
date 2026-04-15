package policy

import (
	"path"
	"strings"
)

// Match returns true if the rule's pattern matches the given input under
// the rule's namespace-specific semantics.
func (r Rule) Match(input string) bool {
	return matchIn(r.Namespace, r.Pattern, input)
}

// matchIn dispatches to the per-namespace matcher.
func matchIn(ns Namespace, pattern, input string) bool {
	switch ns {
	case NSHost:
		return matchHost(pattern, input)
	case NSPath:
		return matchPath(pattern, input)
	case NSRepo:
		return matchRepo(pattern, input)
	case NSContract:
		return matchContract(pattern, input)
	case NSMCP:
		return matchMCP(pattern, input)
	}
	return false
}

// matchHost compares a host pattern to an input host, case-insensitively.
//
// Pattern semantics:
//
//	exact           "api.target.com"  matches "api.target.com" only
//	wildcard        "*.target.com"    matches "sub.target.com" and "a.b.target.com"
//	                                  but NOT "target.com" and NOT "evil-target.com"
//
// The wildcard form is anchored: the match must be a proper subdomain,
// meaning the input contains the base domain preceded by a literal '.'.
// This prevents the subdomain-confusion class where "*.target.com" would
// otherwise match "evil-target.com" via naive suffix matching.
func matchHost(pattern, input string) bool {
	pattern = strings.ToLower(pattern)
	input = strings.ToLower(input)

	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		if base == "" {
			return false
		}
		suffix := "." + base
		return strings.HasSuffix(input, suffix) && input != base
	}
	return pattern == input
}

// matchPath matches a filesystem path glob against an input path.
//
// Supported glob operators:
//
//   - matches any sequence of chars except '/'
//     **  matches any sequence of segments (spans directories)
//     ?   matches exactly one char except '/'
//     []  character class (via path.Match)
//
// "**" is implemented as a multi-segment wildcard by splitting both pattern
// and input on '/' and letting "**" consume zero or more segments via
// backtracking.
func matchPath(pattern, input string) bool {
	patSegs := strings.Split(pattern, "/")
	inputSegs := strings.Split(input, "/")
	return matchSegs(patSegs, inputSegs)
}

// matchSegs performs multi-segment glob matching with support for "**".
func matchSegs(pat, input []string) bool {
	for i := 0; i < len(pat); i++ {
		if pat[i] == "**" {
			rest := pat[i+1:]
			// "**" matches zero or more segments.
			for j := 0; j <= len(input); j++ {
				if matchSegs(rest, input[j:]) {
					return true
				}
			}
			return false
		}
		if len(input) == 0 {
			return false
		}
		ok, err := path.Match(pat[i], input[0])
		if err != nil || !ok {
			return false
		}
		input = input[1:]
	}
	return len(input) == 0
}

// matchRepo compares a repository identifier exactly (case-preserving).
// GitHub repositories are case-preserving but case-insensitive for
// resolution; v0.1 uses exact match and defers case-folding to v0.2.
func matchRepo(pattern, input string) bool {
	return pattern == input
}

// matchContract compares a "<chain>:0x<hex>" pattern to an input address,
// case-insensitively. EIP-55 checksum case is preserved in both pattern
// and input but not significant for matching.
func matchContract(pattern, input string) bool {
	return strings.EqualFold(pattern, input)
}

// matchMCP matches an MCP pattern against an MCP tool invocation.
//
//	pattern "mcp:context7"       matches "mcp:context7"
//	                             matches "mcp:context7:query"
//	pattern "mcp:context7:query" matches "mcp:context7:query" only
func matchMCP(pattern, input string) bool {
	if pattern == input {
		return true
	}
	return strings.HasPrefix(input, pattern+":")
}
