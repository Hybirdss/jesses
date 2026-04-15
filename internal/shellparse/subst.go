package shellparse

import "strings"

// scanSubstitutions walks everything that can hold a command or process
// substitution — the env assignments, the argv, and every redirect
// target — in source order and returns one Substitution per body found.
//
// The scan is source-string aware: it reconstructs the argv sequence
// joined by single spaces before scanning so that substitutions whose
// bodies contain shell word splits (e.g. `$(echo a b)`) are found as
// one body instead of three unbalanced fragments. Argv itself is not
// mutated — downstream consumers see the tokenizer's original split.
//
// Each substitution body is re-tokenized and re-split at Depth+1 with
// the matching Origin, producing a tree of Commands.
func scanSubstitutions(env, argv []string, redirs []Redirect, depth int) ([]Substitution, error) {
	var subs []Substitution

	// Env first, one token at a time — env assignments never span spaces.
	for _, e := range env {
		found, err := findSubstitutions(e, depth)
		if err != nil {
			return nil, err
		}
		subs = append(subs, found...)
	}

	// Argv: rejoin with single spaces so $(...) bodies containing
	// spaces survive intact. The substitution spans are identified by
	// their own delimiters regardless of shell word splitting.
	if len(argv) > 0 {
		joined := joinArgv(argv)
		found, err := findSubstitutions(joined, depth)
		if err != nil {
			return nil, err
		}
		subs = append(subs, found...)
	}

	// Redirect targets: each is one token.
	for _, r := range redirs {
		if r.Target == "" {
			continue
		}
		found, err := findSubstitutions(r.Target, depth)
		if err != nil {
			return nil, err
		}
		subs = append(subs, found...)
	}

	return subs, nil
}

// findSubstitutions scans a single string for $(...), `...`, <(...),
// and >(...) constructs, returning one Substitution per top-level
// opening. Nested substitutions inside a body are resolved by the
// recursive Split call, not at this layer — otherwise each nesting
// level would be reported twice.
func findSubstitutions(s string, depth int) ([]Substitution, error) {
	var subs []Substitution
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			// skip any escaped char to match the tokenizer's view
			i += 2
		case c == '\'':
			// single-quoted literal: skip to closing '
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, ErrUnbalancedSubst
			}
			i = i + 1 + j + 1
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			body, end, err := scanBalanced(s, i+2, '(', ')')
			if err != nil {
				return nil, err
			}
			parsed, err := reparseBody(body, depth+1, "subshell")
			if err != nil {
				return nil, err
			}
			subs = append(subs, Substitution{Kind: "cmd", RawBody: body, Parsed: parsed})
			i = end + 1
		case c == '`':
			body, end, err := scanBacktick(s, i+1)
			if err != nil {
				return nil, err
			}
			parsed, err := reparseBody(body, depth+1, "backtick")
			if err != nil {
				return nil, err
			}
			subs = append(subs, Substitution{Kind: "backtick", RawBody: body, Parsed: parsed})
			i = end + 1
		case (c == '<' || c == '>') && i+1 < len(s) && s[i+1] == '(':
			kind := "proc-in"
			if c == '>' {
				kind = "proc-out"
			}
			body, end, err := scanBalanced(s, i+2, '(', ')')
			if err != nil {
				return nil, err
			}
			parsed, err := reparseBody(body, depth+1, kind)
			if err != nil {
				return nil, err
			}
			subs = append(subs, Substitution{Kind: kind, RawBody: body, Parsed: parsed})
			i = end + 1
		default:
			i++
		}
	}
	return subs, nil
}

// scanBalanced reads from s starting at i (just past an opening delim)
// and returns the body plus the index of the matching close. Paren
// depth is tracked; single-quoted regions and double-quoted regions
// are skipped so that operators inside quotes do not affect depth.
func scanBalanced(s string, i int, open, close byte) (body string, end int, err error) {
	depth := 1
	start := i
	for i < len(s) {
		c := s[i]
		switch c {
		case '\\':
			if i+1 < len(s) {
				i += 2
				continue
			}
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", 0, ErrUnbalancedSubst
			}
			i = i + 1 + j + 1
			continue
		case '"':
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == '"' {
					break
				}
				j++
			}
			if j >= len(s) {
				return "", 0, ErrUnbalancedSubst
			}
			i = j + 1
			continue
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return s[start:i], i, nil
			}
		}
		i++
	}
	return "", 0, ErrUnbalancedSubst
}

// scanBacktick scans from i (just past a backtick) to the next
// unescaped backtick. Backslash inside backticks escapes the next
// character. Quotes do not shield backticks inside a backtick body.
func scanBacktick(s string, i int) (body string, end int, err error) {
	start := i
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if c == '`' {
			return s[start:i], i, nil
		}
		i++
	}
	return "", 0, ErrUnbalancedSubst
}

// reparseBody tokenizes a substitution body at depth+1 and splits it.
// MaxDepth is enforced here so that a body that would exceed the limit
// is rejected before the recursive Tokenize+splitAt work runs.
func reparseBody(body string, depth int, origin string) ([]Command, error) {
	if depth > MaxDepth {
		return nil, ErrMaxDepthExceeded
	}
	toks, err := Tokenize(body)
	if err != nil {
		return nil, err
	}
	return splitAt(toks, depth, origin)
}
