package shellparse

import "errors"

// Command is the structured form of a single shell command within a
// segment. A segment is a run of WORD tokens terminated by one of the
// six command separators (; | || & && newline) or end-of-input.
//
// Argv is the effective argv — the command that execve would see after
// the shell has (a) pulled out leading VAR=value env assignments and
// (b) peeled off wrapper commands from the wrapperTable. This is what
// a destination extractor walks to pull URLs, hostnames, file paths,
// and /dev/tcp targets.
//
// Original preserves the pre-unwrap argv in source token order. It
// exists so an audit reader can reproduce what the operator actually
// typed, even when unwrap collapses five tokens into one.
//
// Env holds the leading "NAME=VALUE" assignments in source order.
// Wrappers holds each stripped wrapper command together with its own
// flags joined by spaces (e.g. "timeout -k 5 30") so that three tokens
// stripped as one wrapper stay one entry here.
//
// Redirects holds every redirection encountered in the segment, in
// source order. Both spaced ("cat < file") and unspaced ("2>&1") forms
// are normalized to the same Redirect shape.
//
// Subst holds every command or process substitution found anywhere in
// Env, Argv, or redirect targets, in source order. Each Substitution's
// Parsed field is the recursive Split of the body at Depth+1.
//
// Reentry is populated when Argv[0] is one of the shell-with-payload
// programs (bash / sh / dash / zsh / ksh with -c, or eval). The payload
// string is re-tokenized and re-split at Depth+1 and stored here.
//
// Depth is zero for a top-level command; every layer of subshell,
// process substitution, backtick, -c payload, or eval payload adds 1.
// Split refuses to recurse beyond MaxDepth.
//
// Terminator is the operator token that closed this segment. It is
// TokNewline for the final segment when input did not end in an
// explicit separator.
//
// Origin tags how this Command came to be:
//
//	"top"       - top-level command in the input
//	"subshell"  - body of $(...)
//	"backtick"  - body of `...`
//	"proc-in"   - body of <(...)
//	"proc-out"  - body of >(...)
//	"bash-c"    - payload of any shell -c invocation
//	"eval"      - payload of eval
type Command struct {
	Argv       []string       `json:"argv"`
	Original   []string       `json:"original,omitempty"`
	Env        []string       `json:"env,omitempty"`
	Wrappers   []string       `json:"wrappers,omitempty"`
	Terminator TokenType      `json:"terminator"`
	Redirects  []Redirect     `json:"redirects,omitempty"`
	Subst      []Substitution `json:"subst,omitempty"`
	Reentry    []Command      `json:"reentry,omitempty"`
	Depth      int            `json:"depth"`
	Origin     string         `json:"origin"`
}

// Redirect describes one redirection operator applied to a command.
//
// Op is the operator text: "<", ">", ">>", "<<", "<<<",
// ">&", "<&", "&>", "&>>".
// FD is the file descriptor being redirected: 0 for reads, 1 for
// writes, or the explicit leading digit when one is present ("2>" → 2).
// Target is the destination or source word. For "<<" (heredoc) Target
// is the delimiter token; the heredoc body itself is not consumed at
// this layer because the tokenizer does not recognize heredocs.
type Redirect struct {
	Op     string `json:"op"`
	FD     int    `json:"fd"`
	Target string `json:"target,omitempty"`
}

// Substitution is a command substitution or process substitution found
// inside a Command's Env, Argv, or redirect targets.
//
//	Kind      meaning                  source form
//	--------  -----------------------  -------------
//	cmd       command substitution     $(...)
//	backtick  legacy command subst     `...`
//	proc-in   process substitution     <(...)
//	proc-out  process substitution     >(...)
//
// RawBody is the original body text between the opening delimiter and
// the matching close, preserved verbatim. Parsed is the recursive
// Split of the body at Depth+1 with Origin set to Kind.
type Substitution struct {
	Kind    string    `json:"kind"`
	RawBody string    `json:"raw_body"`
	Parsed  []Command `json:"parsed"`
}

// Sentinel errors returned by Split and its helpers.
var (
	// ErrMaxDepthExceeded fires when recursion (subshell / process
	// substitution / backtick / bash-c / eval) exceeds MaxDepth.
	ErrMaxDepthExceeded = errors.New("shellparse: maximum nesting depth exceeded")

	// ErrUnbalancedSubst fires when a $( / ` / <( / >( is opened but
	// never closed, or when a quoted segment inside a substitution is
	// unterminated.
	ErrUnbalancedSubst = errors.New("shellparse: unbalanced substitution")
)

// MaxDepth caps recursion across all nesting constructs. Legitimate
// scripts almost never exceed depth 3. Payloads that exceed 8 are
// either adversarial or broken and are rejected rather than parsed.
const MaxDepth = 8

// SplitString is a convenience wrapper: Tokenize then Split.
func SplitString(input string) ([]Command, error) {
	toks, err := Tokenize(input)
	if err != nil {
		return nil, err
	}
	return Split(toks)
}

// Split consumes a flat token stream and produces structured Commands.
// Errors are returned when a substitution is unbalanced or recursion
// exceeds MaxDepth; well-formed input never produces an error.
//
// Before segment walking, Split runs a pre-pass that fuses tokens
// belonging to a single unclosed substitution — $(...), <(...), >(...),
// `...` bodies frequently contain whitespace and separators that the
// tokenizer splits into multiple tokens. The pre-pass merges them back
// into one WORD so the segment walker and redirect extractor see the
// substitution as atomic.
func Split(tokens []Token) ([]Command, error) {
	fused, err := fuseSubstitutions(tokens)
	if err != nil {
		return nil, err
	}
	return splitAt(fused, 0, "top")
}

// fuseSubstitutions walks the token stream and merges tokens belonging
// to a single unclosed $(...), <(...), >(...), or `...` body. Because
// the tokenizer is oblivious to substitution syntax, a body containing
// spaces or pipes emerges as several tokens; this pass fuses them back
// into one WORD with separator characters preserved inside the Value.
//
// When the stream ends with an unclosed substitution the function
// returns ErrUnbalancedSubst.
func fuseSubstitutions(toks []Token) ([]Token, error) {
	var out []Token
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Type != TokWord {
			out = append(out, t)
			continue
		}
		open := substOpenCount(t.Value)
		if open == 0 {
			out = append(out, t)
			continue
		}
		merged := t
		for open > 0 && i+1 < len(toks) {
			i++
			next := toks[i]
			if next.Type == TokWord {
				merged.Value += " " + next.Value
				merged.Raw += " " + next.Raw
			} else {
				sep := separatorRaw(next.Type)
				merged.Value += sep
				merged.Raw += sep
			}
			open = substOpenCount(merged.Value)
		}
		if open != 0 {
			return nil, ErrUnbalancedSubst
		}
		out = append(out, merged)
	}
	return out, nil
}

// substOpenCount reports the net number of unclosed substitution
// openers in s. It counts $( / <( / >( / ` openings and subtracts
// matching closes, skipping over single-quoted regions (which cannot
// contain substitutions) and backslash escapes. Double quotes are
// transparent: substitutions within "" still expand and are counted.
//
// A positive return value means s has that many open substitutions
// still waiting for their close. Zero means balanced. A negative
// return value is clamped to zero (stray closing parens are treated
// as literal, matching shell behavior).
func substOpenCount(s string) int {
	depth := 0
	inBacktick := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
		case c == '\'' && !inBacktick:
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				j++
			}
			if j >= len(s) {
				return depth
			}
			i = j
		case c == '"' && !inBacktick:
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
				return depth
			}
			i = j
		case c == '`':
			inBacktick = !inBacktick
		case !inBacktick && c == '$' && i+1 < len(s) && s[i+1] == '(':
			depth++
			i++
		case !inBacktick && (c == '<' || c == '>') && i+1 < len(s) && s[i+1] == '(':
			depth++
			i++
		case !inBacktick && c == ')':
			if depth > 0 {
				depth--
			}
		}
	}
	if inBacktick {
		depth++
	}
	return depth
}

// separatorRaw returns the source-character form of a separator token.
// Used by fuseSubstitutions to re-insert separator text inside a fused
// substitution body.
func separatorRaw(typ TokenType) string {
	switch typ {
	case TokSemicolon:
		return ";"
	case TokPipe:
		return "|"
	case TokOrOr:
		return "||"
	case TokAmp:
		return "&"
	case TokAndAnd:
		return "&&"
	case TokNewline:
		return "\n"
	}
	return ""
}

// splitAt is the inner routine: it splits tokens into commands at the
// given depth with the given origin tag. Subshell / process-sub /
// backtick / reentry bodies recurse through this.
func splitAt(tokens []Token, depth int, origin string) ([]Command, error) {
	if depth > MaxDepth {
		return nil, ErrMaxDepthExceeded
	}

	var out []Command
	var seg []Token

	flush := func(term TokenType) error {
		if len(seg) == 0 {
			// a blank line or leading separator: skip newline, keep
			// explicit separators so consumers see the structure.
			if term == TokNewline {
				return nil
			}
			out = append(out, Command{Terminator: term, Depth: depth, Origin: origin})
			return nil
		}
		cmd, err := buildCommand(seg, term, depth, origin)
		if err != nil {
			return err
		}
		out = append(out, cmd)
		seg = seg[:0]
		return nil
	}

	for _, tk := range tokens {
		if tk.Type.IsSeparator() {
			if err := flush(tk.Type); err != nil {
				return nil, err
			}
			continue
		}
		seg = append(seg, tk)
	}
	if len(seg) > 0 {
		if err := flush(TokNewline); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// buildCommand constructs one Command from a run of WORD tokens.
// Order of stages matters:
//  1. Record Original argv (verbatim token Values)
//  2. Strip leading NAME=VALUE assignments into Env
//  3. Extract redirects from the remaining argv
//  4. Peel wrapper commands (sudo / env / timeout / ...)
//  5. Scan all surviving text (argv + env + redirect targets) for
//     substitutions and recurse
//  6. Detect bash-c / eval and recurse their payloads
func buildCommand(seg []Token, term TokenType, depth int, origin string) (Command, error) {
	cmd := Command{
		Terminator: term,
		Depth:      depth,
		Origin:     origin,
	}

	// Stage 1
	for _, tk := range seg {
		cmd.Original = append(cmd.Original, tk.Value)
	}

	// Stage 2 — leading env assignments
	argvStart := 0
	for i, a := range cmd.Original {
		if isEnvAssignment(a) {
			cmd.Env = append(cmd.Env, a)
			argvStart = i + 1
			continue
		}
		break
	}
	argv := append([]string(nil), cmd.Original[argvStart:]...)

	// Stage 3 — redirects
	argv, cmd.Redirects = extractRedirects(argv)

	// Stage 4 — wrapper unwrap
	argv, cmd.Wrappers = unwrapWrappers(argv)
	cmd.Argv = argv

	// Stage 5 — substitutions (scan joined source-text, not per-token)
	subs, err := scanSubstitutions(cmd.Env, cmd.Argv, cmd.Redirects, depth)
	if err != nil {
		return cmd, err
	}
	cmd.Subst = subs

	// Stage 6 — bash -c / eval re-entry
	reentry, err := reentryPayload(cmd.Argv, depth)
	if err != nil {
		return cmd, err
	}
	cmd.Reentry = reentry

	return cmd, nil
}

// isEnvAssignment reports whether s matches the shell NAME=VALUE form.
// NAME must satisfy [A-Za-z_][A-Za-z0-9_]*, and = must precede any
// other non-identifier character.
func isEnvAssignment(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			return i > 0
		}
		if !(c == '_' || (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return false
}
