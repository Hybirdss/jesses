package shellparse

import (
	"errors"
	"strings"
)

// TokenType identifies the kind of a token emitted by Tokenize.
type TokenType int

const (
	// TokWord is a single "word" in the shell sense: a whitespace-delimited
	// run of characters with quoting and backslash escapes fully resolved.
	// Adjacent quoted runs concatenate into a single word per POSIX
	// (e.g., `foo'bar'"baz"` is one word `foobarbaz`).
	TokWord TokenType = iota

	// TokSemicolon is `;` — synchronous command separator.
	TokSemicolon

	// TokPipe is `|` — pipeline separator.
	TokPipe

	// TokOrOr is `||` — short-circuit OR list operator.
	TokOrOr

	// TokAmp is `&` — background (async) command separator.
	TokAmp

	// TokAndAnd is `&&` — short-circuit AND list operator.
	TokAndAnd

	// TokNewline is a literal newline (unquoted).
	TokNewline
)

// String returns a short symbolic name for a TokenType, useful in test
// failure messages.
func (t TokenType) String() string {
	switch t {
	case TokWord:
		return "WORD"
	case TokSemicolon:
		return "SEMI"
	case TokPipe:
		return "PIPE"
	case TokOrOr:
		return "OROR"
	case TokAmp:
		return "AMP"
	case TokAndAnd:
		return "ANDAND"
	case TokNewline:
		return "NEWLINE"
	}
	return "?"
}

// IsSeparator reports whether the token is a command-separator operator
// (semicolon, pipe, background, logical-and, logical-or, newline).
func (t TokenType) IsSeparator() bool {
	switch t {
	case TokSemicolon, TokPipe, TokOrOr, TokAmp, TokAndAnd, TokNewline:
		return true
	}
	return false
}

// Token is one lexical element produced by Tokenize.
//
// For TokWord, Value contains the fully-dequoted literal that a shell
// would pass to execve for this argument. Raw preserves the original
// source characters including quotes and escapes.
//
// For operator tokens, Value is empty and Raw contains the operator
// symbol. Start is the zero-based byte offset in the original input
// where the token begins.
type Token struct {
	Type  TokenType
	Value string
	Raw   string
	Start int
}

// Errors returned by Tokenize for malformed input.
var (
	ErrUnterminatedSingleQuote = errors.New("shellparse: unterminated single quote")
	ErrUnterminatedDoubleQuote = errors.New("shellparse: unterminated double quote")
)

// Tokenize splits a shell command string into tokens.
//
// The tokenizer recognizes exactly six command separators
// (; | || & && newline) and handles three kinds of quoting:
//
//   - Single quotes: literal content, no escapes, no interpolation.
//   - Double quotes: backslash escapes `$`, backtick, `"`, `\`, and newline;
//     all other backslashes are preserved literally (POSIX behavior).
//   - Backslash outside quotes: next character is literal; backslash-newline
//     is a line continuation (both characters elided from output).
//
// Subshell constructs — `$(...)`, `<(...)`, backticks — are NOT tokenized
// into their own structural markers at this layer. Their opening and
// closing characters are preserved inside the surrounding WORD token's
// Value; the segment splitter (a higher-level pass) is responsible for
// recursing into them.
//
// Variable expansions (`$var`, `${var}`, `$(...)`, backticks) are likewise
// preserved literally. jesses is a static parser: it never evaluates
// shell variables or command substitutions.
//
// Adjacent quoted runs and unquoted characters concatenate into a single
// WORD. `foo"bar"baz'qux'` produces one TokWord with Value `foobarbazqux`.
//
// Tokenize returns a non-nil error only for unterminated quoted strings.
// All other inputs, including the empty string and whitespace-only input,
// return a (possibly empty) token slice and nil error.
func Tokenize(input string) ([]Token, error) {
	t := &tokenizer{input: input, wordStart: -1}
	if err := t.run(); err != nil {
		return nil, err
	}
	return t.tokens, nil
}

// tokenizer carries the state of a single Tokenize call.
type tokenizer struct {
	input  string
	pos    int
	tokens []Token

	// current word accumulator
	val        strings.Builder // dequoted value
	raw        strings.Builder // original source chars
	wordStart  int             // -1 when no word is active
	wordActive bool            // true once a word has started, even if its value is empty (e.g., "")
}

func (t *tokenizer) startWord() {
	if !t.wordActive {
		t.wordStart = t.pos
		t.wordActive = true
	}
}

func (t *tokenizer) flushWord() {
	if !t.wordActive {
		return
	}
	t.tokens = append(t.tokens, Token{
		Type:  TokWord,
		Value: t.val.String(),
		Raw:   t.raw.String(),
		Start: t.wordStart,
	})
	t.val.Reset()
	t.raw.Reset()
	t.wordStart = -1
	t.wordActive = false
}

func (t *tokenizer) emitOp(typ TokenType, raw string) {
	t.flushWord()
	t.tokens = append(t.tokens, Token{Type: typ, Raw: raw, Start: t.pos})
	t.pos += len(raw)
}

func (t *tokenizer) peek2() string {
	if t.pos+2 <= len(t.input) {
		return t.input[t.pos : t.pos+2]
	}
	return ""
}

func (t *tokenizer) run() error {
	n := len(t.input)
	for t.pos < n {
		c := t.input[t.pos]
		switch c {
		case ' ', '\t':
			t.flushWord()
			t.pos++
		case '\n':
			t.emitOp(TokNewline, "\n")
		case ';':
			t.emitOp(TokSemicolon, ";")
		case '|':
			if t.peek2() == "||" {
				t.emitOp(TokOrOr, "||")
			} else {
				t.emitOp(TokPipe, "|")
			}
		case '&':
			if t.peek2() == "&&" {
				t.emitOp(TokAndAnd, "&&")
			} else {
				t.emitOp(TokAmp, "&")
			}
		case '\\':
			t.readBackslash()
		case '\'':
			if err := t.readSingleQuoted(); err != nil {
				return err
			}
		case '"':
			if err := t.readDoubleQuoted(); err != nil {
				return err
			}
		default:
			t.startWord()
			t.val.WriteByte(c)
			t.raw.WriteByte(c)
			t.pos++
		}
	}
	t.flushWord()
	return nil
}

// readBackslash handles a backslash outside any quotes:
//
//   - backslash + newline  → line continuation (both chars dropped)
//   - backslash + any char → that char is literal (backslash dropped)
//   - trailing backslash   → literal backslash
func (t *tokenizer) readBackslash() {
	t.startWord()
	if t.pos+1 >= len(t.input) {
		// Trailing backslash: emit literal.
		t.val.WriteByte('\\')
		t.raw.WriteByte('\\')
		t.pos++
		return
	}
	next := t.input[t.pos+1]
	t.raw.WriteByte('\\')
	t.raw.WriteByte(next)
	if next != '\n' {
		t.val.WriteByte(next)
	}
	// On '\n': line continuation, both chars elided from Value.
	t.pos += 2
}

// readSingleQuoted consumes a single-quoted string starting at t.pos.
// The current character is assumed to be '. The entire body up to the
// next ' is appended literally to the current word.
func (t *tokenizer) readSingleQuoted() error {
	t.startWord()
	t.raw.WriteByte('\'')
	end := strings.IndexByte(t.input[t.pos+1:], '\'')
	if end < 0 {
		return ErrUnterminatedSingleQuote
	}
	body := t.input[t.pos+1 : t.pos+1+end]
	t.val.WriteString(body)
	t.raw.WriteString(body)
	t.raw.WriteByte('\'')
	t.pos = t.pos + 1 + end + 1
	return nil
}

// readDoubleQuoted consumes a double-quoted string starting at t.pos.
// The current character is assumed to be ". Backslash escapes are
// applied only to the POSIX-defined set: `$`, backtick, `"`, `\`, newline.
// All other backslashes are preserved literally.
func (t *tokenizer) readDoubleQuoted() error {
	t.startWord()
	t.raw.WriteByte('"')
	t.pos++
	for t.pos < len(t.input) {
		c := t.input[t.pos]
		if c == '"' {
			t.raw.WriteByte('"')
			t.pos++
			return nil
		}
		if c == '\\' && t.pos+1 < len(t.input) {
			nxt := t.input[t.pos+1]
			switch nxt {
			case '$', '`', '"', '\\':
				t.val.WriteByte(nxt)
				t.raw.WriteByte(c)
				t.raw.WriteByte(nxt)
				t.pos += 2
				continue
			case '\n':
				// Line continuation inside "": both chars elided.
				t.raw.WriteByte(c)
				t.raw.WriteByte(nxt)
				t.pos += 2
				continue
			default:
				// POSIX: backslash is literal for any other char inside "".
				t.val.WriteByte(c)
				t.val.WriteByte(nxt)
				t.raw.WriteByte(c)
				t.raw.WriteByte(nxt)
				t.pos += 2
				continue
			}
		}
		t.val.WriteByte(c)
		t.raw.WriteByte(c)
		t.pos++
	}
	return ErrUnterminatedDoubleQuote
}
