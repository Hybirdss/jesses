package policy

import "fmt"

// Verdict is the final policy outcome for a destination.
type Verdict int

const (
	VerdictAllow Verdict = iota // an "in:" rule permits the destination
	VerdictWarn                 // no rule matches; mode is advisory
	VerdictBlock                // an "out:" rule excludes, or mode is strict on unpoliced
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictWarn:
		return "warn"
	case VerdictBlock:
		return "block"
	}
	return "unknown"
}

// Decision is the detailed evaluation result.
type Decision struct {
	Verdict  Verdict
	Reason   string // rule reference or "unpoliced (<mode>)"
	RuleLine int    // 1-based source line of the matched rule, or 0 if none
}

// Evaluate looks up the policy verdict for a single (namespace, value) pair.
//
// Evaluation is exclusion-first: every "out:" rule in the file is considered
// before any "in:" rule. If an "out:" rule matches, the destination is
// blocked regardless of any later "in:" rule. If no "out:" rule matches,
// "in:" rules are checked in source order and the first match wins.
//
// If no rule matches, the verdict depends on the policy mode:
//
//	strict   -> VerdictBlock, reason "unpoliced (strict mode)"
//	advisory -> VerdictWarn,  reason "unpoliced (advisory mode)"
func (p *Policy) Evaluate(ns Namespace, value string) Decision {
	// First pass: exclusions win.
	for _, r := range p.Rules {
		if r.Action != ActionOut || r.Namespace != ns {
			continue
		}
		if r.Match(value) {
			return Decision{
				Verdict:  VerdictBlock,
				Reason:   fmt.Sprintf("excluded by rule on line %d (%s: %s)", r.Line, ns, r.Pattern),
				RuleLine: r.Line,
			}
		}
	}
	// Second pass: first matching "in:" wins.
	for _, r := range p.Rules {
		if r.Action != ActionIn || r.Namespace != ns {
			continue
		}
		if r.Match(value) {
			return Decision{
				Verdict:  VerdictAllow,
				Reason:   fmt.Sprintf("allowed by rule on line %d (%s: %s)", r.Line, ns, r.Pattern),
				RuleLine: r.Line,
			}
		}
	}
	// No rule matched — mode determines the verdict.
	if p.Mode == ModeStrict {
		return Decision{Verdict: VerdictBlock, Reason: "unpoliced (strict mode)"}
	}
	return Decision{Verdict: VerdictWarn, Reason: "unpoliced (advisory mode)"}
}
