---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0008 — Exclusion-first policy evaluation

## Context and problem statement

A `scope.txt` file can contain both inclusion (`in:`) and exclusion (`out:`) rules. The evaluation semantics for the overlap between them determines what a user sees when they write a common pattern like:

```
in: *.github.com
out: blog.github.com
```

A naive first-match-wins evaluator walking the file top to bottom accepts `blog.github.com` as matching `in: *.github.com` and never reaches the `out:` rule. Users writing that file almost universally expect the opposite: exclusions should override inclusions even when listed later.

The choice of evaluation order shapes every policy file ever written. Changing it later breaks existing scopes silently.

## Decision drivers

- Match user intuition for the dominant case (allow a broad pattern, carve out specific items).
- Deterministic and explainable in one sentence.
- Independent of rule ordering within each block (so reorganizing the file cannot silently change meaning).
- Fail-safe: when in doubt, block rather than allow.

## Considered options

- Exclusion-first (every `out:` rule evaluated before any `in:`; first matching `out:` denies; otherwise first matching `in:` allows)
- File-order first-match-wins (walk the file top to bottom; first rule to match decides)
- Longest-prefix-wins (most specific pattern decides regardless of in/out)
- Last-match-wins (last rule to match decides; iptables-style)

## Decision outcome

**Chosen: exclusion-first evaluation.** Every `out:` rule is checked before any `in:` rule. If any `out:` matches, the action is blocked. Otherwise, the first matching `in:` allows. If nothing matches, the action is handled per the file's `mode:` directive — `strict` blocks, `advisory` warns. Within each of the two blocks (`out:` and `in:`), first-match-wins is the internal order.

### Positive consequences

- `in: *.github.com` + `out: blog.github.com` does what the user expected.
- Reordering rules within their block does not change aggregate semantics, only which specific rule receives the attribution.
- The semantics are describable in one sentence: "exclusions always win, then the first inclusion, then the mode default."
- Fail-safe default (strict mode blocks on no-match) aligns with the "authorized action envelope" framing.

### Negative consequences

- Users used to iptables-style last-match-wins will need to read the explanation once.
- A genuinely exception-to-the-exception case (rare) requires restructuring the `out:` block rather than ordering around it. Acceptable — exceptions-to-exceptions in scope files almost always indicate a scoping error.

## Pros and cons of the options

### Exclusion-first

- Good: matches intuition for the dominant use case
- Good: ordering within blocks is a stylistic choice, not a semantic one
- Good: simple to explain and implement
- Bad: exception-to-exception patterns require block-level restructuring

### File-order first-match-wins

- Good: simplest possible implementation
- Bad: violates user intuition for the dominant case; users will write broken scopes and not know it
- Bad: reordering the file silently changes policy

### Longest-prefix-wins

- Good: "most specific rule wins" sounds principled
- Bad: "most specific" is not well-defined across namespaces (host wildcards vs path globs vs repo vs contract vs MCP)
- Bad: specificity calculation is opaque; users cannot predict which rule will win

### Last-match-wins (iptables)

- Good: familiar to network engineers
- Bad: not intuitive for non-network-engineer users (bounty hunters, agents, compliance officers)
- Bad: rule order now matters across the whole file; hard to refactor

## Validation

- `internal/policy/precedence_test.go` exercises the exclusion-first semantics directly.
- `TestAnchoredSubdomain` covers the canonical trap (`*.target.com` must match `sub.target.com` but NOT `target.com` or `evil-target.com` or `notarget.com`).
- Documentation in `SPEC.md` §Policy shows the semantics in one paragraph plus a truth table.

## Links

- `internal/policy/precedence.go`
- `internal/policy/precedence_test.go`
- `SPEC.md` §Policy semantics
- `THREAT_MODEL.md` §Subdomain confusion
