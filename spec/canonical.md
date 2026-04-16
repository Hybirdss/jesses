# Canonical JSON encoding — jesses v0.1

This document defines the byte sequence a conforming jesses implementation MUST emit when serializing an audit event (or any other value that will be hashed into a Merkle leaf). Two independent implementations are conformant iff they produce byte-identical output for every vector in `spec/test-vectors/v0.1/`.

This is NOT a new format. It is a strict subset of what Go's `encoding/json` package emits by default. The subset is described here so a reviewer, an external auditor, or an implementer in a third language can produce matching bytes without reading Go source.

Reference implementations:

- Go: [`internal/canonical/canonical.go`](../internal/canonical/canonical.go)
- JavaScript: [`verifier-js/canonical.mjs`](../verifier-js/canonical.mjs)

Conformance tests: [`internal/canonical/conformance_test.go`](../internal/canonical/conformance_test.go).

---

## 1. Composition rules

### 1.1 Objects from Go-style structs

The order of fields in a structured object is the **declaration order** in the source (for Go, the order fields appear in the struct; for other languages, the explicit ordering fixed in this document). It is NOT alphabetical.

For jesses `audit.Event`, the frozen order is:

```
seq, ts, tool, input_hash, input, destinations, decision, reason, policy_ref
```

Any change to this order silently rehashes every Merkle leaf in every existing `.jes` file. It is a breaking change of the same severity as changing the hash function.

A field with an `omitempty` attribute is elided from the output when its value is the zero value of its type:

| Go type           | Omitted when                        |
| ----------------- | ----------------------------------- |
| `string`          | equal to `""`                       |
| integer/float     | equal to `0`                        |
| `bool`            | equal to `false`                    |
| slice             | `nil` OR length `0`                 |
| map               | `nil` OR length `0`                 |
| pointer/interface | `nil`                               |

For jesses `audit.Event`, `input` and `destinations` carry `omitempty`.

### 1.2 Objects from maps (arbitrary keys)

When the source type is a map with string keys — including Go's `map[string]any`, used to carry arbitrary tool input payloads — the keys are emitted in **byte-order sort**. This is NOT locale-aware; `"B"` (0x42) sorts before `"a"` (0x61).

Nested maps are sorted recursively.

### 1.3 Arrays

Arrays preserve source order. No sort.

---

## 2. Primitive encoding

### 2.1 Strings

Strings are emitted as UTF-8, enclosed in `"`. The following characters MUST be escaped:

| Codepoint     | Escape      | Reason                                              |
| ------------- | ----------- | --------------------------------------------------- |
| U+0022 `"`    | `\"`        | JSON grammar                                        |
| U+005C `\`    | `\\`        | JSON grammar                                        |
| U+0008        | `\b`        | Short form                                          |
| U+0009        | `\t`        | Short form                                          |
| U+000A        | `\n`        | Short form                                          |
| U+000C        | `\f`        | Short form                                          |
| U+000D        | `\r`        | Short form                                          |
| U+0000..U+001F (excluding the five above) | `\u00XX` (lowercase hex)   | Control char |
| U+003C `<`    | `\u003c`    | HTML-safety default of Go's `encoding/json`         |
| U+003E `>`    | `\u003e`    | HTML-safety default                                 |
| U+0026 `&`    | `\u0026`    | HTML-safety default                                 |
| U+2028        | `\u2028`    | JSONP-safety default                                |
| U+2029        | `\u2029`    | JSONP-safety default                                |

All other codepoints pass through as raw UTF-8 bytes.

This is intentionally **not** RFC 8785 (JCS). JCS leaves `<`, `>`, `&` raw. jesses uses Go's default because the `encoding/json` HTML-safe mode is the fixed behavior we got at v0.1 and we are committed to not breaking existing `.jes` files. A future jesses v0.2 may migrate to JCS; the corresponding canonical bytes would differ and v0.2 `.jes` files would be a separate predicate-type under the same transparency-log conventions.

### 2.2 Numbers

Integers and floats are emitted in the shortest ECMAScript-compatible round-trip form. For an integer `n`:

- emitted as the decimal digits of `n`
- no leading zero (except the literal `0`)
- no trailing `.0`
- no exponent (unless necessary to stay short, which does not happen for practical jesses fields)

jesses' `audit.Event.Seq` is a `uint64` but in practice an event counter bounded by session length. Implementations targeting languages with only 53-bit-safe integers (JavaScript) are safe for all realistic sessions.

Non-finite numbers (`NaN`, `±Inf`) are **not permitted**. An encoder that encounters one MUST return an error.

### 2.3 null / true / false

Emitted as the lowercase keywords `null`, `true`, `false`.

---

## 3. Structural bytes

- No whitespace between tokens.
- No trailing newline.
- No BOM.
- Key–value separator is `:` (no surrounding space).
- Element separator is `,` (no surrounding space).

The canonical JSON for an `audit.Event` is appended to the session log with a single `\n` byte. The `\n` is a log-framing artifact, NOT part of the canonical bytes. The Merkle leaf hashes the canonical bytes without the trailing newline.

---

## 4. Conformance vectors

Every implementation MUST produce the following byte sequences (shown as hex so whitespace is unambiguous). The complete set is machine-checked in `internal/canonical/conformance_test.go`.

| Input                                      | Hex output                                            |
| ------------------------------------------ | ----------------------------------------------------- |
| `null`                                     | `6e756c6c`                                            |
| `42`                                       | `3432`                                                |
| `{"c":3,"a":1,"b":2}` (unordered map)      | `7b2261223a312c2262223a322c2263223a337d`              |
| `"<script>"`                               | `225c75303033637363726970745c75303033652f3c...`       |
| `"café 中"`                                 | `22636166c3a920e4b8ad22`                              |

(The `<script>` and `café 中` rows are given in full in the test table; this markdown table is a readable spot-check.)

Additional classes the test suite covers:

1. Primitives (`null`, `true`, `false`, `0`).
2. String escapes (all five short forms, all three HTML escapes, both JS line separators, generic control chars).
3. UTF-8 passthrough for non-escaped codepoints in both BMP and surrogate-pair range.
4. Map key sort order, including byte-vs-locale.
5. Nested map sort.
6. Integer format (no trailing `.0`, no exponent).
7. Empty-slice form `[]` (NOT elided at the canonical layer — only `omitempty`-tagged struct fields are elided).
8. Slice order preservation.
9. Struct declaration order (not alphabetical).
10. Determinism — 100 iterations on the same input produce identical bytes.

---

## 5. What this spec does NOT guarantee

- **NOT RFC 8785 (JCS).** See §2.1 — `<`, `>`, `&`, U+2028, U+2029 escape. A library that implements JCS will NOT produce conformant bytes.
- **NOT a canonical form for `float64`.** jesses predicates do not carry floats. An implementation that processes external JSON with floats must pass them through unchanged; there is no guarantee that two `float64` producers of the "same" number emit the same bytes.
- **NOT safe against non-UTF-8 input.** Strings containing invalid UTF-8 sequences produce undefined output. jesses callers MUST validate UTF-8 before passing strings in.
- **NOT a replacement for a signature.** Canonical JSON proves two producers agree on the bytes. The signature proves who produced them. Both gates must hold.

---

## 6. Revision history

- v0.1 (2026-04-16) — initial publication, extracted from `internal/audit/canonical.go` and the byte-exact JS sibling `verifier-js/canonical.mjs`. No behavior change versus the in-tree encoder; this document formalizes what was already being emitted.
