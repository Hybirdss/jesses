// Package shellparse is a focused, zero-dependency tokenizer and segment
// splitter for a minimal subset of POSIX shell syntax — just enough to
// extract network destinations from shell commands an LLM agent generates.
//
// This package deliberately does NOT implement the full bash grammar.
// It implements only what is required to:
//
//  1. Split a command line into command-separator-delimited segments
//     (; | || & && newline).
//  2. Recurse into subshells ($(...), <(...), backticks) and process
//     substitutions.
//  3. Unwrap wrapper commands (sudo, env, time, nice, timeout, stdbuf, xargs).
//  4. Re-enter `bash -c` and `eval` string payloads as fresh input.
//  5. Preserve quoting semantics (single quotes literal, double quotes with
//     $/`/"/\/newline escapes, backslash escapes outside quotes).
//  6. Detect /dev/tcp/<host>/<port> redirection tokens as destinations.
//
// The full bash grammar is an order of magnitude larger and includes
// arrays, here-documents, parameter expansion, arithmetic, functions,
// conditionals, loops, coprocesses, and a dozen other constructs that
// never produce scope-relevant network destinations in the hook context.
// Importing a full shell grammar library would tie jesses's canonical
// Merkle leaf hashes to an upstream parser's release cycle — unacceptable
// for a tool whose outputs must be bit-identical forever. Hence the
// in-house focused parser.
//
// The tokenizer produced by this package operates on a flat command string.
// The segment splitter (a separate pass, to be implemented in tokenizer's
// companion file) consumes Tokens and produces Segments, recursing into
// subshells via Tokenize on the subshell body.
//
// This package has zero external dependencies. Stdlib only.
package shellparse
