// Package audit implements the append-only tool-event log for a jesses
// session.
//
// Every tool invocation Claude Code performs produces exactly one record
// (see Event). Records are appended to a per-session audit.log file using
// file-system-level advisory locking (flock) to prevent concurrent writers
// from interleaving lines.
//
// The canonical serialization is deterministic JSON per Go's encoding/json
// default sorting rules for map keys, combined with fixed struct field
// ordering. This canonical form is what the Merkle tree hashes as leaf data,
// so every byte matters.
//
// This package is called from a single short-lived process per tool
// invocation: Claude Code spawns "jesses hook", the hook reads the tool
// input, and calls Writer.Append exactly once. Durability is achieved by
// calling Sync() on Close, so the hook's exit guarantees the record is on
// disk.
package audit
