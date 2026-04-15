// precommit.mjs
//
// Reproduces internal/precommit.CanonicalBytes for the receipt
// body hash gate (G3). Field order is fixed and must match the Go
// struct declaration order exactly.

import { quote } from "./canonical.mjs";

// canonicalReceiptBytes returns the JSON bytes that Rekor signed
// when the receipt was uploaded. Recomputing SHA-256 over these
// bytes and comparing to LogEntry.BodyHash is what G3 asserts.
export function canonicalReceiptBytes(r) {
	// Go CanonicalBytes emits these five fields in this exact order.
	// No omitempty — every field is always present.
	return (
		"{" +
		quote("session_id") + ":" + quote(r.session_id || "") + "," +
		quote("scope_hash") + ":" + quote(r.scope_hash || "") + "," +
		quote("pub_key") + ":" + quote(r.pub_key || "") + "," +
		quote("timestamp") + ":" + quote(r.timestamp || "") + "," +
		quote("version") + ":" + quote(r.version || "") +
		"}"
	);
}
