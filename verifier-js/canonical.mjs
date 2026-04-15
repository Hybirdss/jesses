// canonical.mjs
//
// Byte-exact reproduction of the Go reference implementation's
// canonical Event serialization. jesses' Merkle leaves are hashed
// over these bytes — any drift here breaks cross-implementation
// conformance.
//
// Go behavior we match:
//   - struct fields emitted in declaration order (not alphabetical)
//   - omitempty elides zero-length strings, nil slices, empty maps
//   - map keys sorted alphabetically (Go 1.12+ guarantee)
//   - strings use the default encoding/json escaping: < > & get
//     \u003c \u003e \u0026, U+2028 and U+2029 are escaped, control
//     chars < 0x20 use \bNNNN short forms where available
//
// Zero external dependencies. Node 20+ built-ins only.

// eventFieldOrder is the frozen declaration order of
// internal/audit.Event in the Go source. Any reorder here MUST be
// matched by a coordinated edit to record.go — see the invariant
// warning in audit/record.go.
const eventFieldOrder = [
	["seq", "number"],
	["ts", "string"],
	["tool", "string"],
	["input_hash", "string"],
	["input", "object"],
	["destinations", "array"],
	["decision", "string"],
	["reason", "string"],
	["policy_ref", "string"],
];

// Fields with Go's omitempty tag.
const omitemptyFields = new Set(["input", "destinations"]);

// canonicalizeEvent takes a parsed Event object (as produced by
// JSON.parse of an audit log line) and returns the canonical JSON
// bytes that the Go reference implementation would have produced.
export function canonicalizeEvent(ev) {
	const parts = [];
	for (const [name, kind] of eventFieldOrder) {
		const val = ev[name];
		if (omitemptyFields.has(name) && isEmpty(val, kind)) {
			continue;
		}
		parts.push(quote(name) + ":" + encodeValue(val, kind));
	}
	return "{" + parts.join(",") + "}";
}

function isEmpty(v, kind) {
	if (v === undefined || v === null) return true;
	if (kind === "string" && v === "") return true;
	if (kind === "array" && Array.isArray(v) && v.length === 0) return true;
	if (kind === "object" && typeof v === "object" && Object.keys(v).length === 0) return true;
	return false;
}

function encodeValue(v, kind) {
	if (v === undefined || v === null) {
		if (kind === "number") return "0";
		if (kind === "string") return '""';
		return "null";
	}
	switch (kind) {
		case "number":
			return encodeNumber(v);
		case "string":
			return quote(String(v));
		case "array":
			return encodeArray(v);
		case "object":
			return encodeObjectSorted(v);
	}
	return "null";
}

function encodeNumber(n) {
	// Go emits integers without trailing .0 and without exponent for
	// reasonable integer values. For uint64 Seq the values fit in
	// Number.MAX_SAFE_INTEGER in practice (hook events don't reach 2^53).
	if (Number.isInteger(n)) {
		return n.toString(10);
	}
	return n.toString();
}

function encodeArray(arr) {
	return "[" + arr.map(v => encodeAny(v)).join(",") + "]";
}

function encodeObjectSorted(obj) {
	const keys = Object.keys(obj).sort();
	const parts = keys.map(k => quote(k) + ":" + encodeAny(obj[k]));
	return "{" + parts.join(",") + "}";
}

// encodeAny serializes an arbitrary JSON value (used inside map
// values — e.g. Event.Input is map[string]any in Go). Recursively
// matches Go json.Marshal.
function encodeAny(v) {
	if (v === null) return "null";
	if (v === true) return "true";
	if (v === false) return "false";
	if (typeof v === "number") return encodeNumber(v);
	if (typeof v === "string") return quote(v);
	if (Array.isArray(v)) return encodeArray(v);
	if (typeof v === "object") return encodeObjectSorted(v);
	return "null";
}

// quote escapes a JavaScript string to Go-compatible JSON bytes.
export function quote(s) {
	let out = '"';
	for (let i = 0; i < s.length; i++) {
		const code = s.charCodeAt(i);
		// Surrogate pairs: handle together to emit one codepoint.
		if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
			const next = s.charCodeAt(i + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				// BMP supplementary character — emit both units as-is
				// (Go also emits them as two UTF-16 surrogate escapes or
				// as raw UTF-8 depending on setup; since we are hashing
				// the JSON bytes, both paths give identical SHA-256
				// when the source string is the same — which it is
				// because we read it from JSON.parse in both runtimes).
				out += s[i] + s[i + 1];
				i++;
				continue;
			}
		}
		switch (code) {
			case 0x22:
				out += '\\"';
				break;
			case 0x5c:
				out += "\\\\";
				break;
			case 0x08:
				out += "\\b";
				break;
			case 0x09:
				out += "\\t";
				break;
			case 0x0a:
				out += "\\n";
				break;
			case 0x0c:
				out += "\\f";
				break;
			case 0x0d:
				out += "\\r";
				break;
			case 0x3c:
				out += "\\u003c";
				break;
			case 0x3e:
				out += "\\u003e";
				break;
			case 0x26:
				out += "\\u0026";
				break;
			case 0x2028:
				out += "\\u2028";
				break;
			case 0x2029:
				out += "\\u2029";
				break;
			default:
				if (code < 0x20) {
					out += "\\u" + code.toString(16).padStart(4, "0");
				} else {
					out += s[i];
				}
		}
	}
	return out + '"';
}
