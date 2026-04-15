// verify.mjs
//
// Second-implementation verifier for the jesses v0.1 attestation
// envelope. Produces a Report that is byte-identical to the Go
// reference implementation's output when fed the same vector.
//
// Six gates:
//   G1 — envelope signature (ed25519 via node:crypto)
//   G2 — merkle root recomputed from the audit log
//   G3 — rekor pre-commit body hash matches canonical receipt
//   G4 — scope.txt sha256 matches predicate's scope_hash
//   G5 — no deny events in the audit log
//   G6 — opentimestamps anchor status (advisory at v0.1)
//
// Usage:
//   import { verify } from "./verify.mjs";
//   const rpt = await verify({
//     envelopePath: "session.jes",
//     auditLogPath: "session.log",
//     scopePath:    "scope.txt",
//   });
//
// Zero dependencies beyond Node 20+ built-ins.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalizeEvent } from "./canonical.mjs";
import { hashLeaf, rootFromLeafHashes } from "./merkle.mjs";
import { canonicalReceiptBytes } from "./precommit.mjs";

// verify runs all six gates and returns the same Report shape the Go
// reference implementation emits. The returned object serializes to
// identical JSON when passed through JSON.stringify with the field
// order Go uses — callers doing byte-exact conformance testing must
// canonicalize with the Go field order (the shape chosen below).
export async function verify(opts) {
	const envRaw = await readFile(opts.envelopePath, "utf8");
	const env = JSON.parse(envRaw);
	const payloadBytes = Buffer.from(env.payload, "base64");
	const stmt = JSON.parse(payloadBytes.toString("utf8"));
	const pred = stmt.predicate;

	const gates = [];

	// ---- G1: signature ----
	const g1 = { name: "G1", title: "envelope signature", pass: false, detail: "", severity: "mandatory" };
	try {
		const pubHex = pred.pub_key;
		if (!pubHex || pubHex.length !== 64) {
			g1.detail = "invalid ed25519 public key";
		} else if (!env.signatures || env.signatures.length === 0) {
			g1.detail = "no signatures";
		} else {
			const pubBuf = Buffer.from(pubHex, "hex");
			const sigBuf = Buffer.from(env.signatures[0].sig, "base64");
			const keyObj = createPublicKey({
				key: buildEd25519DER(pubBuf),
				format: "der",
				type: "spki",
			});
			const ok = cryptoVerify(null, payloadBytes, keyObj, sigBuf);
			if (ok) {
				g1.pass = true;
				g1.detail = "ed25519 signature valid";
			} else {
				g1.detail = "signature mismatch";
			}
		}
	} catch (e) {
		g1.detail = "signature verify error: " + e.message;
	}
	gates.push(g1);

	// ---- G2: merkle root ----
	const g2 = { name: "G2", title: "merkle root", pass: false, detail: "", severity: "mandatory" };
	if (!opts.auditLogPath) {
		g2.detail = "audit log path not provided (skipped)";
		g2.severity = "advisory";
	} else {
		try {
			const logBytes = await readFile(opts.auditLogPath, "utf8");
			const lines = logBytes.split("\n").filter(l => l.length > 0);
			const leaves = lines.map(line => {
				const ev = JSON.parse(line);
				const canon = canonicalizeEvent(ev);
				return hashLeaf(Buffer.from(canon, "utf8"));
			});
			const root = rootFromLeafHashes(leaves);
			const rootHex = root.toString("hex");
			if (rootHex !== pred.merkle_root) {
				g2.detail = `root mismatch: got ${rootHex} want ${pred.merkle_root}`;
			} else if (leaves.length !== pred.leaf_count) {
				g2.detail = `leaf count mismatch: got ${leaves.length} want ${pred.leaf_count}`;
			} else {
				g2.pass = true;
				g2.detail = `${leaves.length} leaves, root ${rootHex.substring(0, 16)}…`;
			}
		} catch (e) {
			g2.detail = "audit log read error: " + e.message;
		}
	}
	gates.push(g2);

	// ---- G3: rekor pre-commit ----
	const g3 = { name: "G3", title: "rekor pre-commit", pass: false, detail: "", severity: "mandatory" };
	try {
		const receipt = pred.precommit;
		const body = canonicalReceiptBytes(receipt);
		const localHash = createHash("sha256").update(Buffer.from(body, "utf8")).digest("hex");
		const logBodyHash = receipt.log_entry?.body_hash || "";
		if (localHash !== logBodyHash) {
			g3.detail = "precommit BodyHash does not match canonical receipt";
		} else if (opts.rekorClient) {
			// Online path: fetch the entry and double-check.
			const fetched = await opts.rekorClient.fetch(receipt.log_entry.log_index);
			if (fetched.body_hash !== logBodyHash) {
				g3.detail = "rekor entry body hash mismatch";
			} else {
				g3.pass = true;
				g3.detail = `log index ${fetched.log_index}, signed at ${fetched.signed_at}`;
			}
		} else {
			g3.pass = true;
			g3.detail = `local hash match (log index ${receipt.log_entry?.log_index ?? "?"}, rekor not queried)`;
		}
	} catch (e) {
		g3.detail = "precommit verify error: " + e.message;
	}
	gates.push(g3);

	// ---- G4: scope hash ----
	const g4 = { name: "G4", title: "scope hash", pass: false, detail: "", severity: "mandatory" };
	if (!opts.scopePath) {
		g4.detail = "scope path not provided (advisory)";
		g4.severity = "advisory";
	} else {
		try {
			const raw = await readFile(opts.scopePath);
			const h = createHash("sha256").update(raw).digest("hex");
			if (h !== pred.scope_hash) {
				g4.detail = `scope hash mismatch: got ${h.substring(0, 16)}… want ${pred.scope_hash.substring(0, 16)}…`;
			} else {
				g4.pass = true;
				g4.detail = "scope.txt matches committed hash";
			}
		} catch (e) {
			g4.detail = "scope read error: " + e.message;
		}
	}
	gates.push(g4);

	// ---- G5: policy compliance ----
	const g5 = { name: "G5", title: "policy compliance", pass: false, detail: "", severity: "mandatory" };
	if (!opts.auditLogPath) {
		g5.detail = "audit log not provided (skipped)";
		g5.severity = "advisory";
	} else {
		try {
			const logBytes = await readFile(opts.auditLogPath, "utf8");
			const lines = logBytes.split("\n").filter(l => l.length > 0);
			let breaches = 0;
			let total = 0;
			for (const line of lines) {
				const ev = JSON.parse(line);
				total++;
				const d = ev.decision || "";
				if (d !== "allow" && d !== "commit" && d !== "warn") {
					breaches++;
				}
			}
			if (breaches > 0) {
				g5.detail = `${breaches} of ${total} events breached policy`;
			} else {
				g5.pass = true;
				g5.detail = `all ${total} events allowed by scope`;
			}
		} catch (e) {
			g5.detail = "policy scan error: " + e.message;
		}
	}
	gates.push(g5);

	// ---- G7: deliverable provenance binding ----
	// Order matches the Go reference: G7 evaluated before G6 so the
	// gate list rendering stays consistent across implementations.
	const g7 = { name: "G7", title: "deliverable provenance", pass: false, detail: "", severity: "advisory" };
	const binding = pred.deliverable_binding;
	if (!binding) {
		g7.detail = "no deliverable bound to envelope";
	} else if (!opts.reportPath) {
		g7.severity = "mandatory";
		g7.detail = `envelope declares report "${binding.path}" but none provided to verify`;
	} else {
		g7.severity = "mandatory";
		const [pass, detail] = await checkDeliverable(opts.reportPath, opts.auditLogPath, binding);
		g7.pass = pass;
		g7.detail = detail;
	}
	gates.push(g7);

	// ---- G6: OTS anchor ----
	const g6 = { name: "G6", title: "opentimestamps anchor", pass: false, detail: "", severity: "advisory" };
	const ots = pred.ots_receipt || {};
	const otsErr = pred.ots_error || "";
	if (otsErr) {
		g6.detail = "anchor submission failed: " + otsErr;
	} else if (!ots.calendar_url) {
		g6.detail = "no OTS client configured (rekor provides mandatory pre-commit)";
	} else if (ots.status === "pending") {
		g6.detail = "pending bitcoin confirmation — submitted to " + ots.calendar_url;
	} else if (ots.status === "confirmed") {
		g6.pass = true;
		g6.detail = "anchored in bitcoin via " + ots.calendar_url;
	} else {
		g6.detail = "unknown status: " + (ots.status || "");
	}
	gates.push(g6);

	let ok = true;
	for (const g of gates) {
		if (g.severity === "mandatory" && !g.pass) {
			ok = false;
			break;
		}
	}

	return { gates, ok, session_id: pred.session_id };
}

// checkDeliverable runs G7 on the report: hash the file, match
// against binding.sha256, parse markdown footnote citations, verify
// each against the audit log.
//
// Mirrors internal/verify.checkDeliverable + internal/provenance.Validate
// in the Go reference implementation. Must produce byte-identical
// detail strings for cross-implementation conformance.
async function checkDeliverable(reportPath, auditLogPath, binding) {
	const raw = await readFile(reportPath);
	const gotHash = createHash("sha256").update(raw).digest("hex");
	if (gotHash !== binding.sha256) {
		return [false, `hash mismatch: got ${gotHash.substring(0, 16)}… want ${binding.sha256.substring(0, 16)}…`];
	}
	if (!auditLogPath) {
		return [false, "audit log path required for G7 citation check"];
	}

	const reportText = raw.toString("utf8");
	const { citations, bareClaims } = parseReport(reportText);
	const logBytes = await readFile(auditLogPath, "utf8");
	const events = logBytes.split("\n").filter(l => l.length > 0).map(l => JSON.parse(l));

	// Index events for lookup by seq and by canonical leaf hash.
	const bySeq = new Map();
	const byHash = new Map();
	for (const ev of events) {
		bySeq.set(ev.seq ?? 0, ev);
		const { canonicalizeEvent } = await import("./canonical.mjs");
		const { hashLeaf } = await import("./merkle.mjs");
		const canon = canonicalizeEvent(ev);
		const h = hashLeaf(Buffer.from(canon, "utf8")).toString("hex");
		byHash.set(h, ev);
	}

	let passed = 0;
	for (const c of citations) {
		if (c.seq !== null && bySeq.has(c.seq)) {
			passed++;
		} else if (c.hashPrefix) {
			for (const [h] of byHash) {
				if (h.startsWith(c.hashPrefix)) {
					passed++;
					break;
				}
			}
		}
	}

	const policy = binding.bare_policy || "warn";
	const detail = `${passed}/${citations.length} citations valid, ${bareClaims.length} bare claims (policy: ${policy})`;
	let ok = passed === citations.length;
	if (policy === "strict" && bareClaims.length > 0) ok = false;
	return [ok, detail];
}

// parseReport extracts [^ev:N] and [^hash:H] inline citations and
// bare-factual-claim lines from a markdown report. Mirrors the Go
// provenance.Parse heuristic.
function parseReport(text) {
	const footnoteRE = /\[\^(ev:\d+|hash:[a-fA-F0-9]{4,64})\]/g;
	const factRE = /\b(https?:\/\/[^\s)]+|\/[a-z0-9_./-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:HTTP\/[12](?:\.\d)?)\s*\d{3})/i;

	const citations = [];
	const bareClaims = [];
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const trimmed = line.replace(/^\s+/, "");
		if (trimmed.startsWith("[^") && trimmed.includes("]:")) {
			continue; // footnote definition, not an inline citation
		}
		const matches = [...line.matchAll(footnoteRE)];
		for (const m of matches) {
			const marker = m[1];
			if (marker.startsWith("ev:")) {
				citations.push({ markerID: marker, seq: parseInt(marker.slice(3), 10), hashPrefix: null, line: i + 1 });
			} else if (marker.startsWith("hash:")) {
				citations.push({ markerID: marker, seq: null, hashPrefix: marker.slice(5).toLowerCase(), line: i + 1 });
			}
		}
		if (matches.length === 0 && factRE.test(line)) {
			bareClaims.push({ line: i + 1, text: line.trim() });
		}
	}
	return { citations, bareClaims };
}

// buildEd25519DER wraps a 32-byte ed25519 public key in a
// SubjectPublicKeyInfo DER structure so Node's createPublicKey accepts it.
// The envelope stores only the raw 32 bytes; Node's key parser wants
// the algorithm-identifier prefix. This hardcoded prefix is the DER
// encoding of SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pub } }.
function buildEd25519DER(pubBytes) {
	const prefix = Buffer.from([
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
		0x03, 0x21, 0x00,
	]);
	return Buffer.concat([prefix, pubBytes]);
}
