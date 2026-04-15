// test.mjs
//
// Spec-conformance harness for the second-implementation verifier.
//
// Loads every vector directory under ../spec/test-vectors/v0.1/ and
// asserts that verify() produces a Report byte-identical to the
// `expected_report` field stored in vector.json.
//
// Run: `node test.mjs` from this directory.
// Exit 0 = all vectors conforming. Non-zero = a drift from the Go
// reference implementation.
//
// No test framework. No dependencies. A failure prints a diff.

import { readdir, readFile } from "node:fs/promises";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verify } from "./verify.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SPEC_DIR = resolve(__dirname, "..", "spec", "test-vectors", "v0.1");

// canonicalReport serializes a Report the same way Go's
// json.MarshalIndent with two-space indent would. Gate field order
// must match the Go Gate struct: name, title, pass, detail, severity.
// Report field order: gates, ok, session_id.
function canonicalReport(r) {
	const gates = (r.gates || []).map(g => ({
		name: g.name,
		title: g.title,
		pass: !!g.pass,
		detail: g.detail,
		severity: g.severity,
	}));
	return JSON.stringify({
		gates,
		ok: !!r.ok,
		session_id: r.session_id,
	});
}

async function runVector(dir) {
	const vectorRaw = await readFile(join(dir, "vector.json"), "utf8");
	const meta = JSON.parse(vectorRaw);
	const expected = meta.expected_report;

	const rpt = await verify({
		envelopePath: join(dir, "session.jes"),
		auditLogPath: join(dir, "session.log"),
		scopePath: join(dir, "scope.txt"),
	});

	const got = canonicalReport(rpt);
	const want = canonicalReport(expected);

	if (got === want) {
		return { name: meta.name, ok: true };
	}
	return {
		name: meta.name,
		ok: false,
		got,
		want,
	};
}

async function main() {
	const entries = await readdir(SPEC_DIR, { withFileTypes: true });
	const vectors = entries.filter(e => e.isDirectory()).map(e => e.name).sort();
	if (vectors.length === 0) {
		console.error("no spec vectors found at", SPEC_DIR);
		process.exit(1);
	}

	let pass = 0;
	let fail = 0;
	for (const name of vectors) {
		const result = await runVector(join(SPEC_DIR, name));
		if (result.ok) {
			console.log(`  ✓  ${name}`);
			pass++;
		} else {
			fail++;
			console.log(`  ✗  ${name}`);
			console.log(`     got:  ${result.got}`);
			console.log(`     want: ${result.want}`);
		}
	}
	console.log("");
	console.log(`${pass}/${pass + fail} vectors conform to Go reference implementation`);
	process.exit(fail === 0 ? 0 : 1);
}

main().catch(err => {
	console.error(err);
	process.exit(1);
});
