// cross-verify.mjs — runs the JavaScript second implementation
// against the demo envelope. Used by reproduce.sh to prove that
// the .jes is readable by a second independent implementation.

import { verify } from "../../verifier-js/verify.mjs";

const rpt = await verify({
	envelopePath: "./session.jes",
	auditLogPath: "./session.log",
	scopePath: "./scope.txt",
	reportPath: "./report.md",
});

const pass = rpt.gates.filter(g => g.pass).length;
console.log("  " + (rpt.ok ? "✓" : "✗") + " JS verifier: " + pass + "/6 gates pass (ok=" + rpt.ok + ")");
for (const g of rpt.gates) {
	const mark = g.pass ? "✓" : g.severity === "advisory" ? "⚠" : "✗";
	console.log("     " + mark + "  " + g.name + "  " + g.title + " — " + g.detail);
}
