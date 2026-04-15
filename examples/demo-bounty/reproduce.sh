#!/bin/bash
# reproduce.sh — deterministic replay of the demo bounty session.
#
# Generates session.jes + session.log in this directory. Running
# this script produces files functionally identical to the
# committed samples (timestamps and random session ID differ;
# everything else matches).
#
# Prerequisites:
#   - Go 1.22+ in $PATH (to build jesses)
#   - Node 20+ in $PATH (to run the JS verifier)

set -euo pipefail
cd "$(dirname "$0")"

# Build jesses binary into this directory if not present.
if [[ ! -x ./jesses ]]; then
  (cd ../.. && go build -o examples/demo-bounty/jesses ./cmd/jesses/)
fi

# Clean prior run so the demo is reproducible.
rm -f session.jes session.log key.priv

echo "▶ feeding 7 tool events through the hook (with --fake-rekor + --fake-ots)"
./jesses hook --fake-rekor --session-dir . < events.jsonl | tee hook-output.jsonl

echo
echo "▶ verdict from the Go reference verifier"
# Exit 1 is expected when G5 fails — don't let set -e abort the demo.
./jesses verify --offline session.jes || true

echo
echo "▶ stats dashboard"
./jesses stats session.jes

echo
echo "▶ binding report.md to envelope (G7 provenance)"
./jesses report --bind report.md --session-dir . session.jes || true

echo
echo "▶ verify with report — G7 enforced"
./jesses verify --offline --report report.md session.jes || true

echo
echo "▶ cross-implementation conformance: same envelope, JavaScript verifier"
node cross-verify.mjs
