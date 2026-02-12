#!/usr/bin/env bash
set -euo pipefail

# Rebuild the Aiken validators and copy the blueprint to the
# convex-testing-interface test data directory.
#
# Validators:
#   - check_answer: simple spending validator (datum + redeemer == 43)
#   - ping_pong: secure stateful PingPong with threat model resistance

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$SCRIPT_DIR/../src/testing-interface/test/data/aiken-contracts-example.json"

cd "$SCRIPT_DIR"

# Check aiken is available
if ! command -v aiken &>/dev/null; then
  echo "Error: 'aiken' not found on PATH."
  echo "Install it: cargo install aiken --locked"
  echo "Or see: https://aiken-lang.org/installation-instructions"
  exit 1
fi

echo "=== Building Aiken validators ==="
aiken build

echo ""
echo "=== Copying blueprint to test data ==="
cp plutus.json "$DEST"

# Print summary
echo ""
echo "Done! Blueprint updated:"
echo "  Source: $SCRIPT_DIR/plutus.json"
echo "  Dest:   $DEST"
echo ""
echo "  Aiken version: $(aiken --version)"
echo ""
echo "  Validators:"
if command -v jq &>/dev/null; then
  jq -r '.validators[] | "    \(.title)  hash: \(.hash)"' plutus.json
else
  echo "    (install jq for detailed validator info)"
  grep -o '"title": "[^"]*"' plutus.json | sed 's/"title": "//;s/"$//' | while read -r title; do
    echo "    $title"
  done
fi
echo ""
echo "Now run: cabal test convex-testing-interface"
