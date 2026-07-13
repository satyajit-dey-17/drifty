#!/usr/bin/env bash
# examples/terragrunt_scan.sh
#
# Example CI-ready Terragrunt drift scan using drifty.
# Requires: drifty, terragrunt, terraform, AWS credentials.
#
# Exit codes:
#   0 — no drift
#   1 — drift detected
#   2 — operational failure
#   3 — partial scan failure

set -euo pipefail

INFRA_ROOT="${1:-./infra}"
MIN_SEVERITY="${2:-high}"
OUTPUT_FILE="drift-report-$(date +%Y%m%d-%H%M%S).json"

echo "==> Validating discovery..."
drifty terragrunt discover --root "${INFRA_ROOT}"

echo ""
echo "==> Running drift scan (min-severity: ${MIN_SEVERITY})..."
drifty terragrunt scan \
  --root "${INFRA_ROOT}" \
  --min-severity "${MIN_SEVERITY}" \
  --output json \
  > "${OUTPUT_FILE}" || SCAN_EXIT=$?

SCAN_EXIT="${SCAN_EXIT:-0}"

echo ""
echo "==> Report written to: ${OUTPUT_FILE}"

case "${SCAN_EXIT}" in
  0) echo "✓ No drift detected." ;;
  1) echo "⚠ Drift detected. Review ${OUTPUT_FILE} for details." ;;
  2) echo "✗ Scan failed. Check terragrunt/terraform installation and AWS credentials." ;;
  3) echo "⚠ Partial scan failure. Some units could not be scanned." ;;
  *) echo "Unknown exit code: ${SCAN_EXIT}" ;;
esac

exit "${SCAN_EXIT}"