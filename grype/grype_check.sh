#!/bin/bash
# Check grype JSON results - fails if any entries found.
#
# Usage:
#   grype_check.sh <file> <severity>   — violation mode (CVEs above threshold)
#   grype_check.sh <file>              — stale ignore mode (ignored CVEs no longer in scan)
set -euo pipefail

FILE="$1"
MODE="${2:-stale}"

if [[ ! -f "$FILE" ]]; then
    echo "ERROR: Results file not found: $FILE"
    exit 1
fi

# Count entries in JSON array (matches both object and string elements)
set +e
COUNT=$(grep -c '"CVE-' "$FILE" 2>/dev/null)
GREP_EXIT=$?
set -e

# grep returns 1 if no match - count will be 0
if [[ $GREP_EXIT -eq 1 ]]; then
    COUNT=0
elif [[ $GREP_EXIT -ne 0 ]]; then
    echo "ERROR: grep failed with exit code $GREP_EXIT"
    exit 1
fi

if [[ "$MODE" == "stale" ]]; then
    PASS_MSG="All ignored CVEs are still present in scan results"
    FAIL_MSG="$COUNT ignored CVEs not found in scan (stale ignores — remove them):"
else
    PASS_MSG="No vulnerabilities at or above $MODE severity"
    FAIL_MSG="Found $COUNT vulnerabilities at or above $MODE severity:"
fi

if [[ "$COUNT" -eq 0 ]]; then
    echo "PASS: $PASS_MSG"
    exit 0
else
    echo "FAIL: $FAIL_MSG"
    cat "$FILE"
    exit 1
fi
