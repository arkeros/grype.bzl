#!/bin/bash
# Check grype violations JSON - fails if any vulnerabilities found
set -euo pipefail

VIOLATIONS_FILE="$1"
FAIL_ON="$2"

if [[ ! -f "$VIOLATIONS_FILE" ]]; then
    echo "ERROR: Violations file not found: $VIOLATIONS_FILE"
    exit 1
fi

# Check if array is empty (no violations)
# Count occurrences of "id" in JSON
set +e
COUNT=$(grep -c '"id"' "$VIOLATIONS_FILE" 2>/dev/null)
GREP_EXIT=$?
set -e

# grep returns 1 if no match, but that's ok - count will be 0
if [[ $GREP_EXIT -eq 1 ]]; then
    COUNT=0
elif [[ $GREP_EXIT -ne 0 ]]; then
    echo "ERROR: grep failed with exit code $GREP_EXIT"
    exit 1
fi

if [[ "$COUNT" -eq 0 ]]; then
    echo "PASS: No vulnerabilities at or above $FAIL_ON severity"
    exit 0
else
    echo "FAIL: Found $COUNT vulnerabilities at or above $FAIL_ON severity:"
    cat "$VIOLATIONS_FILE"
    exit 1
fi
