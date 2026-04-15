#!/bin/bash
# Check grype JSON results - fails if any entries found.
#
# Usage:
#   grype_check.sh <results_file> <count_file> <severity>   — violation mode
#   grype_check.sh <results_file> <count_file>              — stale ignore mode
set -euo pipefail

FILE="$1"
COUNT_FILE="$2"
MODE="${3:-stale}"

if [[ ! -f "$FILE" ]]; then
    echo "ERROR: Results file not found: $FILE"
    exit 1
fi

COUNT=$(cat "$COUNT_FILE")

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
    # Print details on a single line so bazel shows it in the build summary
    DETAILS=$(tr -d '\n' < "$FILE" | sed 's/  */ /g')
    echo "FAIL: $FAIL_MSG $DETAILS"
    exit 1
fi
