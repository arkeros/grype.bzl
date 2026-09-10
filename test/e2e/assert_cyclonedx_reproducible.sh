#!/usr/bin/env bash

# The CycloneDX counterpart of assert_reproducible.sh, on a report a real
# grype produced.
#
# CycloneDX carries volatile fields of its own that `GRYPE_TIMESTAMP=false`
# does not reach, so the json assertions next door say nothing about this
# format. Measured across two runs of one command before this existed: a
# fresh `serialNumber`, a wall-clock `metadata.timestamp`, and a fresh
# `bom-ref` on every one of forty-two vulnerabilities.
set -o errexit -o nounset -o pipefail

readonly REPORT="${1:?usage: assert_cyclonedx_reproducible.sh <report.json> <jq>}"
readonly JQ="${2:?usage: assert_cyclonedx_reproducible.sh <report.json> <jq>}"

failures=0
fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# The document has content, or nothing below proves anything.
components=$("${JQ}" -r '.components | length' "${REPORT}")
if ((components == 0)); then
    fail "the document has no components"
fi

# All three are optional in the schema, so dropping them leaves a valid BOM.
if "${JQ}" -e 'has("serialNumber")' "${REPORT}" >/dev/null 2>&1; then
    fail "serialNumber is present: $("${JQ}" -r '.serialNumber' "${REPORT}")"
fi
if "${JQ}" -e '.metadata | has("timestamp")' "${REPORT}" >/dev/null 2>&1; then
    fail "metadata.timestamp is present: $("${JQ}" -r '.metadata.timestamp' "${REPORT}")"
fi
if "${JQ}" -e '[.vulnerabilities // [] | .[] | select(has("bom-ref"))] | length > 0' "${REPORT}" >/dev/null 2>&1; then
    fail "a vulnerability still carries a bom-ref, which is a fresh uuid each run"
fi

# Ordering varies run to run as well, so the arrays are sorted once the
# volatile fields are gone.
sorted_by() {
    if ! "${JQ}" -e "(.$1 // []) == ((.$1 // []) | sort_by($2))" "${REPORT}" >/dev/null 2>&1; then
        fail "$1 are not in the deterministic order the rule imposes"
    fi
}
sorted_by components '[."bom-ref" // "", .purl // "", .name // "", .version // ""]'
sorted_by vulnerabilities '[.id // "", ((.affects // []) | map(.ref // "") | sort | join(","))]'
sorted_by dependencies '[.ref // ""]' 

# The same catch-all the json assertions use: no build directory anywhere.
if "${JQ}" -e '.. | strings | select(test("/execroot/|/sandbox/|/private/var/|/tmp/"))' "${REPORT}" >/dev/null 2>&1; then
    fail "the document contains a build-directory path"
fi

if ((failures > 0)); then
    printf '%d assertion(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'OK: CycloneDX document is reproducible-shaped (%s components)\n' "${components}"
