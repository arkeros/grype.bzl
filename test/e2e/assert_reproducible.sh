#!/usr/bin/env bash

# Asserts the properties that make a grype report reproducible, on a report a
# real grype produced.
#
# The analysis tests next door assert the shape of the command; they would
# still pass if grype started resolving paths to absolute ones itself, or
# stamping a time under another name. This reads the report.
set -o errexit -o nounset -o pipefail

readonly REPORT="${1:?usage: assert_reproducible.sh <report.json> <jq>}"
readonly JQ="${2:?usage: assert_reproducible.sh <report.json> <jq>}"

failures=0
fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# The scan found something, or the assertions below prove nothing.
matches=$("${JQ}" -r '.matches | length' "${REPORT}")
if ((matches == 0)); then
    fail "the report has no matches, so it cannot show anything about their order"
fi

# grype copies the path it was handed into the report. Absolute means the
# sandbox directory of the action, which differs on every build.
target=$("${JQ}" -r '.source.target | if type == "object" then .userInput else . end' "${REPORT}")
case "${target}" in
/*) fail "source.target is absolute: ${target}" ;;
esac

cache=$("${JQ}" -r '.descriptor.configuration.db["cache-dir"] // ""' "${REPORT}")
case "${cache}" in
/*) fail "db.cache-dir is absolute: ${cache}" ;;
esac

# Nothing anywhere in the report should name an execroot or a sandbox: this
# catches a path leaking through a field nobody thought to check.
if "${JQ}" -e '.. | strings | select(test("/execroot/|/sandbox/|/private/var/|/tmp/"))' "${REPORT}" >/dev/null 2>&1; then
    fail "the report contains a build-directory path: $("${JQ}" -r '[.. | strings | select(test("/execroot/|/sandbox/|/private/var/|/tmp/"))] | first' "${REPORT}")"
fi

# The wall clock. Everything under `descriptor.db` is the pinned database's
# own dates, which are meant to be there and move only when the pin moves.
if "${JQ}" -e 'has("descriptor") and (.descriptor | has("timestamp"))' "${REPORT}" >/dev/null 2>&1; then
    fail "descriptor.timestamp is present: $("${JQ}" -r '.descriptor.timestamp' "${REPORT}")"
fi

# grype returns equally-ranked matches in an order that varies run to run, so
# the rule sorts them. Already-sorted is what that looks like from outside.
if ! "${JQ}" -e '.matches == (.matches | sort_by([-(.vulnerability.risk // 0), tojson]))' "${REPORT}" >/dev/null 2>&1; then
    fail "matches are not in the deterministic order the rule imposes"
fi

if ((failures > 0)); then
    printf '%d assertion(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'OK: report is reproducible-shaped (%s matches)\n' "${matches}"
