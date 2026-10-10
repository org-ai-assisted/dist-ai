#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the SECURE_TERMINAL_TESTS_ONLY selector against a SILENT-GREEN hole: a selector
## that is ONLY separators (e.g. ',') word-splits to ZERO items, so the per-item
## unknown-suite FATAL never fires, the matched set stays empty, and the runner would
## execute ZERO suites yet exit 0 -- a typo reading green. A non-empty selector that
## matches nothing must be FATAL (exit 1), never a silent no-op.
##
## Drives the REAL secure-terminal-tests runner against a STUB checkout (only the module
## directory, so the absent-target guard passes) with the selector set; both cases FATAL
## at the ONLY-filter BEFORE any suite runs, so no compositor and no Qt are needed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

## Installed layout is /usr/share/...; from a checkout the entrypoints sit at ../../bin.
runner="${test_dir}/../../bin/secure-terminal-tests"
[ -x "${runner}" ] || runner='/usr/bin/secure-terminal-tests'
if [ ! -x "${runner}" ]; then
   printf '%s\n' 'FATAL: secure_terminal_tests_only_empty_match_test: secure-terminal-tests not found' >&2
   exit 1
fi

## A stub checkout: only the secure_terminal module DIRECTORY is needed for the
## absent-target guard's -d test to pass. The ONLY-filter runs before any import.
fakerepo="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${fakerepo}" 2>/dev/null || true; }
trap cleanup EXIT
mkdir -p -- "${fakerepo}/usr/lib/python3/dist-packages/secure_terminal"

failures=0

## 1) A separators-only selector matches zero suites -> FATAL (exit 1), never a silent 0.
rc=0
out="$(env --unset=DIST_AI_SKIP_AUTHORIZED \
   "SECURE_TERMINAL_REPO=${fakerepo}" "SECURE_TERMINAL_TESTS_ONLY=," \
   "${runner}" 2>&1)" || rc="$?"
if [ "${rc}" -eq 1 ] && [[ "${out}" == *'matched no suite'* ]]; then
   printf '%s\n' "PASS: a separators-only SECURE_TERMINAL_TESTS_ONLY is FATAL (exit 1), not silent green"
else
   printf '%s\n' "FAIL: separators-only selector exited ${rc} (want 1) / message missing; out=${out}" >&2
   failures=$((failures + 1))
fi

## 2) The per-item unknown-suite FATAL still fires (the empty-match guard did not shadow it).
rc=0
out="$(env --unset=DIST_AI_SKIP_AUTHORIZED \
   "SECURE_TERMINAL_REPO=${fakerepo}" "SECURE_TERMINAL_TESTS_ONLY=no_such_suite" \
   "${runner}" 2>&1)" || rc="$?"
if [ "${rc}" -eq 1 ] && [[ "${out}" == *'unknown suite'* ]]; then
   printf '%s\n' "PASS: an unknown-named suite is still FATAL (exit 1) via the per-item guard"
else
   printf '%s\n' "FAIL: unknown-suite selector exited ${rc} (want 1) / message missing; out=${out}" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf '%s\n' "secure_terminal_tests_only_empty_match_test: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "secure_terminal_tests_only_empty_match_test: OK"
