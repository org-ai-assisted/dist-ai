#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for anondate's default-setting block under 'set -o nounset'.
##
## THE BUG: variables() set its overridable defaults with
## '[ -n "${TOR_RC}" ] || TOR_RC=...'. Under 'set -o nounset' (which anondate
## enables) an UNSET TOR_RC makes '${TOR_RC}' -- the guard's own test -- abort
## with 'TOR_RC: unbound variable' before the default is ever applied. Every
## line in the block had the same defect, so anondate died on line 20 whenever a
## caller did not pre-export these variables. The fix is '${VAR:-}' in the test.
##
## Drives the REAL anondate: extracts its variables() from the shipped script
## (current text, so it cannot drift from the code) and runs it under nounset
## with every TOR_* / locale variable UNSET -- the exact condition that tripped
## the bug. It must complete and apply the defaults.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/anondate"
else
   subject='/usr/sbin/anondate'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: anondate not readable at '${subject}'; set HELPER_SCRIPTS_REPO or install helper-scripts." >&2
   exit 1
fi

## Extract the variables() function verbatim from the shipped script (top-level
## definition, closing brace in column 0). Reading the current text keeps the
## test from drifting away from the code it guards.
func_body="$(awk '/^variables\(\) \{$/ {f=1} f {print} f && /^\}$/ {exit}' "${subject}")"
if [ -z "${func_body}" ]; then
   printf '%s\n' "FATAL: could not extract variables() from '${subject}'." >&2
   exit 1
fi

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## Run the extracted function under nounset with every default variable UNSET,
## then report the values it applied. A pre-fix variables() aborts here with an
## 'unbound variable' error and rc != 0.
run_rc=0
run_output="$(
   env -u TOR_RC -u TOR_LOG -u TOR_DIR -u TOR_DESCRIPTORS -u NEW_TOR_DESCRIPTORS \
       -u TOR_CONSENSUS -u TOR_UNVERIFIED_CONSENSUS -u DATE_RE -u LC_TIME -u TZ \
      bash -c 'set -o errexit -o nounset -o pipefail
'"${func_body}"'
variables
printf "TOR_RC=%s\n" "${TOR_RC}"
printf "TOR_DIR=%s\n" "${TOR_DIR}"' 2>&1
)" || run_rc=$?

case "${run_output}" in
   *"unbound variable"*)
      fail "variables() tripped nounset on an unset default: ${run_output}"
      ;;
   *)
      pass "variables() runs under nounset with all defaults unset (no unbound variable)"
      ;;
esac

if [ "${run_rc}" -eq 0 ]; then
   pass "variables() exited cleanly (rc=0)"
else
   fail "variables() exited non-zero (rc=${run_rc}) -- output: ${run_output}"
fi

case "${run_output}" in
   *"TOR_RC=/etc/tor/torrc"*)
      pass "variables() applied the TOR_RC default"
      ;;
   *)
      fail "variables() did not apply the TOR_RC default -- output: ${run_output}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: anondate variables() is nounset-safe with unset defaults."
