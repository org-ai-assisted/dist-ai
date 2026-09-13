#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dist-ai-tests-all's --timeout-* validation: a ZERO interval must be rejected
## (exit 2), not accepted.
##
## THE BUG IT GUARDS: require_timeout validated only the SHAPE
## ('^[0-9]+(\.[0-9]+)?[smhd]?$'), which accepts '0'. But timeout(1) treats a
## duration of 0 as "no timeout at all", so '--timeout-core 0' silently DISABLED the
## per-suite timeout -- the exact wedge-with-no-verdict that the --kill-after guard
## exists to prevent. Easy to hit from a CI template passing an unset "${TIMEOUT:-0}".
##
## Drives the SHIPPED orchestrator: a rejected value exits 2 during arg parsing,
## BEFORE the sandbox gate and before any suite runs. The escape vars are unset so a
## VALID value stops at the host gate (exit 3) rather than ever running a suite.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

orch="${test_dir}/../../bin/dist-ai-tests-all"
[ -x "${orch}" ] || orch='/usr/bin/dist-ai-tests-all'
if [ ! -x "${orch}" ]; then
   printf '%s\n' 'FATAL: timeout_zero_rejected_test: dist-ai-tests-all not found' >&2
   exit 1
fi

failures=0

## Run the orchestrator with every sandbox-gate escape UNSET, so a value that PASSES
## validation halts at the host gate (exit 3) and never runs a suite.
run_orch() {
   local rc=0
   env --unset=GITHUB_ACTIONS --unset=DIST_AI_IN_SANDBOX \
      --unset=DIST_AI_ALLOW_HOST_TESTS --unset=CI \
      "${orch}" "$@" >/dev/null 2>&1 || rc="$?"
   printf '%s\n' "${rc}"
}

check() {
   local desc="$1" want="$2" got="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s (rc %s)\n' "${desc}" "${got}"
   else
      printf 'FAIL: %s: rc %s, expected %s\n' "${desc}" "${got}" "${want}" >&2
      failures=$((failures + 1))
   fi
}

## A zero interval in any spelling is rejected with the usage exit code 2.
check '--timeout-core 0 is rejected'    2 "$(run_orch --timeout-core 0)"
check '--timeout-fuzz 0 is rejected'    2 "$(run_orch --timeout-fuzz 0)"
check '--timeout-heavy 0.0 is rejected' 2 "$(run_orch --timeout-heavy 0.0)"
check '--timeout-core 0s is rejected'   2 "$(run_orch --timeout-core 0s)"
## A malformed value is still a usage error (unchanged behaviour).
check '--timeout-core abc is rejected'  2 "$(run_orch --timeout-core abc)"
## A valid POSITIVE interval PASSES validation -> it is not exit 2; with the escapes
## unset it halts at the host sandbox gate (exit 3), proving it was accepted.
check '--timeout-core 300 passes validation, halts at gate' 3 "$(run_orch --timeout-core 300)"
check '--timeout-core 600s passes validation, halts at gate' 3 "$(run_orch --timeout-core 600s)"

if [ "${failures}" -gt 0 ]; then
   printf 'timeout_zero_rejected_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'timeout_zero_rejected_test: OK\n'
