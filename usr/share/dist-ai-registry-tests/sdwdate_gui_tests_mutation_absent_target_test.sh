#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the sdwdate-gui-tests-mutation absent-target policy: an absent sdwdate_gui
## checkout is a hard FATAL (exit 1), NOT a silent exit-77 SKIP -- UNLESS the caller
## authorized the skip via DIST_AI_SKIP_AUTHORIZED=1 (which dist-ai-tests-all sets for
## a --allow-skip'd or a lenient non-strict run). A bare exit-77 on an absent target
## reads green in a summary line; making it FATAL keeps a misconfigured run (no
## checkout, no authorization) from passing while it tested nothing.
##
## The absent-target guard returns at the top of sdwdate-gui-tests-mutation, before
## staging or mutating anything, so invoking it here neither runs the lane nor recurses.

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
runner="${test_dir}/../../bin/sdwdate-gui-tests-mutation"
[ -x "${runner}" ] || runner='/usr/bin/sdwdate-gui-tests-mutation'
orch="${test_dir}/../../bin/dist-ai-tests-all"
[ -r "${orch}" ] || orch='/usr/bin/dist-ai-tests-all'

if [ ! -x "${runner}" ]; then
   printf '%s\n' 'FATAL: sdwdate_gui_tests_mutation_absent_target_test: sdwdate-gui-tests-mutation not found' >&2
   exit 1
fi

## A path guaranteed to hold no sdwdate_gui module, forcing the absent-target guard.
## Never created, so the guard's -d test is false regardless of the operator's checkout.
absent="${test_dir}/no-such-sdwdate-gui-checkout-$$"

failures=0

## 1) Unauthorized absent target -> hard FATAL (exit 1), never a silent 77.
rc=0
env --unset=DIST_AI_SKIP_AUTHORIZED "SDWDATE_GUI_REPO=${absent}" \
   "${runner}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 1 ]; then
   printf '%s\n' "PASS: absent target without authorization is FATAL (exit 1)"
else
   printf '%s\n' "FAIL: absent target without authorization exited ${rc}, expected 1 (FATAL)" >&2
   failures=$((failures + 1))
fi

## 2) Authorized absent target -> SKIP (exit 77), so --allow-skip still works.
rc=0
env "DIST_AI_SKIP_AUTHORIZED=1" "SDWDATE_GUI_REPO=${absent}" \
   "${runner}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 77 ]; then
   printf '%s\n' "PASS: absent target WITH authorization SKIPs (exit 77)"
else
   printf '%s\n' "FAIL: absent target with DIST_AI_SKIP_AUTHORIZED=1 exited ${rc}, expected 77" >&2
   failures=$((failures + 1))
fi

## 3) The orchestrator sets that authorization ONLY when it would tolerate the skip.
##    Static, by reading dist-ai-tests-all. The line that sets DIST_AI_SKIP_AUTHORIZED
##    must be guarded by "! skip_is_fatal", not unconditional -- an unconditional set
##    would authorize every skip and re-open the hole. (Shared orchestrator plumbing,
##    the same guard secure-terminal relies on.)
if [ ! -r "${orch}" ]; then
   printf '%s\n' "FAIL: dist-ai-tests-all not found for the plumbing check" >&2
   failures=$((failures + 1))
else
   plumb="$(grep -B1 -- 'DIST_AI_SKIP_AUTHORIZED=1' "${orch}" 2>/dev/null || true)"
   if [ -z "${plumb}" ]; then
      printf '%s\n' "FAIL: dist-ai-tests-all never sets DIST_AI_SKIP_AUTHORIZED (suite can never be authorized to skip)" >&2
      failures=$((failures + 1))
   elif [[ "${plumb}" == *'! skip_is_fatal'* ]]; then
      printf '%s\n' "PASS: dist-ai-tests-all gates DIST_AI_SKIP_AUTHORIZED on \"! skip_is_fatal\""
   else
      printf '%s\n' "FAIL: dist-ai-tests-all sets DIST_AI_SKIP_AUTHORIZED without an \"! skip_is_fatal\" guard (missing or inverted)" >&2
      failures=$((failures + 1))
   fi
fi

## 4) The runner is registered in the orchestrator's integration_suites, so the gate
##    actually runs it (an unwired lane silently never executes -- a green that tested
##    nothing). Static read of dist-ai-tests-all.
if [ -r "${orch}" ] && grep --quiet -- 'sdwdate-gui-tests-mutation' "${orch}"; then
   printf '%s\n' "PASS: sdwdate-gui-tests-mutation is wired into dist-ai-tests-all"
else
   printf '%s\n' "FAIL: sdwdate-gui-tests-mutation is not referenced by dist-ai-tests-all (unwired lane)" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf '%s\n' "sdwdate_gui_tests_mutation_absent_target_test: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "sdwdate_gui_tests_mutation_absent_target_test: OK"
