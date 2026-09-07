#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins one silent-green regression in usr/bin/sdwdate-gui-tests-integration:
## when EVERY integration phase is skipped for missing display tooling (ran==0),
## the runner must report SKIP (exit 77), NEVER PASS (exit 0). The pre-fix tail
## fell through to 'exit 0' with zero tests run -- a false green under the
## 0=PASS / 77=SKIP / else=FAIL orchestrator contract.
##
## Drives the SHIPPED helper (report_result), extracted from the runner text so
## an edit to it is what gets tested; run in a subshell because it calls exit.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/sdwdate-gui-tests-integration"
[ -r "${runner}" ] || runner='/usr/bin/sdwdate-gui-tests-integration'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: sdwdate-gui-tests-integration not found" >&2
   exit 1
fi

## Extract the shipped exit-logic. Its ABSENCE (pre-fix inline tail) is itself
## the regression, so a missing function is a FAIL, not a silent pass.
eval "$(sed -n '/^report_result() {/,/^}/p' -- "${runner}")"
if ! declare -F report_result >/dev/null; then
   fail 'runner has no report_result(): the ran==0 false-green fix is missing (pre-fix inline "exit 0")'
   printf '%s\n' "===== ${pass_count} passed, ${fail_count} failed =====" >&2
   exit 1
fi

## Run report_result in a subshell with controlled globals; capture its exit code.
check_exit() {
   local want="$1" _ran="$2" _failed="$3" label="$4" rc=0
   ( ran="${_ran}"; failed="${_failed}"; report_result ) >/dev/null 2>&1 || rc=$?
   if [ "${rc}" = "${want}" ]; then
      pass "${label}: exit ${rc}"
   else
      fail "${label}: exit ${rc}, want ${want}"
   fi
}

check_exit 77 0 0 'ran==0 (all phases skipped) -> SKIP'
check_exit 0 2 0 'ran>0, failed==0 -> PASS'
check_exit 1 2 1 'failed>0 -> FAIL'
check_exit 1 0 1 'failed>0 with ran==0 -> FAIL (failure trumps)'

printf '%s\n' "" "test_sdwdate_integration_runner_skip: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
