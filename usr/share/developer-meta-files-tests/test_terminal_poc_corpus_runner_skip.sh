#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins a silent-green regression in usr/bin/terminal-poc-corpus-tests: an
## absent REQUIRED target/dep (terminal-poc-corpus / secure_terminal checkout,
## or python3-pyqt6/pyte) used to 'exit 77' UNCONDITIONALLY -- a bare SKIP that
## reads GREEN, the exact "terminal-poc-corpus-tests reported SKIP in CI for
## weeks while the gate looked wired" regression. It must be FATAL (exit 1)
## unless the orchestrator authorized the skip (DIST_AI_SKIP_AUTHORIZED=1),
## matching secure-terminal-tests-fuzz.
##
## Drives the SHIPPED helper (skip_or_fatal), extracted from the runner text.

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
runner="${test_dir}/../../bin/terminal-poc-corpus-tests"
[ -r "${runner}" ] || runner='/usr/bin/terminal-poc-corpus-tests'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: terminal-poc-corpus-tests not found" >&2
   exit 1
fi

## The fix replaced three unconditional 'exit 77' blocks with skip_or_fatal, and
## added report_stage_result (all-stages-skipped -> not a green PASS). Their
## ABSENCE is the regression, so a missing function is a FAIL.
eval "$(sed -n '/^skip_or_fatal() {/,/^}/p' -- "${runner}")"
eval "$(sed -n '/^report_stage_result() {/,/^}/p' -- "${runner}")"
if ! declare -F skip_or_fatal >/dev/null; then
   fail 'runner has no skip_or_fatal(): the unauthorized-absent-target skip fix is missing (pre-fix unconditional "exit 77")'
   printf '%s\n' "===== ${pass_count} passed, ${fail_count} failed =====" >&2
   exit 1
fi
if ! declare -F report_stage_result >/dev/null; then
   fail 'runner has no report_stage_result(): the all-stages-skipped false-green fix is missing (pre-fix "exit ${overall}")'
   printf '%s\n' "===== ${pass_count} passed, ${fail_count} failed =====" >&2
   exit 1
fi

run_gate() {
   ## Args: DIST_AI_SKIP_AUTHORIZED value ('' = unset), expected exit, label.
   local authval="$1" want="$2" label="$3" rc=0
   if [ -z "${authval}" ]; then
      ( unset DIST_AI_SKIP_AUTHORIZED; skip_or_fatal 'test target absent' ) >/dev/null 2>&1 || rc=$?
   else
      ( DIST_AI_SKIP_AUTHORIZED="${authval}"; skip_or_fatal 'test target absent' ) >/dev/null 2>&1 || rc=$?
   fi
   if [ "${rc}" = "${want}" ]; then
      pass "${label}: exit ${rc}"
   else
      fail "${label}: exit ${rc}, want ${want}"
   fi
}

## Unauthorized (the standalone / lenient / --allow-skip case) MUST be FATAL.
run_gate '' 1 'DIST_AI_SKIP_AUTHORIZED unset -> FATAL (1)'
## Only the orchestrator-authorized case SKIPs.
run_gate 1 77 'DIST_AI_SKIP_AUTHORIZED=1 -> SKIP (77)'
## A non-1 value is NOT authorization.
run_gate 0 1 'DIST_AI_SKIP_AUTHORIZED=0 -> FATAL (1)'

## report_stage_result: the stage-level silent-green guard. Runs in a subshell with
## controlled globals (overall/ran) + a controlled DIST_AI_SKIP_AUTHORIZED.
check_stage_result() {
   local _overall="$1" _ran="$2" authval="$3" want="$4" label="$5" rc=0
   (
      overall="${_overall}"; ran="${_ran}"
      if [ -z "${authval}" ]; then unset DIST_AI_SKIP_AUTHORIZED; else DIST_AI_SKIP_AUTHORIZED="${authval}"; fi
      report_stage_result
   ) >/dev/null 2>&1 || rc=$?
   if [ "${rc}" = "${want}" ]; then
      pass "${label}: exit ${rc}"
   else
      fail "${label}: exit ${rc}, want ${want}"
   fi
}

## A real stage failure trumps.
check_stage_result 1 0 '' 1 'overall!=0 -> FAIL (1)'
## Every stage skipped (ran==0), unauthorized -> FATAL, not a green PASS (the finding).
check_stage_result 0 0 '' 1 'all stages skipped, unauthorized -> FATAL (1)'
## Every stage skipped, authorized by the orchestrator -> SKIP.
check_stage_result 0 0 1 77 'all stages skipped, authorized -> SKIP (77)'
## At least one stage ran and none failed -> real PASS.
check_stage_result 0 2 '' 0 'ran>0, overall==0 -> PASS (0)'

## Structural: every legitimate 'exit 77' now lives inside skip_or_fatal, so a
## reintroduced bare skip on an absent target (evading the gate) shows up as a
## second one. Assert exactly one.
count77="$(grep --count --extended-regexp '^[[:space:]]*exit 77[[:space:]]*$' -- "${runner}" || true)"
if [ "${count77}" = '1' ]; then
   pass 'exactly one exit 77 in the runner (inside skip_or_fatal)'
else
   fail "runner has ${count77} bare 'exit 77' lines, want 1 (all skips must route through skip_or_fatal)"
fi

printf '%s\n' "" "test_terminal_poc_corpus_runner_skip: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
