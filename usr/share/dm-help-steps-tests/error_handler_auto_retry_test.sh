#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL help-steps/pre error handler (exception_handler_process_shared
## + exception_handler_retry) and asserts the auto-retry CONTROL logic:
##   1. the auto-retry counter caps at dist_build_auto_retry (--retry-max)
##   2. 'fatal_error_no_retry' short-circuits auto-retry entirely
##   3. a retry that SUCCEEDS stops the loop immediately
##
## Scope note: this covers the retry COUNT/decision logic, which is correct. It
## does NOT assert replay FIDELITY of the captured command (the known
## BASH_COMMAND-capture/replay defect) -- those regression tests land with that
## fix.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
pre="${dm_checkout}/help-steps/pre"
if [ ! -r "${pre}" ]; then
   printf '%s\n' "FATAL: help-steps/pre not found at '${pre}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi
## pre's helper-scripts siblings (xtrace/trace/retry-run) resolve via this.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH:-${dm_checkout}/packages/kicksecure/helper-scripts}"
if [ ! -r "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/xtrace.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts not found at '${HELPER_SCRIPTS_PATH}' (set HELPER_SCRIPTS_PATH)." >&2
   exit 1
fi

test_failures=0
pass() {
   printf '%s\n' "PASS: $*"
}
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Source the REAL handler, then DISARM the traps it installs so this test shell
## keeps control and calls the handler explicitly.
# shellcheck disable=SC1090
source "${pre}" >/dev/null 2>&1
trap - ERR EXIT INT TERM HUP

## Silence the handler's console output (output_cmd_set would otherwise rebuild
## output_cmd from xtrace state). A no-op keeps the real control flow intact.
output_cmd_set() {
   ## Read by the sourced handler ("${output_cmd[@]}" ...), not locally.
   # shellcheck disable=SC2034
   output_cmd=(true)
}

## Minimal environment the handler reads (non-interactive, zero retry wait).
## Consumed by the sourced exception_handler_*, not referenced locally; the
## handler reads the dispatch/do-retry knobs via ${x:-} defaults, so only the
## values that must differ from empty/unset are set here.
# shellcheck disable=SC2034
dist_build_interactive="false"
# shellcheck disable=SC2034
dist_build_wait_auto_retry="0"
# shellcheck disable=SC2034
dist_build_version="test"
# shellcheck disable=SC2034
dist_build_error_counter="0"
# shellcheck disable=SC2034
trap_signal_type_last=""
# shellcheck disable=SC2034
last_failed_exit_code="1"
# shellcheck disable=SC2034
ignore_error="false"

## Drive one auto-retry scenario in a SUBSHELL so globals (counter, probe count)
## never leak between cases. Echo the probe invocation count on stdout.
##   $1 = dist_build_auto_retry (--retry-max)
##   $2 = the last_failed_bash_command to replay
##   $3 = retry-probe behaviour: "fail" (always) or "succeed-after:N"
run_scenario() {
   local max="$1" cmd="$2" behave="$3"
   (
      RETRY_COUNT=0
      succeed_after="${behave#succeed-after:}"
      ## retry_probe / fatal_error_no_retry are invoked INDIRECTLY: the sourced
      ## handler replays them by name via last_failed_bash_command, so shellcheck
      ## cannot see the call site.
      # shellcheck disable=SC2317
      retry_probe() {
         RETRY_COUNT=$((RETRY_COUNT + 1))
         if [ "${behave}" = "fail" ]; then
            return 1
         fi
         if [ "${RETRY_COUNT}" -ge "${succeed_after}" ]; then
            return 0
         fi
         return 1
      }
      # shellcheck disable=SC2317
      fatal_error_no_retry() {
         ## Stand-in: like the real sentinel, it is not a runnable command path,
         ## but the handler decides on the NAME, not on running it.
         RETRY_COUNT=$((RETRY_COUNT + 1))
         return 1
      }
      ## Read by the sourced exception_handler_* (not locally).
      # shellcheck disable=SC2034
      dist_build_auto_retry="${max}"
      unset dist_build_auto_retry_counter 2>/dev/null || true
      # shellcheck disable=SC2034
      last_failed_bash_command="${cmd}"
      exception_handler_process_shared "ERR" >/dev/null 2>&1 || true
      printf '%s\n' "${RETRY_COUNT}"
   )
}

## 1. Counter caps at --retry-max: a command that always fails is retried
## EXACTLY dist_build_auto_retry times, then the handler gives up.
count="$(run_scenario 2 retry_probe fail)"
if [ "${count}" = "2" ]; then
   pass "auto-retry caps at dist_build_auto_retry (retried ${count}/2 times)"
else
   fail "auto-retry count was ${count}, expected 2 (--retry-max cap broken)"
fi

## A different cap value is honoured (guards against a hardcoded 2).
count="$(run_scenario 4 retry_probe fail)"
if [ "${count}" = "4" ]; then
   pass "auto-retry honours a --retry-max of 4 (retried ${count} times)"
else
   fail "auto-retry count was ${count}, expected 4"
fi

## 2. fatal_error_no_retry short-circuits: NO retry at all.
count="$(run_scenario 2 "fatal_error_no_retry boom" fail)"
if [ "${count}" = "0" ]; then
   pass "fatal_error_no_retry short-circuits auto-retry (0 retries)"
else
   fail "fatal_error_no_retry still retried ${count} time(s) (short-circuit broken)"
fi

## 3. A retry that succeeds stops the loop immediately (no further attempts).
count="$(run_scenario 5 retry_probe succeed-after:1)"
if [ "${count}" = "1" ]; then
   pass "auto-retry stops as soon as a retry succeeds (ran ${count} time)"
else
   fail "auto-retry ran ${count} times after success, expected 1"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: error-handler auto-retry control logic."
