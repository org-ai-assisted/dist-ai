#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: the dm error handler (help-steps/pre) NO LONGER auto-retries
## by replaying the captured ${last_failed_bash_command} string. That replay was
## unsound -- a command behind `cmd || return` / `if` / a pipe captured the wrong
## token, and a command with a variable/quote/space could not be replayed
## faithfully (and an apt-get replay dropped DIST_APTGETOPT). Genuinely transient
## commands now retry soundly at the call site via help-steps/retry-run's
## argv-array retry_run. This asserts the replay mechanism is GONE.

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

## STRUCTURAL CANARY: the replay function must not exist. FAILS on the old code,
## which defined exception_handler_retry.
if declare -F exception_handler_retry >/dev/null 2>&1; then
   fail "exception_handler_retry still defined -- the unsound BASH_COMMAND replay was not removed"
else
   pass "exception_handler_retry is gone (no BASH_COMMAND replay function)"
fi

## BEHAVIOURAL CANARY: driving the handler must NOT replay last_failed_bash_command.
## Set it to a probe that would increment a counter if the handler ran it; after
## the handler processes an error, the probe must have run ZERO times. FAILS on
## the old code (which replayed it up to dist_build_auto_retry times).
output_cmd_set() {
   ## Read by the sourced handler, not locally.
   # shellcheck disable=SC2034
   output_cmd=(true)
}
# shellcheck disable=SC2034
dist_build_interactive="false"
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

replay_count="$(
   RETRY_COUNT=0
   # shellcheck disable=SC2317
   replay_probe() {
      RETRY_COUNT=$((RETRY_COUNT + 1))
      return 1
   }
   ## Mimic the old auto-retry knob being ON, to prove the mechanism is gone even
   ## when a stale caller still exports it.
   # shellcheck disable=SC2034
   dist_build_auto_retry="2"
   # shellcheck disable=SC2034
   last_failed_bash_command="replay_probe"
   exception_handler_process_shared "ERR" >/dev/null 2>&1 || true
   printf '%s\n' "${RETRY_COUNT}"
)"
if [ "${replay_count}" = "0" ]; then
   pass "the error handler never replays last_failed_bash_command (0 invocations)"
else
   fail "last_failed_bash_command was replayed ${replay_count} time(s) -- unsound auto-retry still present"
fi

## The capture of the failed command (for the ERROR report) is intentionally KEPT.
## shellcheck disable=SC2016 -- literal string searched for with grep -F, not expanded.
# shellcheck disable=SC2016
if grep --quiet --fixed-strings 'last_failed_bash_command="${BASH_COMMAND}"' -- "${pre}"; then
   pass "last_failed_bash_command is still CAPTURED for the error report"
else
   fail "last_failed_bash_command capture missing -- the error report lost the failed command"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: error handler no longer replays BASH_COMMAND."
