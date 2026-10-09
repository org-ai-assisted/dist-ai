#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL help-steps/retry-run retry_run and asserts it takes its
## default attempt count from the variables.d knob retry_run_default_tries,
## falling back to 4 when the knob is unset (as inside the cowbuilder chroot,
## where variables.d is not sourced). A per-call --tries still overrides.

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
lib="${dm_checkout}/help-steps/retry-run"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: help-steps/retry-run not found at '${lib}' (set DERIVATIVE_MAKER_DIR)." >&2
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

## retry_run calls 'error' only on misuse; define a stub so the source is safe.
error() {
   printf '%s\n' "error: $*" >&2
   return 1
}
# shellcheck disable=SC1090
source "${lib}"

work="$(mktemp -d)"
cleanup() {
   safe-rm -rf -- "${work}"
}
trap cleanup EXIT
countfile="${work}/attempts"

## A transient-looking failure (matches retry_run's transient regex), so
## retry_run retries up to its attempt count. Each call appends one byte.
flaky() {
   printf '%s' "x" >> "${countfile}"
   printf '%s\n' "Could not resolve host: example.invalid"
   return 1
}

## Count attempts for one run with the given retry_run_default_tries setting.
## $1 = value to export, or the literal "unset" to test the fallback.
attempts_for() {
   local setting="$1"
   true > "${countfile}"
   (
      export retry_run_default_delay="0"
      if [ "${setting}" = "unset" ]; then
         unset retry_run_default_tries 2>/dev/null || true
      else
         export retry_run_default_tries="${setting}"
      fi
      retry_run -- flaky >/dev/null 2>&1 || true
   )
   wc -c < "${countfile}" | tr -d ' '
}

## The knob sets the default attempt count.
got="$(attempts_for 3)"
if [ "${got}" = "3" ]; then
   pass "retry_run honours retry_run_default_tries=3 (3 attempts)"
else
   fail "retry_run made ${got} attempts with retry_run_default_tries=3 (knob not read)"
fi

## A different value proves it is actually read (not hardcoded).
got="$(attempts_for 2)"
if [ "${got}" = "2" ]; then
   pass "retry_run honours retry_run_default_tries=2 (2 attempts)"
else
   fail "retry_run made ${got} attempts with retry_run_default_tries=2"
fi

## Unset -> chroot-safe fallback of 4.
got="$(attempts_for unset)"
if [ "${got}" = "4" ]; then
   pass "retry_run falls back to 4 attempts when the knob is unset (chroot-safe)"
else
   fail "retry_run made ${got} attempts with the knob unset, expected 4"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: retry_run default-knobs."
