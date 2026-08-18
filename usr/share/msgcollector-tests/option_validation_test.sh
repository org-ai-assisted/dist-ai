#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for msgcollector option-parser validation (ai-review, claude pass):
##  - a value-taking option given with no value must fail with a clear "requires
##    a value" error, NOT the alarming "script bug" banner (a bare 'shift 2' past
##    the end trips the ERR trap under errexit + shift_verbose);
##  - --typex must reject a value outside info|warning|error at the collection
##    boundary, instead of silently producing no GUI dialog later (the dialog's
##    argparse rejects it, and that dispatch is backgrounded / discarded).
##
## Drives the REAL msgcollector binary end-to-end against an isolated
## XDG_RUNTIME_DIR (the same mechanism integration_tests_test.sh uses).

set -o errexit
set -o nounset
set -o errtrace
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""
msgcollector_libexec="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector"
MSGCOLLECTOR="${msgcollector_libexec}/msgcollector"

if [ ! -r "${MSGCOLLECTOR}" ]; then
  printf '%s\n' "$0: SKIP: msgcollector not found at '${MSGCOLLECTOR}'" >&2
  exit 77
fi

XDG_RUNTIME_DIR="$(mktemp --directory)"
export XDG_RUNTIME_DIR
cleanup_handler() {
  ## Invoked via trap, not called directly.
  # shellcheck disable=SC2317
  safe-rm --recursive --force -- "${XDG_RUNTIME_DIR}"
}
trap cleanup_handler EXIT

PASS=0
FAIL=0
pass() {
  printf '%s\n' "$0: PASS: $1"
  PASS=$(( PASS + 1 ))
}
fail() {
  printf '%s\n' "$0: FAIL: $1" >&2
  FAIL=$(( FAIL + 1 ))
}

test_missing_option_value_is_clean_error() {
  ## A value-taking option as the last argument, no value. Capture both streams
  ## (msgcollector prints these diagnostics on stdout).
  local rc out
  rc=0
  out="$("${MSGCOLLECTOR}" --identifier vtest --typex 2>&1)" || rc=$?
  if [ "${rc}" = "0" ]; then
    fail "missing --typex value: expected nonzero exit"
    return
  fi
  if grep --quiet --fixed-strings -- 'requires a value' <<< "${out}" \
     && ! grep --quiet --ignore-case -- 'script bug' <<< "${out}"; then
    pass "missing option value -> clean 'requires a value' error (no 'script bug' banner)"
  else
    fail "missing --typex value: wrong message: '${out}'"
  fi
}

test_invalid_typex_is_rejected() {
  ## An out-of-range severity must be rejected at collection, not silently
  ## dropped at dispatch.
  local rc out
  rc=0
  out="$("${MSGCOLLECTOR}" --identifier vtest --typex badtype --messagex \
         --message 'hi' --done 2>&1)" || rc=$?
  if [ "${rc}" != "0" ] \
     && grep --quiet --fixed-strings -- 'invalid typex' <<< "${out}"; then
    pass "invalid --typex value rejected with a clear error"
  else
    fail "invalid --typex value: expected nonzero exit with 'invalid typex', got rc=${rc} out='${out}'"
  fi
}

test_valid_typex_still_accepted() {
  ## Guard against over-tightening: a valid severity must still collect cleanly.
  local rc
  rc=0
  "${MSGCOLLECTOR}" --identifier vtest --typex info --messagex \
    --message 'hi' --done >/dev/null 2>&1 || rc=$?
  if [ "${rc}" = "0" ]; then
    pass "valid --typex value still accepted"
  else
    fail "valid --typex info was rejected (rc=${rc})"
  fi
}

test_missing_option_value_is_clean_error
test_invalid_typex_is_rejected
test_valid_typex_still_accepted

printf '%s\n' "$0: Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne "0" ]; then
  exit 1
fi
exit 0
