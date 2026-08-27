#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for two parse-cmd arg-handling bugs:
##   - --kernel / --headers / --initramfs read BUILD_*_PKGS to append to it, but
##     parse-cmd runs under nounset BEFORE help-steps/variables defaults those, so a
##     REAL value (not 'none'/empty) crashed with 'unbound variable'. Fixed with a
##     :- default.
##   - --package-jobs printed its "must be a whole integer" error but did NOT exit,
##     so a bogus value slipped through fail-fast into a much later build step.
##
## Drives the REAL parse-cmd; only the color/error reporting layer help-steps/pre
## would supply is stubbed.

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
parse_cmd="${dm_checkout}/help-steps/parse-cmd"
if [ ! -x "${parse_cmd}" ]; then
   printf '%s\n' "FATAL: parse-cmd not found/executable at '${parse_cmd}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

export bold='' cyan='' eunder='' red='' reset='' under=''
error() {
   printf '%s\n' "$*"
   exit 1
}
export -f error

## Run parse-cmd with the given args; captured combined output (rc ignored -- the
## run errors out later on mandatory args, which is fine; we assert on messages).
run_out() {
   env -u CLAUDECODE "${parse_cmd}" "$@" 2>&1 || true
}

## --- the nounset crash: a real package value must not trip 'unbound variable' ---
for flag in --kernel --headers --initramfs; do
   out="$( run_out "${flag}" some-real-package )"
   case "${out}" in
      *"unbound variable"*)
         fail "${flag} <value> still crashes with 'unbound variable'"
         ;;
      *)
         pass "${flag} <value> does not crash (nounset default present)"
         ;;
   esac
done

## --- a DANGEROUS option (a dangerous flavor) with the unlock UNSET must give the
## actionable "DANGEROUS option" error, NOT a bare nounset 'unbound variable' crash
## (error_dangerous_option_maybe read dist_build_unlock_dangerous_options bare --
## the exact break that had CI's kicksecure-ci-tiny-do-not-use build die at Phase 1).
dang_out="$( unset dist_build_unlock_dangerous_options; run_out --flavor kicksecure-ci-tiny-do-not-use )"
case "${dang_out}" in
   *"unbound variable"*)
      fail "dangerous flavor without unlock crashes on unbound dist_build_unlock_dangerous_options"
      ;;
   *"DANGEROUS option"*)
      pass "dangerous flavor without unlock gives the actionable DANGEROUS-option error, not a crash"
      ;;
   *)
      fail "dangerous flavor: unexpected output: ${dang_out}"
      ;;
esac

## --- --package-jobs must fail-fast on a non-integer ---
## A second, distinct bad arg (--headers '') follows it. The fix exits AT the
## package-jobs branch, so the --headers "must not be empty" error is NEVER reached;
## the pre-fix code prints the integer error, keeps parsing, and DOES reach it. So
## the '--headers' error's ABSENCE is the proof it stopped (robust -- does not
## depend on which mandatory-arg error a bare run would surface).
bad_out="$( run_out --package-jobs abc --headers '' )"
case "${bad_out}" in
   *"must be passed a whole integer"*)
      pass "--package-jobs abc reports the integer error"
      ;;
   *)
      fail "--package-jobs abc did not report the integer error"
      ;;
esac
case "${bad_out}" in
   *"must not be empty"*)
      fail "--package-jobs abc kept parsing past the error (reached --headers)"
      ;;
   *)
      pass "--package-jobs abc stops at the error (never reached --headers)"
      ;;
esac

## A valid value passes that check (no integer error; it stops later, elsewhere).
good_out="$( run_out --package-jobs 4 )"
case "${good_out}" in
   *"must be passed a whole integer"*)
      fail "--package-jobs 4 wrongly reported the integer error"
      ;;
   *)
      pass "--package-jobs 4 passes the integer check"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd arg validation."
