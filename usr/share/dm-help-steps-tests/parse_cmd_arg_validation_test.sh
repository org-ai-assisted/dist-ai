#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for parse-cmd arg-handling:
##   - --kernel / --headers / --initramfs read BUILD_*_PKGS to append to it, but
##     parse-cmd runs under nounset BEFORE help-steps/variables defaults those, so a
##     REAL value (not 'none'/empty) crashed with 'unbound variable'. Guarded with a
##     :- default.
##   - a DANGEROUS flavor with the unlock unset must give the actionable "DANGEROUS
##     option" error, not a bare nounset crash (error_dangerous_option_maybe read
##     dist_build_unlock_dangerous_options with a :- default).
##   - --package-jobs must fail-fast (exit) on a non-integer value; a whole integer
##     (including 0) is accepted at parse time.
##   - value-taking flags must reject a MISSING value before 'shift 2' (a trailing
##     bare flag otherwise crashes 'shift count out of range' under errexit).
##     --vmram/--vram/--vmsize also reject an explicit empty value; the others
##     (--only-packages/--file-system/--hostname/--retry-{max,wait,before,after})
##     ACCEPT an explicit empty value, which is meaningful downstream.
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

## run_out ignores rc, so a CRASH (nounset 'unbound variable', or errexit tripping on
## 'shift count out of range') surfaces ONLY in the captured text, never as a non-zero
## exit. A crash must therefore be recognized from its message, or an assertion whose
## pass branch is "the expected error is absent" would read a crash as success -- masking
## a crash in exactly the path the assertion protects. Single source for the markers.
has_crash_signature() {
   case "$1" in
      *"unbound variable"*|*"shift count out of range"*)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

## Verdict for a '--flag ""' run (explicit empty value): a crash is NOT a clean accept;
## 'requires a' is a wrongful rejection; anything else accepted the empty value.
## Empty output is anomalous, NOT acceptance: a clean accept lets parsing CONTINUE to the
## downstream mandatory-arg error ("Missing '--arch' option!"), which is non-empty. run_out
## discards rc, so a hypothetical silent (no-message) rejection would otherwise read as a
## pass -- treat empty output as its own verdict and fail it.
classify_empty_value_out() {
   if has_crash_signature "$1"; then
      printf '%s' "crash"
      return
   fi
   case "$1" in
      "")
         printf '%s' "empty"
         ;;
      *"requires a"*)
         printf '%s' "rejected"
         ;;
      *)
         printf '%s' "accepted"
         ;;
   esac
}

## Verdict for the '--package-jobs 0 --headers ""' run: 0 is a whole integer, so parse-cmd
## must ACCEPT it and CONTINUE to the trailing mandatory-empty '--headers ""' error
## ('must not be empty'). The integer error means 0 was wrongly rejected at parse; a crash
## is not acceptance; a missing downstream error means parsing never continued.
classify_package_jobs_zero_out() {
   if has_crash_signature "$1"; then
      printf '%s' "crash"
      return
   fi
   case "$1" in
      *"must be passed a whole integer"*)
         printf '%s' "rejected-at-parse"
         ;;
      *"must not be empty"*)
         printf '%s' "accepted-continued"
         ;;
      *)
         printf '%s' "unexpected"
         ;;
   esac
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
## A second, distinct bad arg (--headers '') follows it. parse-cmd exits AT the
## package-jobs branch, so the --headers "must not be empty" error is NEVER reached.
## The '--headers' error's ABSENCE is the proof it stopped (robust -- does not
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

## --- --package-jobs 0 is a whole integer and accepted at parse time -----------
## The parse-time check accepts a whole integer (^(0|[1-9][0-9]*)$), so 0 passes
## here (any semantic rejection of 0 happens later, elsewhere). The trailing
## '--headers ""' is a SECOND, downstream mandatory-empty error; its PRESENCE
## positively proves 0 was accepted and parsing CONTINUED past the package-jobs
## branch. Keying the pass on "no integer error" alone would also hold on a crash
## or any other early error, wrongly reading it as acceptance.
zero_out="$( run_out --package-jobs 0 --headers '' )"
case "$( classify_package_jobs_zero_out "${zero_out}" )" in
   accepted-continued)
      pass "--package-jobs 0 is accepted at parse time (parsing continued to --headers)"
      ;;
   rejected-at-parse)
      fail "--package-jobs 0 was rejected at parse time (the whole-integer check accepts 0)"
      ;;
   crash)
      fail "--package-jobs 0 crashed instead of being accepted at parse time: ${zero_out}"
      ;;
   *)
      fail "--package-jobs 0: expected accept-then-stop at the --headers error, got: ${zero_out}"
      ;;
esac

## --- --vmram / --vram / --vmsize: a trailing bare flag gives the actionable error,
## not a 'shift count out of range' crash (the empty-value check must run BEFORE
## 'shift 2'). The pre-fix order shifted first, so shift died under errexit before
## the message printed. ---
for flag in --vmram --vram --vmsize; do
   last_out="$( run_out "${flag}" )"
   case "${last_out}" in
      *"You forgot to specify"*)
         pass "${flag} as last arg gives the actionable error, not a shift crash"
         ;;
      *)
         fail "${flag} as last arg did not give the actionable error: ${last_out}"
         ;;
   esac
done

## --- the same shift-before-check class in the other value-taking options: a
## trailing bare flag must give the actionable "requires a ..." error, not a raw
## 'shift count out of range' crash. ---
for flag in --only-packages --file-system --hostname --retry-max --retry-wait --retry-before --retry-after -t --tag -r --ref; do
   bare_out="$( run_out "${flag}" )"
   case "${bare_out}" in
      *"requires a"*)
         pass "${flag} as last arg gives the actionable error, not a shift crash"
         ;;
      *)
         fail "${flag} as last arg did not give the actionable error: ${bare_out}"
         ;;
   esac
done

## --- an EXPLICIT empty value ('--flag ""') must be ACCEPTED for these flags: an
## empty value is meaningful downstream (clear the list / fall back to the default /
## skip the retry hook), so only a MISSING value (trailing bare flag, above) is an
## error. Guards against re-tightening the guard from an argument-count check back
## to an emptiness check, which would reject the supported empty value. ---
for flag in --only-packages --file-system --hostname --retry-max --retry-wait --retry-before --retry-after -t --tag -r --ref; do
   empty_out="$( run_out "${flag}" "" )"
   case "$( classify_empty_value_out "${empty_out}" )" in
      accepted)
         pass "${flag} \"\" accepts an explicit empty value (not rejected at parse)"
         ;;
      rejected)
         fail "${flag} \"\" wrongly rejected an explicit empty value (meaningful downstream)"
         ;;
      crash)
         fail "${flag} \"\" crashed instead of accepting an explicit empty value: ${empty_out}"
         ;;
      empty)
         fail "${flag} \"\" produced NO output -- cannot confirm the empty value was accepted"
         ;;
   esac
done

## --- CANARY: the crash-signature guard is load-bearing. run_out ignores rc, so the
## ONLY thing between a crashing parse-cmd and a false PASS is this text match. Prove it
## on synthetic inputs (the real clean parse-cmd is exercised live above): a shift-crash
## must classify as 'crash' in BOTH the empty-value and package-jobs-0 blocks, and a clean
## mandatory-arg error must not. RED here if a crash arm is ever dropped. ---
crash_stub_out='parse-cmd: line 42: shift: shift count out of range'
if has_crash_signature "${crash_stub_out}" && ! has_crash_signature "ERROR: --headers must not be empty."; then
   pass 'canary: a shift-crash is a crash signature, a clean mandatory-arg error is not'
else
   fail 'canary broken: crash-signature detection lost its teeth'
fi
if [ "$( classify_empty_value_out "${crash_stub_out}" )" = "crash" ]; then
   pass 'canary: an empty-value crash is caught, not mistaken for an accept'
else
   fail 'canary broken: an empty-value crash reached the accept branch'
fi
if [ "$( classify_empty_value_out "" )" = "empty" ]; then
   pass 'canary: empty output is not read as acceptance (run_out discards rc)'
else
   fail 'canary broken: empty output was read as an accept'
fi
if [ "$( classify_package_jobs_zero_out "${crash_stub_out}" )" = "crash" ]; then
   pass 'canary: a --package-jobs 0 crash is caught, not mistaken for acceptance'
else
   fail 'canary broken: a --package-jobs 0 crash reached the accept branch'
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: parse-cmd arg validation."
