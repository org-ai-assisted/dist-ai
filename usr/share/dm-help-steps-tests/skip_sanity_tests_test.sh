#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the '--skip-sanity-tests' optimization.
##
## dm-build-official-one runs the sanity-tests step once per flavor up front,
## then builds each flavor with './derivative-maker'. Each of those per-flavor
## builds re-ran build-steps.d/*_sanity-tests (and thus the expensive
## git_sanity_test over the parent + ~45 submodules) on UNCHANGED git state.
## The fix adds '--skip-sanity-tests true' to 'reuse_shared_args' so the
## per-flavor rebuilds skip it; 1100_sanity-tests honors the flag by returning
## from main() before any check.
##
## THE BUG IT GUARDS:
##   1. a silent revert dropping '--skip-sanity-tests true' from reuse_shared_args
##      (the per-flavor builds would re-verify again), and
##   2. 1100_sanity-tests no longer short-circuiting on the flag.
##
## Reads the REAL shipped scripts (no drift). No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## --- Part 1: dm-build-official-one wires the flag into reuse_shared_args -----
official="$(locate_help_step dm-build-official-one "${DM_BUILD_OFFICIAL_ONE:-}" "${test_dir}")" \
   || exit 1
reuse_block="$(sed -n '/^reuse_shared_args=($/,/^)$/p' -- "${official}")"
## Canary: the extraction must capture the real array, or the assertions below
## would pass vacuously on an empty string.
case "${reuse_block}" in
   *'--skip-prepare-build-machine true'*)
      pass "canary: reuse_shared_args extracted from ${official##*/}"
      ;;
   *)
      fail "could not extract reuse_shared_args; the assertion below would prove nothing"
      ;;
esac
## The flag and its value must be TWO separate array elements. A combined single
## argument -- quoted '--skip-sanity-tests true', or '--skip-sanity-tests=true' --
## would satisfy a bare substring check yet not reach derivative-maker as the
## intended switch, so reject those forms explicitly.
case "${reuse_block}" in
   *"'--skip-sanity-tests true'"*|*'"--skip-sanity-tests true"'*|*'--skip-sanity-tests=true'*)
      fail "reuse_shared_args passes the flag and value as ONE argument; they must be two separate array elements"
      ;;
   *'--skip-sanity-tests'*)
      pass "reuse_shared_args skips sanity-tests on per-flavor rebuilds (flag and value as separate elements)"
      ;;
   *)
      fail "reuse_shared_args no longer passes '--skip-sanity-tests true'; per-flavor rebuilds re-verify unchanged git state"
      ;;
esac

## --- Part 2: 1100_sanity-tests honors dist_build_skip_sanity_tests ----------
## An explicit DM_SANITY_TESTS override must be usable; never silently fall back
## to the checkout copy (that would test a DIFFERENT script than requested).
sanity=""
if [ -n "${DM_SANITY_TESTS:-}" ]; then
   if [ ! -r "${DM_SANITY_TESTS}" ]; then
      fail "DM_SANITY_TESTS override is set but not readable: ${DM_SANITY_TESTS}"
      printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
      exit 1
   fi
   sanity="${DM_SANITY_TESTS}"
elif [ -r "${dm_checkout}/build-steps.d/1100_sanity-tests" ]; then
   sanity="${dm_checkout}/build-steps.d/1100_sanity-tests"
fi
if [ -z "${sanity}" ]; then
   fail "1100_sanity-tests not found (set DM_SANITY_TESTS or DERIVATIVE_MAKER_DIR)"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi

## Extract the real skip guard from main() and drive both branches. The sed
## pattern matches the literal shell text in the file, so it stays single-quoted.
# shellcheck disable=SC2016
guard="$(sed -n '/if \[ "${dist_build_skip_sanity_tests:-}" = "true" \]; then/,/^   fi$/p' -- "${sanity}")"
case "${guard}" in
   *'return 0'*)
      pass "canary: skip guard (with 'return 0') extracted from 1100_sanity-tests"
      ;;
   *)
      fail "could not extract the skip guard; the assertions below would prove nothing"
      ;;
esac

## The guard references colour vars without ':-'; define them empty. 'return'
## requires a function context, so the guard is wrapped and a sentinel printed
## iff it does NOT short-circuit.
## bold/cyan/reset and dist_build_skip_sanity_tests are consumed by the eval'd
## guard; shellcheck cannot see eval usage.
# shellcheck disable=SC2034
run_guard() {
   (
      bold='' cyan='' reset=''
      ## Clear any inherited value so the 'unset' case is genuinely unset even if
      ## the caller exported dist_build_skip_sanity_tests=true.
      if [ "$1" = unset ]; then
         unset dist_build_skip_sanity_tests
      else
         dist_build_skip_sanity_tests="$1"
      fi
      eval "guard_fn() { ${guard}
         printf '%s\n' FELL_THROUGH
      }"
      guard_fn
   )
}

## Capture status too: if run_guard exits nonzero BEFORE printing the sentinel,
## the command substitution is empty and the bare '*' branch would misread a
## broken skip path as a pass. '|| rc=$?' keeps errexit from aborting the test.
guard_true_rc=0
guard_true_out="$(run_guard true)" || guard_true_rc=$?
if [ "${guard_true_rc}" -ne 0 ]; then
   fail "run_guard true exited ${guard_true_rc} before completing; cannot judge the skip path"
else
   case "${guard_true_out}" in
      *FELL_THROUGH*)
         fail "1100 main() did NOT short-circuit on dist_build_skip_sanity_tests=true"
         ;;
      *)
         pass "1100 main() returns early when dist_build_skip_sanity_tests=true"
         ;;
   esac
fi
guard_unset_rc=0
guard_unset_out="$(run_guard unset)" || guard_unset_rc=$?
if [ "${guard_unset_rc}" -ne 0 ]; then
   fail "run_guard unset exited ${guard_unset_rc} before completing; cannot judge the run path"
else
   case "${guard_unset_out}" in
      *FELL_THROUGH*)
         pass "1100 main() runs the checks when the flag is unset"
         ;;
      *)
         fail "1100 main() short-circuited with the flag UNSET -- it would always skip"
         ;;
   esac
fi

## --- Part 3: the guard is main()'s FIRST action, ahead of any check ---------
## Executing the extracted guard proves its LOGIC; this proves the WIRING -- a
## correct guard placed AFTER an expensive check would not save the work.
main_body="$(sed -n '/^main() {/,/^}$/p' -- "${sanity}")"
guard_line="$(printf '%s\n' "${main_body}" | grep -n 'dist_build_skip_sanity_tests' | head -n 1 | cut -d: -f1)"
check_line="$(printf '%s\n' "${main_body}" | grep -nE '^[[:space:]]*(test-wc|check-)' | head -n 1 | cut -d: -f1)"
if [ -n "${guard_line}" ] && [ -n "${check_line}" ] && [ "${guard_line}" -lt "${check_line}" ]; then
   pass "1100 main() checks dist_build_skip_sanity_tests before running any check"
else
   fail "1100 main() does not short-circuit before its checks (guard_line='${guard_line}', first_check_line='${check_line}')"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: --skip-sanity-tests wiring and guard."
