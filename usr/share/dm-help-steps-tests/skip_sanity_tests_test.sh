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
case "${reuse_block}" in
   *'--skip-sanity-tests true'*)
      pass "reuse_shared_args skips sanity-tests on per-flavor rebuilds"
      ;;
   *)
      fail "reuse_shared_args no longer passes '--skip-sanity-tests true'; per-flavor rebuilds re-verify unchanged git state"
      ;;
esac

## --- Part 2: 1100_sanity-tests honors dist_build_skip_sanity_tests ----------
sanity=""
for candidate in "${DM_SANITY_TESTS:-}" "${dm_checkout}/build-steps.d/1100_sanity-tests"; do
   case "${candidate}" in
      ''|'/build-steps.d/1100_sanity-tests')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      sanity="${candidate}"
      break
   fi
done
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
      if [ "$1" != unset ]; then
         dist_build_skip_sanity_tests="$1"
      fi
      eval "guard_fn() { ${guard}
         printf '%s\n' FELL_THROUGH
      }"
      guard_fn
   )
}

case "$(run_guard true)" in
   *FELL_THROUGH*)
      fail "1100 main() did NOT short-circuit on dist_build_skip_sanity_tests=true"
      ;;
   *)
      pass "1100 main() returns early when dist_build_skip_sanity_tests=true"
      ;;
esac
case "$(run_guard unset)" in
   *FELL_THROUGH*)
      pass "1100 main() runs the checks when the flag is unset"
      ;;
   *)
      fail "1100 main() short-circuited with the flag UNSET -- it would always skip"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: --skip-sanity-tests wiring and guard."
