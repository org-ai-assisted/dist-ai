#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## check-stray-loop-devices (build-steps.d/1100_sanity-tests) warns about leftover loop devices
## from a previously aborted build. With per-lane concurrent builds (--build-slot / dist_build_slot),
## a CONCURRENT build in another lane legitimately holds loop devices that are none of this build's
## business -- the pre-lane check scanned ALL of `losetup --all` and printed a scary "stray loop
## devices detected" block for them, which reads as a failure in a verbose (set -x) build log.
##
## The function must now warn ONLY about loops backing a file inside THIS build's lane
## (binary_build_folder_dist), ignoring /var/swapfile and other lanes' loops. The REAL function is
## extracted + sourced; `losetup` + SUDO_TO_ROOT are stubbed (no root, no real loops) and `true`
## is overridden as an output sink so the function's informational branch is observable.
## Canary: fails on the pre-lane whole-host scan.

## File-wide: LOSETUP_OUT is a per-call prefix assignment to the function under test, read by the
## `losetup` stub; shellcheck sees only the stub's read, not the caller's assignment.
# shellcheck disable=SC2154
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
sanity="${dm_checkout}/build-steps.d/1100_sanity-tests"
if [ ! -r "${sanity}" ]; then
   printf '%s\n' "FAIL: cannot read ${sanity}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## Extract just the function (1100_sanity-tests is a build step, not sourceable). Its body has no
## bare '}' line until its own close, so the range sed is exact.
fn="$(sed -n '/^check-stray-loop-devices()/,/^}/p' -- "${sanity}")"
if ! grep --quiet 'binary_build_folder_dist' <<< "${fn}"; then
   fail "extracted function does not reference binary_build_folder_dist -- extraction wrong or not lane-aware"
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
   exit 1
fi
eval "${fn}"

## Lane under test, plus a decoy lane a concurrent build would own.
# shellcheck disable=SC2034  # read by the sourced function
binary_build_folder_dist="/home/user/derivative-binary/mylane"
# shellcheck disable=SC2034  # emptied so the stub `losetup` function is what the function calls
SUDO_TO_ROOT=""

## `true "INFO: ..."` is the dm idiom for a message visible only under set -x; override it as a
## sink so the test can see which branch the REAL function took.
true() { printf '%s\n' "$*"; }

## Stub losetup: emit whatever the current case set.
losetup() { printf '%s\n' "${LOSETUP_OUT}"; }

run_check() { LOSETUP_OUT="$1" check-stray-loop-devices 2>&1; }

## Case A: a loop in OUR lane + a decoy in another lane + the swapfile.
out="$(run_check "/dev/loop0: [64769]:111 (/var/swapfile)
/dev/loop1: [64769]:222 (/home/user/derivative-binary/otherlane/Kicksecure-CLI_image)
/dev/loop2: [64769]:333 (/home/user/derivative-binary/mylane/Kicksecure-CLI_image)")"
if grep --quiet 'Stray loop devices detected' <<< "${out}" \
   && grep --quiet '/home/user/derivative-binary/mylane/Kicksecure-CLI_image' <<< "${out}"; then
   pass "warns about a stray loop inside this build's lane"
else
   fail "did not warn about our own lane's stray loop"
fi
if grep --quiet 'otherlane' <<< "${out}" || grep --quiet '/var/swapfile' <<< "${out}"; then
   fail "leaked another lane's loop / the swapfile into the stray-device report"
else
   pass "ignores another lane's loop and the swapfile"
fi

## Case A2: a DELETED backing file in our lane (the typical aborted-build leftover).
## The ' (deleted)' suffix must not defeat the parse (greedy ##*( took the wrong paren).
out="$(run_check "/dev/loop3: [64769]:444 (/home/user/derivative-binary/mylane/Kicksecure-CLI_image (deleted))")"
if grep --quiet 'Stray loop devices detected' <<< "${out}" \
   && grep --quiet 'mylane/Kicksecure-CLI_image' <<< "${out}"; then
   pass "detects a DELETED backing file in this lane (greedy-paren parse bug fixed)"
else
   fail "missed a '(deleted)' stray loop in this lane"
fi

## Case B: only a decoy lane + swapfile -> no stray in OUR lane.
out="$(run_check "/dev/loop0: [64769]:111 (/var/swapfile)
/dev/loop1: [64769]:222 (/home/user/derivative-binary/otherlane/Kicksecure-CLI_image)")"
if grep --quiet 'No stray loop devices in this build lane' <<< "${out}"; then
   pass "reports clean when only other lanes / swapfile hold loops"
else
   fail "false-positive: flagged another lane's loop as this build's stray"
fi

## Case C: nothing attached.
out="$(run_check "")"
if grep --quiet 'No stray loop devices in this build lane' <<< "${out}"; then
   pass "reports clean when no loop devices are attached"
else
   fail "did not report clean on empty losetup output"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
