#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Exercise the shared release-check battery driver (release-checks.bsh) with stub
## executor/reboot/verify callbacks -- no VM. Asserts: run order (user checks, then
## one reboot, then sysmaint checks), fail-fast, the check-8 retry, and that a visual
## cross-check mismatch fails a check whose functional signal PASSED (dual-signal).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

me='battery-test'
script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${script_dir}/../dm-image-boot-tests/release-checks.bsh"
[ -r "${lib}" ] || { printf 'ERROR: release-checks.bsh not found: %s\n' "${lib}" >&2; exit 1; }
# shellcheck source=../dm-image-boot-tests/release-checks.bsh
source "${lib}"
## No real sleeps in the retry path.
RELEASE_CHECK_RETRY_SLEEP[8]=0

pass=0
fail=0
assert_eq() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s\n' "${desc}"; pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s\n  got:  [%s]\n  want: [%s]\n' "${desc}" "${got}" "${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

## --- configurable stubs -----------------------------------------------------
EXEC_LOG=''; EXEC_FAIL_NUM=''; EXEC_FLAKY_NUM=''; EXEC_FLAKY_FAILS=0; EXEC_FLAKY_SEEN=0
REBOOT_COUNT=0; REBOOT_AT=''; VERIFY_FAIL_NUM=''
reset() {
   EXEC_LOG=''; EXEC_FAIL_NUM=''; EXEC_FLAKY_NUM=''; EXEC_FLAKY_FAILS=0; EXEC_FLAKY_SEEN=0
   REBOOT_COUNT=0; REBOOT_AT=''; VERIFY_FAIL_NUM=''
}
# shellcheck disable=SC2317  ## passed by name to run_release_check_battery
stub_exec() {   ## NUM SESSION CMD TIMEOUT
   local num="$1" session="$2"
   EXEC_LOG="${EXEC_LOG}${EXEC_LOG:+ }${num}:${session}"
   [ "${num}" = "${EXEC_FAIL_NUM}" ] && return 1
   if [ "${num}" = "${EXEC_FLAKY_NUM}" ]; then
      EXEC_FLAKY_SEEN=$(( EXEC_FLAKY_SEEN + 1 ))
      [ "${EXEC_FLAKY_SEEN}" -le "${EXEC_FLAKY_FAILS}" ] && return 1
   fi
   return 0
}
# shellcheck disable=SC2317  ## passed by name to run_release_check_battery
stub_reboot() { REBOOT_COUNT=$(( REBOOT_COUNT + 1 )); REBOOT_AT="${EXEC_LOG}"; }
# shellcheck disable=SC2317  ## passed by name to run_release_check_battery
stub_verify() {
   if [ "$1" = "${VERIFY_FAIL_NUM}" ]; then
      return 1
   fi
   return 0
}
count_tok() { tr ' ' '\n' <<< "$1" | grep -c "^$2\$" || true; }

## T1: everything passes.
reset
rc=0; run_release_check_battery stub_exec stub_reboot stub_verify || rc=$?
assert_eq 'T1 battery rc'      "${rc}"          '0'
assert_eq 'T1 run order'       "${EXEC_LOG}"    '1:user 5:user 6:user 4:user 8:user 2:sysmaint 3:sysmaint'
assert_eq 'T1 one reboot'      "${REBOOT_COUNT}" '1'
assert_eq 'T1 reboot after user checks' "${REBOOT_AT}" '1:user 5:user 6:user 4:user 8:user'

## T2: functional failure at check 4 -> fail-fast, no reboot, later checks skipped.
reset; EXEC_FAIL_NUM=4
rc=0; run_release_check_battery stub_exec stub_reboot stub_verify || rc=$?
assert_eq 'T2 battery rc'      "${rc}"          '1'
assert_eq 'T2 failed num'      "${RELEASE_CHECK_FAILED_NUM}" '4'
assert_eq 'T2 stopped at 4'    "${EXEC_LOG}"    '1:user 5:user 6:user 4:user'
assert_eq 'T2 no reboot'       "${REBOOT_COUNT}" '0'

## T3: check 8 flakes twice then passes (RETRIES=3) -> overall pass, 3 attempts.
reset; EXEC_FLAKY_NUM=8; EXEC_FLAKY_FAILS=2
rc=0; run_release_check_battery stub_exec stub_reboot stub_verify || rc=$?
assert_eq 'T3 battery rc'      "${rc}"          '0'
assert_eq 'T3 check 8 tried 3x' "$(count_tok "${EXEC_LOG}" '8:user')" '3'

## T3b: check 8 fails all 3 attempts -> fail at 8.
reset; EXEC_FLAKY_NUM=8; EXEC_FLAKY_FAILS=3
rc=0; run_release_check_battery stub_exec stub_reboot stub_verify || rc=$?
assert_eq 'T3b battery rc'     "${rc}"          '1'
assert_eq 'T3b failed num'     "${RELEASE_CHECK_FAILED_NUM}" '8'
assert_eq 'T3b check 8 tried 3x' "$(count_tok "${EXEC_LOG}" '8:user')" '3'

## T4: the visual cross-check disagrees at check 6 (dual-signal). verify is
## render-first, so check 6's functional exec never runs once the screen fails.
reset; VERIFY_FAIL_NUM=6
rc=0; run_release_check_battery stub_exec stub_reboot stub_verify || rc=$?
assert_eq 'T4 battery rc'      "${rc}"          '1'
assert_eq 'T4 failed num'      "${RELEASE_CHECK_FAILED_NUM}" '6'
assert_eq 'T4 check 6 exec skipped (visual failed first)' "${EXEC_LOG}" '1:user 5:user'

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
