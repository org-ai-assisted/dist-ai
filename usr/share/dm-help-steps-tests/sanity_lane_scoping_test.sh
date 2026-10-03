#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The three globally-scoped sanity checks in build-steps.d/1100_sanity-tests must be scoped to
## THIS build's lane (binary_build_folder_dist / CHROOT_FOLDER) so a CONCURRENT build in another
## --build-slot does not false-trip them:
##   - check-stray-mounts     : match the full lane CHROOT_FOLDER in /proc/mounts, not the
##                              shared basename (basename match = fatal abort on a sibling lane)
##   - check-stray-loop-devices: warn only for a loop backing a file inside this lane; read the
##                              structured losetup BACK-FILE column (robust to '(deleted)' etc.)
##   - mount-test             : the stale device-mapper precheck errors only for a loopNpM whose
##                              backing loop is inside this lane, not any global loopNpM
##
## The REAL functions are SOURCED (1100 is source-able: was_executed gates its main()). All
## privileged calls route through ${SUDO_TO_ROOT}, so a single dispatcher stub feeds fixtures
## for cat/losetup/dmsetup/mktemp/truncate -- no root, no real loop devices, no real mounts.
## Canary: fails on the pre-lane (basename / whole-host) versions.

## Fixture / config vars (MOUNTS_FIXTURE, LOOP_BACKFILES, DMSETUP_LS, LOOP_BACK, SUDO_TO_ROOT,
## CHROOT_FOLDER, color vars) are consumed by the SOURCED 1100 functions, not statically here.
# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
subject="${dm_checkout}/build-steps.d/1100_sanity-tests"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FAIL: cannot read ${subject}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## Source the real build step WITHOUT running it (was_executed is false when sourced).
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH:-${dm_checkout}/packages/kicksecure/helper-scripts}"
# shellcheck disable=SC1090
source "${subject}"
if [ "$(type -t check-stray-mounts)" != "function" ] || [ "$(type -t mount-test)" != "function" ]; then
   printf '%s\n' "FAIL: sourcing 1100 did not expose the check functions (source-able broken?)" >&2
   exit 1
fi

## Lane under test + a decoy lane a concurrent build would own. The basename is identical.
binary_build_folder_dist="/home/user/derivative-binary/mylane"
CHROOT_FOLDER="${binary_build_folder_dist}/Kicksecure-CLI_image"
other_chroot="/home/user/derivative-binary/otherlane/Kicksecure-CLI_image"

## Message sinks: 'true' carries INFO text in these functions; 'error' aborts the build. Both
## PRINT (so the capturing subshell in run_fn sees them -- a variable set in $(...) would be lost).
# shellcheck disable=SC2317
true() { printf '%s\n' "$*"; }
# shellcheck disable=SC2317
error() { printf 'ERROR: %s\n' "$*"; exit 42; }

## Privileged-call dispatcher (SUDO_TO_ROOT). Fixtures are set per case in the globals below.
MOUNTS_FIXTURE=""        # stdin of 'cat /proc/mounts'
LOOP_BACKFILES=""        # newline list for 'losetup --list --output BACK-FILE --noheadings' (no device)
DMSETUP_LS=""            # output of 'dmsetup ls'
declare -A LOOP_BACK=()  # per-device backing file: LOOP_BACK[/dev/loop5]=/path
# shellcheck disable=SC2317
dispatch() {
   local tool="$1"; shift
   case "${tool}" in
      cat)
         printf '%s\n' "${MOUNTS_FIXTURE}"
         ;;
      losetup)
         ## With a trailing '-- /dev/loopN' it is the per-device query (mount-test); else the
         ## all-devices BACK-FILE list (check-stray-loop-devices).
         local last="${*: -1}"
         case "${last}" in
            /dev/loop*)
               printf '%s\n' "${LOOP_BACK[${last}]:-}"
               ;;
            *)
               printf '%s\n' "${LOOP_BACKFILES}"
               ;;
         esac
         ;;
      dmsetup)
         case "$1" in
            version)
               return 0
               ;;
            ls)
               printf '%s\n' "${DMSETUP_LS}"
               ;;
         esac
         ;;
      mktemp)
         printf '%s\n' "/fake/test.img"
         ;;
      truncate)
         ## Fail here so mount-test stops right AFTER the stale-dm precheck in the non-stale
         ## cases -- the distinct "could not size" error proves it got PAST the stale check.
         return 1
         ;;
      sh)
         ## 'sh -c "command -v mke2fs"' precondition -- report mke2fs present.
         return 0
         ;;
      *)
         return 0
         ;;
   esac
}
SUDO_TO_ROOT="dispatch"
## mount-test skips unless mke2fs resolves on PATH via a bare 'command -v' too (belt + braces).
export reset="" bold="" red="" cyan=""

## run_fn <fn>: run the sourced function in a subshell (so its error()/exit is contained),
## capture stdout+stderr in CAP, rc in CAP_RC.
run_fn() {
   if CAP="$( "$1" 2>&1 )"; then CAP_RC=0; else CAP_RC=$?; fi
}

## ---- check-stray-mounts: full lane path, not basename ---------------------------------------
MOUNTS_FIXTURE="/dev/mapper/x ${CHROOT_FOLDER} ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'Stray mounts detected' <<< "${CAP}"; then
   pass "check-stray-mounts: aborts on a mount inside THIS lane's CHROOT_FOLDER"
else
   fail "check-stray-mounts: did not abort on this lane's own stray mount (rc=${CAP_RC})"
fi

MOUNTS_FIXTURE="/dev/mapper/y ${other_chroot} ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 0 ]; then
   pass "check-stray-mounts: ignores a concurrent lane's mount (same basename, different path)"
else
   fail "check-stray-mounts: false-aborted on another lane's mount (basename match regressed, rc=${CAP_RC})"
fi

## ---- check-stray-loop-devices: lane-only, robust BACK-FILE parse ----------------------------
LOOP_BACKFILES="/var/swapfile
${other_chroot%/*}/otherlane.raw
${binary_build_folder_dist}/Kicksecure-CLI.raw"
run_fn check-stray-loop-devices
if grep --quiet 'Stray loop devices detected' <<< "${CAP}" \
   && grep --quiet "${binary_build_folder_dist}/Kicksecure-CLI.raw" <<< "${CAP}"; then
   pass "check-stray-loop-devices: warns about a loop backing a file in this lane"
else
   fail "check-stray-loop-devices: missed this lane's stray loop"
fi
if grep --quiet 'otherlane' <<< "${CAP}" || grep --quiet 'swapfile' <<< "${CAP}"; then
   fail "check-stray-loop-devices: leaked another lane / swapfile into the report"
else
   pass "check-stray-loop-devices: ignores other lanes and the swapfile"
fi

## A DELETED backing file in this lane (typical aborted-build leftover) is still matched.
LOOP_BACKFILES="${binary_build_folder_dist}/Kicksecure-CLI.raw (deleted)"
run_fn check-stray-loop-devices
if grep --quiet 'Stray loop devices detected' <<< "${CAP}"; then
   pass "check-stray-loop-devices: matches a '(deleted)' backing file in this lane"
else
   fail "check-stray-loop-devices: missed a '(deleted)' backing file"
fi

## Only other lanes present -> clean.
LOOP_BACKFILES="/var/swapfile
${other_chroot%/*}/otherlane.raw"
run_fn check-stray-loop-devices
if grep --quiet 'No stray loop devices in this build lane' <<< "${CAP}"; then
   pass "check-stray-loop-devices: clean when only other lanes / swapfile hold loops"
else
   fail "check-stray-loop-devices: false-positive on another lane's loop"
fi

## ---- mount-test: stale-dm precheck scoped to this lane --------------------------------------
## A loopNpM whose loop backs a file in THIS lane -> fatal "stale ... in this build lane".
DMSETUP_LS="loop5p1 (254:0)"
LOOP_BACK=(["/dev/loop5"]="${binary_build_folder_dist}/Kicksecure-CLI.raw")
run_fn mount-test
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'stale device-mapper .* in this build lane' <<< "${CAP}"; then
   pass "mount-test: aborts on a stale loopNpM backing THIS lane"
else
   fail "mount-test: did not abort on this lane's stale dm mapping (rc=${CAP_RC})"
fi

## A loopNpM for ANOTHER lane -> NOT the stale error; mount-test proceeds and fails later at the
## image step (distinct 'could not size' error), proving the stale precheck ignored the foreign dm.
DMSETUP_LS="loop6p1 (254:1)"
LOOP_BACK=(["/dev/loop6"]="${other_chroot%/*}/otherlane.raw")
run_fn mount-test
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'could not size the test image' <<< "${CAP}" \
   && ! grep --quiet 'stale device-mapper' <<< "${CAP}"; then
   pass "mount-test: ignores a concurrent lane's loopNpM (passes the stale precheck)"
else
   fail "mount-test: false-aborted on another lane's dm mapping (rc=${CAP_RC}): ${CAP}"
fi

## No dm mappings -> passes the precheck (again errors later at the stubbed image step).
DMSETUP_LS=""
LOOP_BACK=()
run_fn mount-test
if ! grep --quiet 'stale device-mapper' <<< "${CAP}"; then
   pass "mount-test: clean dm state passes the stale precheck"
else
   fail "mount-test: false stale-dm error with no mappings present"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
