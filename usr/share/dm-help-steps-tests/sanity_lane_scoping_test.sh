#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The three globally-scoped sanity checks in build-steps.d/1100_sanity-tests must be scoped to
## THIS build's lane (binary_build_folder_dist / CHROOT_FOLDER) so a CONCURRENT build in another
## --build-slot does not false-trip them:
##   - check-stray-mounts     : match /proc/mounts against the CANONICAL lane CHROOT_FOLDER with an
##                              ANCHORED (exact-or-below) match, never a substring: not the shared
##                              basename (basename match = fatal abort on a sibling lane), not a
##                              prefix-sibling ("..._image_extra"), and after resolving a trailing
##                              slash / symlink so the spelling does not matter
##   - check-stray-loop-devices: warn only for a loop backing a file inside this lane; read the
##                              structured losetup BACK-FILE column (robust to '(deleted)' etc.)
##   - mount-test             : the stale device-mapper precheck errors for a loopNpM whose backing
##                              loop is inside THIS lane, AND for an ORPHAN loopNpM with no backing
##                              loop at all (empty BACK-FILE), but NOT for another lane's live mapping
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
error() { printf '%s\n' "ERROR: $*"; exit 42; }

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

## A submount strictly BELOW the lane chroot (a build bind-mount) -> abort.
MOUNTS_FIXTURE="devpts ${CHROOT_FOLDER}/dev/pts devpts rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'Stray mounts detected' <<< "${CAP}"; then
   pass "check-stray-mounts: aborts on a submount below this lane's CHROOT_FOLDER"
else
   fail "check-stray-mounts: missed a submount below CHROOT_FOLDER (rc=${CAP_RC})"
fi

## A sibling whose path merely STARTS with the chroot path ("..._image_extra") is NOT at or below
## it and must NOT trip -- anchored match, not substring. Canary: the old 'grep -F' substring aborts.
MOUNTS_FIXTURE="/dev/mapper/z ${CHROOT_FOLDER}_extra ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 0 ]; then
   pass "check-stray-mounts: ignores a prefix-sibling path (anchored, not substring)"
else
   fail "check-stray-mounts: false-aborted on a prefix-sibling (substring match regressed, rc=${CAP_RC})"
fi

## A trailing slash on CHROOT_FOLDER must still match the kernel-canonical (slash-stripped) mount
## point. Canary: the old literal grep for 'CHROOT_FOLDER' with a trailing slash never matches the
## slash-less /proc/mounts line.
saved_chroot="${CHROOT_FOLDER}"
CHROOT_FOLDER="${saved_chroot}/"
MOUNTS_FIXTURE="/dev/mapper/x ${saved_chroot} ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'Stray mounts detected' <<< "${CAP}"; then
   pass "check-stray-mounts: canonicalizes a trailing-slash CHROOT_FOLDER before matching"
else
   fail "check-stray-mounts: trailing-slash CHROOT_FOLDER missed its own mount (rc=${CAP_RC})"
fi
CHROOT_FOLDER="${saved_chroot}"

## A symlinked CHROOT_FOLDER must resolve to the real path /proc/mounts reports. Build a REAL
## symlink (realpath consults the live FS) and point CHROOT_FOLDER through it. Canary: the old
## substring grep compares the unresolved symlink path and never matches the resolved mount line.
sym_root="$(mktemp --directory)"
## Trap-based cleanup so the temp dir is removed even if a step aborts under errexit before the
## explicit safe-rm below (e.g. mkdir/ln failing on a broken FS).
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup_sym_root() { [ -z "${sym_root:-}" ] || safe-rm --recursive --force -- "${sym_root}"; }
trap cleanup_sym_root EXIT
mkdir --parents -- "${sym_root}/real/Kicksecure-CLI_image"
ln --symbolic -- "${sym_root}/real" "${sym_root}/link"
saved_chroot="${CHROOT_FOLDER}"
CHROOT_FOLDER="${sym_root}/link/Kicksecure-CLI_image"
MOUNTS_FIXTURE="/dev/mapper/x ${sym_root}/real/Kicksecure-CLI_image ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'Stray mounts detected' <<< "${CAP}"; then
   pass "check-stray-mounts: resolves a symlinked CHROOT_FOLDER to the real mount path"
else
   fail "check-stray-mounts: symlinked CHROOT_FOLDER did not match its real mount (rc=${CAP_RC})"
fi
CHROOT_FOLDER="${saved_chroot}"
safe-rm --recursive --force -- "${sym_root}"
sym_root=""
trap - EXIT

## /proc/mounts OCTAL-ESCAPES space/tab/newline/backslash in the mount point. Rather than unescape,
## check-stray-mounts FAILS CLOSED on a CHROOT_FOLDER containing any of those, so field 2 can be
## compared verbatim without silently missing an escaped mount. Canary: a verbatim compare with no
## such guard would just not match and return 0 (fail-open) instead of aborting.
saved_chroot="${CHROOT_FOLDER}"
CHROOT_FOLDER="/home/user/derivative-binary/mylane/Foo Bar_image"
MOUNTS_FIXTURE="/dev/mapper/x ${CHROOT_FOLDER} ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'must not contain a space, tab, newline or backslash' <<< "${CAP}"; then
   pass "check-stray-mounts: fails closed on a whitespace CHROOT_FOLDER (verbatim-match precondition)"
else
   fail "check-stray-mounts: did not reject a whitespace CHROOT_FOLDER (rc=${CAP_RC}): ${CAP}"
fi
CHROOT_FOLDER='/home/user/derivative-binary/mylane/back\slash_image'
MOUNTS_FIXTURE="/dev/mapper/x ${CHROOT_FOLDER} ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'must not contain a space, tab, newline or backslash' <<< "${CAP}"; then
   pass "check-stray-mounts: fails closed on a backslash CHROOT_FOLDER (verbatim-match precondition)"
else
   fail "check-stray-mounts: did not reject a backslash CHROOT_FOLDER (rc=${CAP_RC}): ${CAP}"
fi
## A TRAILING NEWLINE must be caught on the RAW value: realpath via $() strips it from the canonical
## path, so a canon-only check would pass it while /proc/mounts records the byte as \012 (fail-open).
CHROOT_FOLDER=$'/home/user/derivative-binary/mylane/Kicksecure-CLI_image\n'
MOUNTS_FIXTURE="/dev/mapper/x /home/user/derivative-binary/mylane/Kicksecure-CLI_image ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'must not contain a space, tab, newline or backslash' <<< "${CAP}"; then
   pass "check-stray-mounts: fails closed on a trailing-newline CHROOT_FOLDER (raw-value check)"
else
   fail "check-stray-mounts: did not reject a trailing-newline CHROOT_FOLDER (rc=${CAP_RC}): ${CAP}"
fi
CHROOT_FOLDER="${saved_chroot}"

## The reject must apply to the CANONICAL path: a CLEAN-spelled CHROOT_FOLDER whose symlink resolves
## to a spaced path would otherwise slip past and then fail-open on the verbatim compare. Build a real
## symlink to a spaced directory and point CHROOT_FOLDER (clean) through it; expect a fail-closed reject.
sym_sp_root="$(mktemp --directory)"
mkdir --parents -- "${sym_sp_root}/sp ace/Kicksecure-CLI_image"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup_sym_sp() { [ -z "${sym_sp_root:-}" ] || safe-rm --recursive --force -- "${sym_sp_root}"; }
trap cleanup_sym_sp EXIT
ln --symbolic -- "${sym_sp_root}/sp ace" "${sym_sp_root}/clean"
saved_chroot="${CHROOT_FOLDER}"
CHROOT_FOLDER="${sym_sp_root}/clean/Kicksecure-CLI_image"
MOUNTS_FIXTURE="/dev/mapper/x ${sym_sp_root}/sp ace/Kicksecure-CLI_image ext4 rw 0 0"
run_fn check-stray-mounts
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'must not contain a space, tab, newline or backslash' <<< "${CAP}"; then
   pass "check-stray-mounts: rejects on the CANONICAL path when a clean symlink resolves to a space"
else
   fail "check-stray-mounts: did not reject a symlink-to-spaced-path CHROOT_FOLDER (rc=${CAP_RC}): ${CAP}"
fi
CHROOT_FOLDER="${saved_chroot}"
safe-rm --recursive --force -- "${sym_sp_root}"
sym_sp_root=""
trap - EXIT

## ---- check-stray-loop-devices: lane-only, robust BACK-FILE parse ----------------------------
LOOP_BACKFILES="/var/swapfile
${other_chroot%/*}/otherlane.raw
${binary_build_folder_dist}/Kicksecure-CLI.raw"
run_fn check-stray-loop-devices
## warn-only: it must return 0 (a warning that ABORTED would still match the grep).
if [ "${CAP_RC}" -eq 0 ] \
   && grep --quiet 'Stray loop devices detected' <<< "${CAP}" \
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
if [ "${CAP_RC}" -eq 0 ] && grep --quiet 'Stray loop devices detected' <<< "${CAP}"; then
   pass "check-stray-loop-devices: matches a '(deleted)' backing file in this lane"
else
   fail "check-stray-loop-devices: missed a '(deleted)' backing file"
fi

## Only other lanes present -> clean.
LOOP_BACKFILES="/var/swapfile
${other_chroot%/*}/otherlane.raw"
run_fn check-stray-loop-devices
if [ "${CAP_RC}" -eq 0 ] && grep --quiet 'No stray loop devices in this build lane' <<< "${CAP}"; then
   pass "check-stray-loop-devices: clean when only other lanes / swapfile hold loops"
else
   fail "check-stray-loop-devices: false-positive on another lane's loop"
fi

## ---- mount-test: stale-dm precheck scoped to this lane --------------------------------------
## A loopNpM whose loop backs a file in THIS lane -> fatal "stale ... in this build lane".
DMSETUP_LS="loop5p1 (254:0)"
LOOP_BACK=(["/dev/loop5"]="${binary_build_folder_dist}/Kicksecure-CLI.raw")
run_fn mount-test
## This case ALSO guards the loop-name strip: a greedy '%%p*' ("loop5p1" -> "loo") would key the
## backing lookup on /dev/loo (empty) and send this down the orphan path, so CAP would carry
## "orphaned: no backing loop device" instead of the lane backing file -- failing the grep below.
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'stale device-mapper' <<< "${CAP}" \
   && grep --quiet "${binary_build_folder_dist}/Kicksecure-CLI.raw" <<< "${CAP}"; then
   pass "mount-test: aborts on a stale loopNpM backing THIS lane (and strips loop5p1 -> loop5)"
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
## Mirror the other-lane case: prove the precheck was PASSED THROUGH to the image
## step (distinct 'could not size' at rc 42), not short-circuited by an early failure
## that merely happens to lack the 'stale device-mapper' text.
if [ "${CAP_RC}" -eq 42 ] && grep --quiet 'could not size the test image' <<< "${CAP}" \
   && ! grep --quiet 'stale device-mapper' <<< "${CAP}"; then
   pass "mount-test: clean dm state passes the stale precheck (reaches the image step)"
else
   fail "mount-test: false stale-dm error or did not reach the image step (rc=${CAP_RC}): ${CAP}"
fi

## An ORPHANED loopNpM whose backing /dev/loopN is gone (empty BACK-FILE) cannot be attributed to a
## lane, so it is WARNED about but is NOT fatal -- a fatal abort here would defeat lane isolation and
## over-abort when the losetup query merely failed transiently or the loop lives in another mount
## namespace (BACK-FILE reads empty in all three). mount-test proceeds and fails later at the stubbed
## image step. Canary: a lane-only check that ignores an empty backing emits no warning and this fails.
DMSETUP_LS="loop7p1 (254:2)"
LOOP_BACK=()
run_fn mount-test
if grep --quiet 'no backing loop device' <<< "${CAP}" \
   && ! grep --quiet 'in this build lane' <<< "${CAP}" \
   && grep --quiet 'could not size the test image' <<< "${CAP}"; then
   pass "mount-test: WARNS (non-fatally) about an orphaned loopNpM with no backing loop device"
else
   fail "mount-test: orphan not warned non-fatally (rc=${CAP_RC}): ${CAP}"
fi

## A whitespace-only BACK-FILE (losetup column padding on a vanished device) is treated as empty ->
## warned as an orphan, not silently skipped.
DMSETUP_LS="loop8p1 (254:3)"
LOOP_BACK=(["/dev/loop8"]="   ")
run_fn mount-test
if grep --quiet 'no backing loop device' <<< "${CAP}" \
   && ! grep --quiet 'in this build lane' <<< "${CAP}" \
   && grep --quiet 'could not size the test image' <<< "${CAP}"; then
   pass "mount-test: treats a whitespace-only BACK-FILE as an orphan (warned, not fatal)"
else
   fail "mount-test: whitespace-only BACK-FILE not warned as orphan (rc=${CAP_RC}): ${CAP}"
fi

## An orphan AND a concurrent lane's live mapping together: warn the orphan, leave the foreign backed
## mapping alone, and do NOT fatally abort.
DMSETUP_LS="loop7p1 (254:2)
loop6p1 (254:1)"
LOOP_BACK=(["/dev/loop6"]="${other_chroot%/*}/otherlane.raw")
run_fn mount-test
if grep --quiet 'loop7p1 (no backing loop device' <<< "${CAP}" \
   && ! grep --quiet 'in this build lane' <<< "${CAP}" \
   && ! grep --quiet 'loop6p1' <<< "${CAP}"; then
   pass "mount-test: warns the orphan, ignores a concurrent lane's live mapping, no fatal abort"
else
   fail "mount-test: mixed orphan + foreign-lane mapping mis-handled (rc=${CAP_RC}): ${CAP}"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
