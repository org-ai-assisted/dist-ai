#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Real-kernel e2e: drive the ACTUAL swap-file-creator do_start / do_stop (via
## the shared drive helper, with REAL external commands) against a loop-backed
## ext4 and a loop-backed btrfs filesystem, as root, and assert the swap is
## genuinely enabled (swapon --show), the file is mode 0600, and do_stop tears
## it down and removes it. This is the acceptance a shim/unit test cannot give:
## the kernel actually accepts the produced swap file (right perms, no holes,
## btrfs nocow).
##
## Root + loop devices required; the runner gates that and exits 77 when absent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
drive="${tool_dir}/../swap-file-creator-tests/swap_file_creator_drive.sh"

[ -v SWAP_FILE_CREATOR_REPO ] || SWAP_FILE_CREATOR_REPO=""
if [ -n "${SWAP_FILE_CREATOR_REPO}" ]; then
   subject="${SWAP_FILE_CREATOR_REPO}/usr/share/swap-file-creator/swap-file-creator"
else
   subject='/usr/share/swap-file-creator/swap-file-creator'
fi
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -n "${HELPER_SCRIPTS_PATH}" ]; then
   hs_bin="${HELPER_SCRIPTS_PATH}/usr/bin"
   libdir="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts"
else
   hs_bin='/usr/bin'
   libdir='/usr/libexec/helper-scripts'
fi

for req in "${subject}:subject" "${libdir}/check_runtime.bsh:check_runtime.bsh" "${drive}:drive helper"; do
   if [ ! -r "${req%%:*}" ]; then
      printf '%s\n' "FATAL: ${req#*:} not readable at '${req%%:*}'" >&2
      exit 1
   fi
done
# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"
## These tools are REQUIRED for the e2e (not optional): absence on a root VM lane
## is an environment bug -> FATAL, never a silent skip (R-220).
for dep in mkfs.ext4 mkfs.btrfs mkswap swapon swapoff losetup mount umount btrfs bc safe-rm; do
   if ! has "${dep}"; then
      printf '%s\n' "FATAL: required tool '${dep}' not found -- provision it on this VM lane" >&2
      exit 1
   fi
done

export SUBJECT="${subject}"
export HELPER_SCRIPTS_PATH
export PATH="${hs_bin}:${PATH}"

## Cleanup: tear down anything still live, even on an assertion failure midway.
enabled_swaps=()
mounts=()
images=()
cleanup() {
   local s m i
   for s in "${enabled_swaps[@]}"; do swapoff "${s}" 2>/dev/null || true; done
   for m in "${mounts[@]}"; do umount "${m}" 2>/dev/null || true; done
   for i in "${images[@]}"; do safe-rm -f -- "${i}" 2>/dev/null || true; done
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"; got="$2"; want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## True (0) if $1 is an active swap device/file right now (exact NAME match).
swap_active() {
   swapon --noheadings --raw --show=NAME | grep --fixed-strings --line-regexp -- "$1" >/dev/null
}

## Run one filesystem's create+teardown cycle. $1 label, $2 mkfs command word.
run_fs() {
   local label="$1" mkfs_cmd="$2" img mnt sf rc
   img="$(mktemp)"
   images+=( "${img}" )
   dd if=/dev/zero of="${img}" bs=1M count=320 status=none
   "${mkfs_cmd}" -q -F "${img}" 2>/dev/null || "${mkfs_cmd}" -f "${img}"
   mnt="$(mktemp --directory)"
   mount -o loop "${img}" "${mnt}"
   mounts+=( "${mnt}" )
   sf="${mnt}/swapfile"

   ## do_start enables the swap for real.
   rc=0
   DRIVE_SWAPFILE="${sf}" DRIVE_SIZE_MB=64 DRIVE_DO_PRE_CHECK=no \
      bash "${drive}" start >/dev/null 2>&1 || rc=$?
   enabled_swaps+=( "${sf}" )
   check "(${label}) do_start exit 0"              "${rc}" "0"
   check "(${label}) swap is active (swapon --show)" "$(swap_active "${sf}" && printf '%s' y || printf '%s' n)" "y"
   check "(${label}) swap file mode 0600"          "$(stat --format='%a' -- "${sf}" 2>/dev/null || printf '%s' MISSING)" "600"

   ## do_stop swapoff + removes it.
   rc=0
   DRIVE_SWAPFILE="${sf}" DRIVE_DO_PRE_CHECK=no \
      bash "${drive}" stop >/dev/null 2>&1 || rc=$?
   check "(${label}) do_stop exit 0"               "${rc}" "0"
   check "(${label}) swap no longer active"        "$(swap_active "${sf}" && printf '%s' y || printf '%s' n)" "n"
   check "(${label}) swap file removed"            "$([ -e "${sf}" ] && printf '%s' y || printf '%s' n)" "n"

   umount "${mnt}"
   safe-rm -f -- "${img}"
}

run_fs ext4 mkfs.ext4
run_fs btrfs mkfs.btrfs

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
