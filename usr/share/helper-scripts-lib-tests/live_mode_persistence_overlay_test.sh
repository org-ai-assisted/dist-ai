#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## live-mode.sh gained persistent-live-overlay detection: the 'Persistent' GRUB
## submenu boots 'rd.live.overlay=LABEL=persistence:/live/overlay'. Two emitted
## variables encode it:
##   live_status_persistence_requested  'true' iff the kernel cmdline carries a
##     WHOLE-TOKEN ' rd.live.overlay=' (space-boundary). The amnesic base flag
##     'rd.live.overlay.overlayfs=1' (no '=' right after 'overlay') and any
##     substring match ('fake_rd.live.overlay=1') must NOT trip it.
##   live_status_persistence_active  'true' iff requested AND /run/overlayfs is a
##     SYMLINK (dmsquash-live symlinks it onto the persistence device when the
##     overlay engages; a plain tmpfs dir is the SILENT amnesic RAM fallback).
##
## Drives the REAL live-mode.sh as a subprocess with its env-injection hooks set
## (kernel_cmdline, run_overlayfs_is_symlink, proc_mount_contents,
## writable_fs_lists_str, livecheck_lsblk_contents) so it computes deterministically
## without touching the host, then parses the two 'var=value' lines it prints and
## asserts both. No root, no network.
##
## Sources nothing: live-mode.sh resolves its own siblings (check_runtime.bsh,
## strings.bsh) via HELPER_SCRIPTS_PATH. HELPER_SCRIPTS_REPO points both the
## subject and its siblings at a checkout, which is what the suite runner wires in
## CI; unset falls back to the installed helper-scripts.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

## live-mode.sh sources its siblings via "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/...;
## point that at the same checkout so the code under test -- not an installed copy
## -- is what runs.
HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
export HELPER_SCRIPTS_PATH

hs_base="${HELPER_SCRIPTS_PATH:-}"
live_mode_sh="${hs_base}/usr/libexec/helper-scripts/live-mode.sh"

if [ ! -r "${live_mode_sh}" ]; then
   printf '%s\n' "FATAL: helper-scripts library not readable: '${live_mode_sh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

pass_count=0
fail_count=0

## Run the REAL live-mode.sh as a subprocess with the deterministic env-injection
## hooks set, and print only its two persistence lines. writable_fs_lists_str is
## set to a bare newline so live-mode.sh skips the external get_writable_fs_lists.sh
## call; proc_mount_contents / livecheck_lsblk_contents keep the rest off the host.
run_live_mode() {
   local cmdline="$1" symlink="$2"
   env \
      HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      kernel_cmdline="${cmdline}" \
      proc_mount_contents=$'tmpfs /run tmpfs rw 0 0\n' \
      writable_fs_lists_str=$'\n' \
      livecheck_lsblk_contents='0' \
      run_overlayfs_is_symlink="${symlink}" \
      /usr/bin/bash "${live_mode_sh}" 2>/dev/null
}

## Extract the single-quoted value of a 'name=value' line from captured output.
get_var() {
   local output="$1" name="$2" line value
   value=''
   while IFS= read -r line; do
      case "${line}" in
         "${name}="*)
            value="${line#"${name}="}"
            value="${value#\'}"
            value="${value%\'}"
            printf '%s' "${value}"
            return 0
            ;;
      esac
   done <<< "${output}"
   printf '%s' '<unset>'
}

check_case() {
   local desc="$1" cmdline="$2" symlink="$3" want_requested="$4" want_active="$5"
   local output rc=0 got_requested got_active
   output="$(run_live_mode "${cmdline}" "${symlink}")" || rc=$?
   got_requested="$(get_var "${output}" 'live_status_persistence_requested')"
   got_active="$(get_var "${output}" 'live_status_persistence_active')"
   if [ "${rc}" -eq 0 ] \
      && [ "${got_requested}" = "${want_requested}" ] \
      && [ "${got_active}" = "${want_active}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${desc}: requested='${got_requested}' active='${got_active}'"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${desc}: rc=${rc} requested='${got_requested}' active='${got_active}', wanted requested='${want_requested}' active='${want_active}'"
   fi
}

## --- assertions ------------------------------------------------------------
## Requested + symlink -> overlay engaged on a real persistence device.
check_case 'LABEL overlay, /run/overlayfs symlink' \
   'rd.live.image rd.live.overlay=LABEL=persistence:/live/overlay' 'true' \
   'true' 'true'
## Requested but /run/overlayfs a plain dir -> amnesic RAM fallback, not active.
check_case 'LABEL overlay, /run/overlayfs plain dir' \
   'rd.live.image rd.live.overlay=LABEL=persistence:/live/overlay' 'false' \
   'true' 'false'
## UUID= spelling requests persistence just the same.
check_case 'UUID overlay, /run/overlayfs symlink' \
   'rd.live.image rd.live.overlay=UUID=abcd:/live/overlay' 'true' \
   'true' 'true'
## The amnesic base flag has no '=' right after 'overlay' -- must NOT match.
check_case 'overlayfs base flag does not match' \
   'rd.live.image rd.live.overlay.overlayfs=1' 'false' \
   'false' 'false'
## A parameter that merely CONTAINS 'rd.live.overlay=' as a substring -- no match.
check_case 'substring rd.live.overlay= does not match' \
   'rd.live.image fake_rd.live.overlay=1' 'true' \
   'false' 'false'
## No overlay parameter at all.
check_case 'no overlay parameter' \
   'rd.live.image' 'true' \
   'false' 'false'

printf '%s\n' ""
printf '%s\n' "===== live-mode persistence overlay: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
