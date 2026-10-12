#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for calamares-bootloader-config.dist seeding grub-pc/install_devices WITHOUT
## aborting the install when the boot disk has no stable /dev/disk/by-id/ name.
##
## THE BUG IT GUARDS (install-abort regression): the per-device seed is
## `grub_pc_install_device_stable="$(get_stable_disk_id "${dev}")"`, a plain assignment under
## `set -o errexit`. If get_stable_disk_id returned non-zero when no /dev/disk/by-id symlink
## resolved to the device (virtio-blk with no serial, Xen PV /dev/xvda, ...), errexit ABORTED
## the whole bootloader-config job and failed the install. get_stable_disk_id now FALLS BACK to
## the raw device (a valid install_devices value) and returns 0, so the seed never aborts.
##
## Drives the REAL get_stable_disk_id (sourced define-only). No chroot, no root, no install.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/share/calamares/helpers/calamares-bootloader-config.dist"
else
   subject='/usr/share/calamares/helpers/calamares-bootloader-config.dist'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

# shellcheck disable=SC1090
source "${subject}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## --- Case no by-id match -> raw-device fallback, rc 0 (CANARY) --------------------------------
## A device that cannot match any /dev/disk/by-id entry drives the no-match path. CANARY: the
## pre-fix code returned non-zero + empty here, so the caller's `$(...)` aborted the install
## under errexit. get_stable_disk_id must now echo the raw device and return 0.
bogus='/dev/does-not-exist-zzzq'
rc=0; out="$(get_stable_disk_id "${bogus}")" || rc=$?
got=0; [ "${rc}" -eq 0 ] || got=1
check "get_stable_disk_id returns 0 when no by-id matches (no errexit abort)" "${got}"
got=0; [ "${out}" = "${bogus}" ] || got=1
check "get_stable_disk_id falls back to the raw device when no by-id matches" "${got}"

## --- Case contract: an EMPTY device is still a hard error ------------------------------------
## The fallback is for a real-but-unmatched device, not a missing argument; an empty device is a
## caller bug and must still fail (the seed loop only ever passes a grub-probe device).
rc=0; get_stable_disk_id "" || rc=$?
got=0; [ "${rc}" -ne 0 ] || got=1
check "get_stable_disk_id returns non-zero for an empty device (contract)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
