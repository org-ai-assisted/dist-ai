#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for calamares-bootloader-config.dist seeding grub-pc/install_devices WITHOUT
## aborting the install when the boot disk has no stable /dev/disk/by-id/ name.
##
## THE BUG IT GUARDS (install-abort regression): the per-device seed was
## `grub_pc_install_device_stable="$(get_stable_disk_id "${dev}")"`, a plain assignment under
## `set -o errexit`. get_stable_disk_id returns non-zero when no /dev/disk/by-id symlink
## resolves to the device (virtio-blk with no serial, Xen PV /dev/xvda, ...), so errexit
## ABORTED the whole bootloader-config job and failed the install. The raw grub-probe device is
## a valid install_devices value and was the historical seed. grub_pc_seed_device now falls back
## to it and always returns 0, so the caller's command substitution cannot trip errexit.
##
## Drives the REAL grub_pc_seed_device / get_stable_disk_id (sourced define-only). No chroot,
## no root, no install.

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

## --- Case REAL no-match: the real get_stable_disk_id fails -> raw-device fallback, rc 0 -------
## A device that cannot match any /dev/disk/by-id entry exercises the REAL function's failure
## path feeding the fallback. CANARY: the pre-fix call site (bare get_stable_disk_id) would
## yield empty + non-zero here and, under errexit, abort the install.
bogus='/dev/does-not-exist-zzzq'
rc=0; out="$(grub_pc_seed_device "${bogus}")" || rc=$?
got=0; [ "${rc}" -eq 0 ] || got=1
check "grub_pc_seed_device returns 0 when no by-id exists (no errexit abort)" "${got}"
got=0; [ "${out}" = "${bogus}" ] || got=1
check "grub_pc_seed_device falls back to the raw device when no by-id exists" "${got}"

## --- Case real contract: get_stable_disk_id fails on an empty / unmatched arg ----------------
rc=0; get_stable_disk_id "" || rc=$?
got=0; [ "${rc}" -ne 0 ] || got=1
check "get_stable_disk_id returns non-zero for an empty device (contract)" "${got}"

## --- Case by-id present: fallback prefers the stable id ---------------------------------------
## Stub get_stable_disk_id success so the by-id branch is deterministic (a real by-id match is
## host-dependent). grub_pc_seed_device must return the stable id, not the raw device.
# shellcheck disable=SC2317  ## called indirectly by grub_pc_seed_device
get_stable_disk_id() {
   printf '%s\n' "/dev/disk/by-id/stub-ata-DISK"
}
rc=0; out="$(grub_pc_seed_device /dev/sda)" || rc=$?
got=0; [ "${rc}" -eq 0 ] && [ "${out}" = "/dev/disk/by-id/stub-ata-DISK" ] || got=1
check "grub_pc_seed_device returns the stable by-id when one exists" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
