#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Two selectors in help-steps/build-step-helpers.bsh (used by
## 3500_install-packages), each of whose wrong answer breaks the image:
##   - newest-kernel-version: the kernel dracut rebuilds the initramfs for. A
##     byte-order pick takes 'vmlinuz-6.1.0-9' over 'vmlinuz-6.12.0-1' ('.' <
##     digit under LC_ALL=C), i.e. the OLD kernel.
##   - select-grub-probe-device: the device whose UUID replaces root=/dev/mapper.
##     An EMPTY '/boot' probe result must not win over a valid root probe.
##
## Both are SOURCED and called directly; the canary redefines the buggy forms in
## a subshell. Needs no root, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
lib="${dm_checkout}/help-steps/build-step-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## A /boot listing in ls -1 (LC_ALL=C) order: the OLD kernel sorts first by byte,
## so a byte-first pick would take it; version-sort must take the newer one.
boot_listing="$( printf '%s\n' \
   'System.map-6.1.0-9-amd64' \
   'config-6.1.0-9-amd64' \
   'initrd.img-6.1.0-9-amd64' \
   'vmlinuz-6.1.0-9-amd64' \
   'vmlinuz-6.12.0-1-amd64' )"

## --- newest-kernel-version -------------------------------------------------
if [ "$( newest-kernel-version "${boot_listing}" )" = "6.12.0-1-amd64" ]; then
   pass 'newest-kernel-version picks the newest kernel by version, not byte order'
else
   fail "newest-kernel-version: expected '6.12.0-1-amd64'"
fi

if [ "$( newest-kernel-version "$( printf 'vmlinuz-6.1.0-9-amd64\n' )" )" = "6.1.0-9-amd64" ]; then
   pass 'newest-kernel-version returns the sole kernel and strips vmlinuz-'
else
   fail 'newest-kernel-version single: expected 6.1.0-9-amd64'
fi

if [ -z "$( newest-kernel-version "$( printf 'config-x\ninitrd.img-x\n' )" )" ]; then
   pass 'newest-kernel-version is empty when there is no vmlinuz'
else
   fail 'newest-kernel-version no-kernel: expected empty'
fi

## --- select-grub-probe-device ----------------------------------------------
if [ "$( select-grub-probe-device /dev/mapper/loop0p2 /dev/mapper/loop0p2 )" = "/dev/mapper/loop0p2" ]; then
   pass 'select-grub-probe-device: equal probes return that device'
else
   fail 'select equal: expected /dev/mapper/loop0p2'
fi

if [ "$( select-grub-probe-device /dev/mapper/loop0p2 /dev/mapper/loop0p3 )" = "/dev/mapper/loop0p3" ]; then
   pass 'select-grub-probe-device: differing probes prefer a non-empty /boot'
else
   fail 'select differ: expected /dev/mapper/loop0p3'
fi

if [ "$( select-grub-probe-device /dev/mapper/loop0p2 '' )" = "/dev/mapper/loop0p2" ]; then
   pass 'select-grub-probe-device: an empty /boot probe falls back to the root probe'
else
   fail 'select empty-boot: expected /dev/mapper/loop0p2'
fi

## --- CANARY: the buggy forms are actually caught ---------------------------
## Byte-first kernel pick returns the OLD kernel; always-/boot device pick
## returns empty when the /boot probe failed.
buggy_kernel="$(
   newest-kernel-version() {
      printf '%s\n' "$1" | grep 'vmlinuz' | sed --quiet '1p' | sed 's/^vmlinuz-//'
   }
   newest-kernel-version "${boot_listing}"
)"
buggy_device="$(
   select-grub-probe-device() {
      if [ "$1" = "$2" ]; then
         printf '%s\n' "$1"
      else
         printf '%s\n' "$2"
      fi
   }
   select-grub-probe-device /dev/mapper/loop0p2 ''
)"
if [ "${buggy_kernel}" = "6.1.0-9-amd64" ] && [ -z "${buggy_device}" ]; then
   pass 'canary: byte-first kernel pick and always-/boot device pick are caught'
else
   fail "canary broken: kernel='${buggy_kernel}' device='${buggy_device}'"
fi

summary_line="===== install-packages selectors: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
