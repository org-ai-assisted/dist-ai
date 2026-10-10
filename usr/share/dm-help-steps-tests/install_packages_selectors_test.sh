#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## newest-kernel-version in help-steps/misc-helpers.bsh (used by
## 3500_install-packages): the kernel dracut rebuilds the initramfs for. A
## byte-order pick takes 'vmlinuz-6.1.0-9' over 'vmlinuz-6.12.0-1' ('.' < digit
## under LC_ALL=C), i.e. the OLD kernel.
##
## (The grub-probe device selection is no longer a function -- it is an inline
## prefer-non-empty-/boot branch in 3500_install-packages -- so it is not a
## sourceable unit and is not covered here.)
##
## SOURCED and called directly; the canary redefines the buggy form in a
## subshell. Needs no root, no build.

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
lib="${dm_checkout}/help-steps/misc-helpers.bsh"
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

if [ "$( newest-kernel-version "$( printf '%s\n' "vmlinuz-6.1.0-9-amd64" )" )" = "6.1.0-9-amd64" ]; then
   pass 'newest-kernel-version returns the sole kernel and strips vmlinuz-'
else
   fail 'newest-kernel-version single: expected 6.1.0-9-amd64'
fi

if [ -z "$( newest-kernel-version "$( printf '%s\n' "config-x" "initrd.img-x" )" )" ]; then
   pass 'newest-kernel-version is empty when there is no vmlinuz'
else
   fail 'newest-kernel-version no-kernel: expected empty'
fi

## Anchored to '^vmlinuz-': a higher-versioned name that merely CONTAINS vmlinuz
## (e.g. xen-vmlinuz-*) must not outrank the real kernel.
if [ "$( newest-kernel-version "$( printf '%s\n' "xen-vmlinuz-9.9.9-amd64" "vmlinuz-6.12.0-1-amd64" )" )" = "6.12.0-1-amd64" ]; then
   pass 'newest-kernel-version ignores non-kernel names that merely contain vmlinuz'
else
   fail 'newest-kernel-version anchor: a decoy *vmlinuz* line was picked'
fi

## --- CANARY: the buggy form is actually caught -----------------------------
## A byte-first kernel pick returns the OLD kernel.
buggy_kernel="$(
   newest-kernel-version() {
      printf '%s\n' "$1" | grep 'vmlinuz' | sed --quiet '1p' | sed 's/^vmlinuz-//'
   }
   newest-kernel-version "${boot_listing}"
)"
if [ "${buggy_kernel}" = "6.1.0-9-amd64" ]; then
   pass 'canary: a byte-first kernel pick is caught'
else
   fail "canary broken: kernel='${buggy_kernel}'"
fi

summary_line="===== install-packages selectors: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
