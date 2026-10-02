#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 45_debugging must emit ONLY grub.cfg comment lines, even when a GRUB_*
## value spans multiple lines.
##
## grub-probe --target=device returns one device PER LINE for a multi-device
## btrfs, so GRUB_DEVICE and GRUB_DEVICE_BOOT carry an embedded newline there.
## A raw newline inside an emitted '## ...' comment turns the continuation into
## a bare grub command, grub.cfg fails to parse, and update-grub breaks -- which
## is exactly what happened on a two-device btrfs host.
##
## stdout of this generator is appended verbatim to grub.cfg, so the property is
## "every emitted line is a comment". Asserted against the multi-device case.
##
## No root, no network, no grub-mkconfig.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v GRUB_LIVE_REPO ] || GRUB_LIVE_REPO=""
[ -v TMP ] || TMP=/tmp

if [ -n "${GRUB_LIVE_REPO}" ]; then
   generator="${GRUB_LIVE_REPO}/etc/grub.d/45_debugging"
else
   generator='/etc/grub.d/45_debugging'
fi

if [ ! -r "${generator}" ]; then
   printf '%s\n' "FATAL: no 45_debugging generator at '${generator}'; set GRUB_LIVE_REPO" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/grub-debug-newline.XXXXXX")"

## Reached only through the EXIT trap below, which shellcheck does not connect
## to this definition.
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup_handler EXIT

stub_dir="${work_dir}/stub"
mkdir --parents -- "${stub_dir}"

## Force the chroot-only code path: 45_debugging emits nothing unless ischroot
## reports a chroot (its block runs only during the build), so the malformed
## multi-device output can occur only there.
printf '%s\n' '#!/bin/sh' 'exit 0' >"${stub_dir}/ischroot"
chmod 0755 -- "${stub_dir}/ischroot"

## A two-device btrfs: grub-probe emits one device per line, so these two
## GRUB_* values carry an embedded newline.
multi_device="$(printf '%s\n%s' '/dev/nvme1n1p2' '/dev/nvme0n1p2')"

output="$(env --ignore-environment \
   PATH="${stub_dir}:/usr/bin:/bin" \
   GRUB_DEVICE="${multi_device}" \
   GRUB_DEVICE_UUID="11111111-2222-3333-4444-555555555555" \
   GRUB_DEVICE_PARTUUID="66666666-7777-8888-9999-aaaaaaaaaaaa" \
   GRUB_DEVICE_BOOT="${multi_device}" \
   GRUB_DEVICE_BOOT_UUID="11111111-2222-3333-4444-555555555555" \
   GRUB_DISABLE_LINUX_UUID="" \
   GRUB_DISABLE_LINUX_PARTUUID="" \
   sh "${generator}" 2>/dev/null)" || true

fail=0

## The chroot path must have run, else this asserts nothing.
if [[ "${output}" != *'information START'* ]]; then
   printf '%s\n' "FATAL: 45_debugging emitted no debug block; chroot path not exercised" >&2
   exit 1
fi

## Every non-empty emitted line MUST begin with '##'. A line that does not is a
## leaked newline -> a bare grub command -> malformed grub.cfg: the regression.
bare_lines="$(printf '%s\n' "${output}" | grep --invert-match --extended-regexp '^(##|$)' || true)"
if [ -n "${bare_lines}" ]; then
   printf '%s\n' "FAIL: 45_debugging emitted non-comment line(s) into grub.cfg:"
   printf '%s\n' "${bare_lines}" | sed 's/^/    /'
   fail=1
else
   printf '%s\n' "PASS: 45_debugging emits only grub.cfg comment lines for a multi-device GRUB_DEVICE"
fi

exit "${fail}"
