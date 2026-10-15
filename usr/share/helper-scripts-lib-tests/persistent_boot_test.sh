#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistent-boot.sh: the writable-boot helper for a persistent live overlay.
## persistent_boot_cmdline normalizes the realized kernel cmdline (drops the
## bootloader-injected + overlay/luks tokens, re-adds the canonical persistence
## overlay and optional LUKS uuid). persistent_boot_write_grub_cfg emits a
## grub.cfg that boots every kernel pair present, version-sorted newest-first,
## with an amnesic overlay-reset entry.
##
## Sources the INSTALLED persistent-boot.sh by default; HELPER_SCRIPTS_REPO points
## it at a checkout (how the suite runner wires CI). Pure logic: no root, no
## device, no network. grub SYNTAX is validated at the ISO/boot-test level.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   persistent_boot_sh_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/persistent-boot.sh"
else
   persistent_boot_sh_path='/usr/libexec/helper-scripts/persistent-boot.sh'
fi

if [ ! -r "${persistent_boot_sh_path}" ]; then
   printf '%s\n' "FATAL: persistent-boot.sh not readable at '${persistent_boot_sh_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${persistent_boot_sh_path}"

for fn in persistent_boot_cmdline persistent_boot_write_grub_cfg; do
   if [ ! "$(type -t "${fn}")" = 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${persistent_boot_sh_path}' defined no '${fn}' function" >&2
      exit 1
   fi
done

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1"; }

workdir="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

cmdline_file="${workdir}/cmdline"
export PERSISTENT_BOOT_CMDLINE_FILE="${cmdline_file}"

## --- persistent_boot_cmdline ------------------------------------------------

## A1: strip BOOT_IMAGE/initrd, keep the base live tokens, append the canonical
## overlay, no LUKS uuid when none is given.
printf '%s\n' 'BOOT_IMAGE=/live/vmlinuz root=live:CDLABEL=DM_LIVE rd.live.dir=live rd.live.squashimg=filesystem.squashfs rd.live.overlay.overlayfs=1 initrd=/live/initrd.img quiet' > "${cmdline_file}"
out="$(persistent_boot_cmdline persistence)"
if [[ "${out}" != *"BOOT_IMAGE="* ]] \
   && [[ "${out}" != *"initrd=/live/initrd.img"* ]] \
   && [[ "${out}" == *"root=live:CDLABEL=DM_LIVE"* ]] \
   && [[ "${out}" == *"rd.live.overlay.overlayfs=1"* ]] \
   && [[ "${out}" == *"quiet"* ]] \
   && [[ "${out}" == *"rd.live.overlay=LABEL=persistence:/live/overlay"* ]] \
   && [[ "${out}" != *"rd.luks.uuid="* ]]; then
   pass "cmdline: strips boot/initrd, keeps base, appends overlay, no luks"
else
   fail "cmdline A1 wrong: '${out}'"
fi

## A2: a LUKS uuid is appended when given.
out="$(persistent_boot_cmdline persistence 40e273d7-4e63-4459-b16f-ba3df4374905)"
if [[ "${out}" == *"rd.live.overlay=LABEL=persistence:/live/overlay"* ]] \
   && [[ "${out}" == *"rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905"* ]]; then
   pass "cmdline: appends luks uuid when encrypted"
else
   fail "cmdline A2 wrong: '${out}'"
fi

## A3: a pre-existing overlay/luks token is normalized, never duplicated.
printf '%s\n' 'root=live:CDLABEL=DM_LIVE rd.live.overlay=LABEL=stale:/old rd.luks.uuid=deadbeef quiet' > "${cmdline_file}"
out="$(persistent_boot_cmdline persistence 40e273d7-4e63-4459-b16f-ba3df4374905)"
overlay_count="$(printf '%s\n' "${out}" | grep --only-matching 'rd.live.overlay=LABEL=' | wc --lines)"
luks_count="$(printf '%s\n' "${out}" | grep --only-matching 'rd.luks.uuid=' | wc --lines)"
if [ "${overlay_count}" = "1" ] && [ "${luks_count}" = "1" ] \
   && [[ "${out}" != *"stale"* ]] && [[ "${out}" != *"deadbeef"* ]] \
   && [[ "${out}" == *"rd.live.overlay=LABEL=persistence:/live/overlay"* ]]; then
   pass "cmdline: normalizes a pre-existing overlay/luks token (no duplication)"
else
   fail "cmdline A3 wrong (overlay=${overlay_count} luks=${luks_count}): '${out}'"
fi

## --- persistent_boot_write_grub_cfg -----------------------------------------

boot_dir="${workdir}/boot"
mkdir --parents -- "${boot_dir}"
touch -- "${boot_dir}/vmlinuz-6.1.0-9"
touch -- "${boot_dir}/initrd.img-6.1.0-9"
touch -- "${boot_dir}/vmlinuz-6.1.0-10"
touch -- "${boot_dir}/initrd.img-6.1.0-10"
## An unpaired kernel (no matching initrd) must be excluded.
touch -- "${boot_dir}/vmlinuz-6.1.0-11-nopair"

test_cmdline='root=live:CDLABEL=DM_LIVE rd.live.overlay.overlayfs=1 rd.live.overlay=LABEL=persistence:/live/overlay'
if persistent_boot_write_grub_cfg "${boot_dir}" "${test_cmdline}"; then
   pass "write_grub_cfg: returns 0 with kernels present"
else
   fail "write_grub_cfg: returned nonzero with kernels present"
fi
cfg="${boot_dir}/grub/grub.cfg"

if [ -r "${cfg}" ]; then
   pass "write_grub_cfg: wrote grub/grub.cfg"
else
   fail "write_grub_cfg: no grub.cfg written"
fi

if grep --quiet --line-regexp 'set default=0' "${cfg}"; then
   pass "write_grub_cfg: sets default=0"
else
   fail "write_grub_cfg: no 'set default=0'"
fi

## Version-sort: the newest kernel's entry must precede the older one's.
line_new="$(grep --line-number 'vmlinuz-6.1.0-10 ' "${cfg}" | head --lines 1 | cut --delimiter=: --fields=1)"
line_old="$(grep --line-number 'vmlinuz-6.1.0-9 ' "${cfg}" | head --lines 1 | cut --delimiter=: --fields=1)"
if [ -n "${line_new}" ] && [ -n "${line_old}" ] && [ "${line_new}" -lt "${line_old}" ]; then
   pass "write_grub_cfg: version-sorted newest-first (6.1.0-10 before 6.1.0-9)"
else
   fail "write_grub_cfg: not version-sorted (new=${line_new} old=${line_old})"
fi

if ! grep --quiet 'nopair' "${cfg}"; then
   pass "write_grub_cfg: excludes an unpaired kernel"
else
   fail "write_grub_cfg: included an unpaired kernel"
fi

if grep --quiet 'rd.live.overlay.reset=1' "${cfg}"; then
   pass "write_grub_cfg: emits an amnesic overlay-reset entry"
else
   fail "write_grub_cfg: no reset entry"
fi

if grep --quiet --fixed-strings "${test_cmdline}" "${cfg}"; then
   pass "write_grub_cfg: embeds the given cmdline"
else
   fail "write_grub_cfg: cmdline missing from entries"
fi

## B: an empty boot dir yields no config and a nonzero return.
empty_dir="${workdir}/empty"
mkdir --parents -- "${empty_dir}"
empty_rc=0
persistent_boot_write_grub_cfg "${empty_dir}" "${test_cmdline}" || empty_rc=$?
if [ "${empty_rc}" -ne 0 ] && [ ! -e "${empty_dir}/grub/grub.cfg" ]; then
   pass "write_grub_cfg: returns nonzero and writes nothing on an empty boot dir"
else
   fail "write_grub_cfg: empty dir not handled (rc=${empty_rc})"
fi

printf '%s\n' ""
printf '%s\n' "===== persistent-boot: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
