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

for fn in persistent_boot_cmdline persistent_boot_write_grub_cfg persistent_boot_safe_boot_dir; do
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
   && [[ "${out}" == *"rd.live.overlay=LABEL=persistence:/live/overlay"* ]] \
   && [[ "${out}" == *"rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905"* ]]; then
   pass "cmdline: normalizes a pre-existing overlay/luks token (no duplication)"
else
   fail "cmdline A3 wrong (overlay=${overlay_count} luks=${luks_count}): '${out}'"
fi

## A4: a pre-existing rd.live.overlay.reset is stripped (else a persistent entry
## would wipe the overlay every boot). The amnesic entry re-adds it on its own.
printf '%s\n' 'root=live:CDLABEL=DM_LIVE rd.live.overlay=LABEL=stale:/old rd.live.overlay.reset=1 quiet' > "${cmdline_file}"
out="$(persistent_boot_cmdline persistence)"
if [[ "${out}" != *"rd.live.overlay.reset"* ]] \
   && [[ "${out}" == *"rd.live.overlay=LABEL=persistence:/live/overlay"* ]]; then
   pass "cmdline: strips a pre-existing rd.live.overlay.reset"
else
   fail "cmdline A4 wrong: '${out}'"
fi

## --- persistent_boot_luks_uuid ----------------------------------------------

printf '%s\n' 'root=live rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905 quiet' > "${cmdline_file}"
uuid_rc=0
uuid_out="$(persistent_boot_luks_uuid)" || uuid_rc=$?
if [ "${uuid_rc}" -eq 0 ] && [ "${uuid_out}" = '40e273d7-4e63-4459-b16f-ba3df4374905' ]; then
   pass "luks_uuid: echoes a valid uuid, rc 0 (encrypted)"
else
   fail "luks_uuid valid wrong (rc=${uuid_rc} out='${uuid_out}')"
fi

printf '%s\n' 'root=live rd.live.overlay=LABEL=persistence:/live/overlay quiet' > "${cmdline_file}"
uuid_rc=0
uuid_out="$(persistent_boot_luks_uuid)" || uuid_rc=$?
if [ "${uuid_rc}" -eq 1 ] && [ -z "${uuid_out}" ]; then
   pass "luks_uuid: rc 1 when absent (plaintext)"
else
   fail "luks_uuid absent wrong (rc=${uuid_rc} out='${uuid_out}')"
fi

## A crafted non-UUID (grub metacharacters) must be refused, not echoed.
printf '%s\n' 'root=live rd.luks.uuid=not-a-uuid};evil quiet' > "${cmdline_file}"
uuid_rc=0
uuid_out="$(persistent_boot_luks_uuid)" || uuid_rc=$?
if [ "${uuid_rc}" -eq 2 ] && [ -z "${uuid_out}" ]; then
   pass "luks_uuid: rc 2 on a malformed/crafted value (refused)"
else
   fail "luks_uuid malformed wrong (rc=${uuid_rc} out='${uuid_out}')"
fi

## First valid uuid wins (not the last).
printf '%s\n' 'rd.luks.uuid=40e273d7-4e63-4459-b16f-ba3df4374905 rd.luks.uuid=11111111-2222-3333-4444-555555555555' > "${cmdline_file}"
uuid_rc=0
uuid_out="$(persistent_boot_luks_uuid)" || uuid_rc=$?
if [ "${uuid_rc}" -eq 0 ] && [ "${uuid_out}" = '40e273d7-4e63-4459-b16f-ba3df4374905' ]; then
   pass "luks_uuid: takes the first valid uuid"
else
   fail "luks_uuid first-wins wrong: '${uuid_out}'"
fi

## --- persistent_boot_device (test seam) -------------------------------------
dev_out="$(PERSISTENT_BOOT_DEVICE=/dev/fake-persistbootx persistent_boot_device persistbootx)"
if [ "${dev_out}" = '/dev/fake-persistbootx' ]; then
   pass "device: PERSISTENT_BOOT_DEVICE seam returns the forced device"
else
   fail "device seam wrong: '${dev_out}'"
fi

## --- persistent_boot_safe_boot_dir ------------------------------------------
## The shared chokepoint both the hook and persistence-setup use before any write:
## '<mount>/boot' must be a real directory, never a planted symlink that would
## redirect the kernel/initrd copies onto the live root fs.

## A fresh mount (no 'boot' yet): creates it and echoes the path.
sbd_fresh="${workdir}/sbd-fresh"
mkdir --parents -- "${sbd_fresh}"
sbd_rc=0
sbd_out="$(persistent_boot_safe_boot_dir "${sbd_fresh}")" || sbd_rc=$?
if [ "${sbd_rc}" -eq 0 ] && [ "${sbd_out}" = "${sbd_fresh}/boot" ] && [ -d "${sbd_fresh}/boot" ]; then
   pass "safe_boot_dir: creates and echoes '<mount>/boot' on a fresh mount"
else
   fail "safe_boot_dir fresh wrong (rc=${sbd_rc} out='${sbd_out}')"
fi

## An existing real 'boot' directory is accepted idempotently.
sbd_rc=0
sbd_out="$(persistent_boot_safe_boot_dir "${sbd_fresh}")" || sbd_rc=$?
if [ "${sbd_rc}" -eq 0 ] && [ "${sbd_out}" = "${sbd_fresh}/boot" ]; then
   pass "safe_boot_dir: idempotent on an existing real boot dir"
else
   fail "safe_boot_dir idempotent wrong (rc=${sbd_rc} out='${sbd_out}')"
fi

## REGRESSION (root arbitrary-write): a planted 'boot -> <evil>' symlink is refused
## and nothing is created in the evil target. On the pre-fix code 'mkdir --parents'
## succeeded on the link and writes escaped through it.
sbd_evil_mount="${workdir}/sbd-evil"
sbd_evil_target="${workdir}/sbd-evil-target"
mkdir --parents -- "${sbd_evil_mount}" "${sbd_evil_target}"
ln --symbolic -- "${sbd_evil_target}" "${sbd_evil_mount}/boot"
sbd_rc=0
sbd_out="$(persistent_boot_safe_boot_dir "${sbd_evil_mount}")" || sbd_rc=$?
if [ "${sbd_rc}" -eq 1 ] && [ -z "${sbd_out}" ]; then
   pass "safe_boot_dir: refuses a planted 'boot' symlink (rc 1, no path)"
else
   fail "safe_boot_dir symlink not refused (rc=${sbd_rc} out='${sbd_out}')"
fi

## A non-directory 'boot' (a regular file) is refused too.
sbd_file_mount="${workdir}/sbd-file"
mkdir --parents -- "${sbd_file_mount}"
touch -- "${sbd_file_mount}/boot"
sbd_rc=0
persistent_boot_safe_boot_dir "${sbd_file_mount}" > /dev/null 2>&1 || sbd_rc=$?
if [ "${sbd_rc}" -eq 1 ]; then
   pass "safe_boot_dir: refuses a non-directory 'boot'"
else
   fail "safe_boot_dir non-dir boot not refused (rc=${sbd_rc})"
fi

## An empty mount dir is refused (never operate on '/boot').
sbd_rc=0
persistent_boot_safe_boot_dir '' > /dev/null 2>&1 || sbd_rc=$?
if [ "${sbd_rc}" -eq 1 ]; then
   pass "safe_boot_dir: refuses an empty mount dir"
else
   fail "safe_boot_dir empty-mount not refused (rc=${sbd_rc})"
fi

## --- persistent_boot_prune --------------------------------------------------
prune_dir="${workdir}/prune"
prune_src="${workdir}/prunesrc"
mkdir --parents -- "${prune_dir}" "${prune_src}"
touch -- "${prune_dir}/vmlinuz-1.0" "${prune_dir}/initrd.img-1.0"
touch -- "${prune_dir}/vmlinuz-2.0" "${prune_dir}/initrd.img-2.0"
## Only 2.0 is still installed in the source.
touch -- "${prune_src}/vmlinuz-2.0" "${prune_src}/initrd.img-2.0"
persistent_boot_prune "${prune_dir}" "${prune_src}"
if [ ! -e "${prune_dir}/vmlinuz-1.0" ] && [ ! -e "${prune_dir}/initrd.img-1.0" ] \
   && [ -e "${prune_dir}/vmlinuz-2.0" ] && [ -e "${prune_dir}/initrd.img-2.0" ]; then
   pass "prune: drops a kernel no longer installed, keeps the current one"
else
   fail "prune: wrong set remains"
fi

## prune self-guards a symlinked boot_dir: a 'boot -> target' must not let the glob
## + safe-rm delete through it. Both callers route via safe_boot_dir, but prune must
## not be a raw destructive sink for a future caller. prune_src has no 1.0, so the
## pre-guard code would delete the link target's vmlinuz-1.0.
prune_evil="${workdir}/prune-evil-target"
mkdir --parents -- "${prune_evil}"
touch -- "${prune_evil}/vmlinuz-1.0" "${prune_evil}/initrd.img-1.0"
ln --symbolic -- "${prune_evil}" "${workdir}/prune-link"
persistent_boot_prune "${workdir}/prune-link" "${prune_src}"
if [ -e "${prune_evil}/vmlinuz-1.0" ]; then
   pass "prune: refuses a symlinked boot dir (no delete through the link)"
else
   fail "prune: deleted through a symlinked boot dir"
fi

## --- hardening: injection + misuse ------------------------------------------

## A token carrying a grub metacharacter is dropped whole (grub separates
## commands by ';'/newline/'$', never by spaces -- so what must not survive is
## the metacharacter, not a bare word). Safe tokens are kept.
printf '%s\n' "quiet;echo\$x root=live:CDLABEL=DM_LIVE rd.live.overlay.overlayfs=1" > "${cmdline_file}"
out="$(persistent_boot_cmdline persistence)"
meta_semi=";"
meta_dollar="\$"
meta_btick="\`"
if [[ "${out}" != *"${meta_semi}"* ]] && [[ "${out}" != *"${meta_dollar}"* ]] \
   && [[ "${out}" != *"${meta_btick}"* ]] && [[ "${out}" != *"echo"* ]] \
   && [[ "${out}" == *"root=live:CDLABEL=DM_LIVE"* ]] \
   && [[ "${out}" == *"rd.live.overlay.overlayfs=1"* ]]; then
   pass "cmdline: drops a grub-metacharacter token, keeps safe tokens"
else
   fail "cmdline injection-drop wrong: '${out}'"
fi

## An unsafe overlay label is refused (rc 1).
printf '%s\n' 'quiet' > "${cmdline_file}"
label_rc=0
persistent_boot_cmdline 'x; echo PWN' > /dev/null 2>&1 || label_rc=$?
if [ "${label_rc}" -eq 1 ]; then
   pass "cmdline: refuses an unsafe overlay label"
else
   fail "cmdline unsafe-label not refused (rc=${label_rc})"
fi

## A ':' in the overlay label is refused: dracut takes devspec=${overlay%%:*}, so
## 'persist:evil' would truncate to label 'persist'. ':' is valid in a general
## token but NEVER in a label for this overlay syntax.
printf '%s\n' 'quiet' > "${cmdline_file}"
colon_rc=0
persistent_boot_cmdline 'persist:evil' > /dev/null 2>&1 || colon_rc=$?
if [ "${colon_rc}" -eq 1 ]; then
   pass "cmdline: refuses a ':' in the overlay label (dracut truncation)"
else
   fail "cmdline colon-label not refused (rc=${colon_rc})"
fi

## A label that FAILS validation and carries a newline must not forge a second log
## line: the refusal is sanitized to a single line (non-printables -> '?').
printf '%s\n' 'quiet' > "${cmdline_file}"
nl_label=$'bad\nevil'
label_stderr="$(persistent_boot_cmdline "${nl_label}" 2>&1 >/dev/null || true)"
nl_lines="$(printf '%s' "${label_stderr}" | wc --lines)"
if [ "${nl_lines}" -eq 0 ] && [[ "${label_stderr}" == *'?'* ]] && [[ "${label_stderr}" != *'evil'$'\n'* ]]; then
   pass "cmdline: sanitizes a newline in the refused-label log (no forged line)"
else
   fail "cmdline label-log not sanitized (lines=${nl_lines} stderr='${label_stderr}')"
fi

## A malformed luks uuid argument is refused (rc 1), not pasted raw.
uuid_rc=0
persistent_boot_cmdline persistence 'aaaa; reboot' > /dev/null 2>&1 || uuid_rc=$?
if [ "${uuid_rc}" -eq 1 ]; then
   pass "cmdline: refuses a malformed luks uuid argument"
else
   fail "cmdline malformed-uuid-arg not refused (rc=${uuid_rc})"
fi

## A legit kernel param with '!' (acpi_osi=!) is NOT dropped (not a grub metachar).
printf '%s\n' 'quiet acpi_osi=! root=live:CDLABEL=DM_LIVE' > "${cmdline_file}"
out="$(persistent_boot_cmdline persistence)"
if [[ "${out}" == *"acpi_osi=!"* ]]; then
   pass "cmdline: keeps a legit '!' parameter"
else
   fail "cmdline dropped acpi_osi=!: '${out}'"
fi

## A source the -r test passes but cat cannot read (a directory) is refused, not
## treated as an empty/plaintext cmdline.
dir_cmdline="${workdir}/dir_as_cmdline"
mkdir --parents -- "${dir_cmdline}"
cat_rc=0
PERSISTENT_BOOT_CMDLINE_FILE="${dir_cmdline}" persistent_boot_cmdline persistence > /dev/null 2>&1 || cat_rc=$?
if [ "${cat_rc}" -eq 1 ]; then
   pass "cmdline: refuses a directory cmdline source (cat failure)"
else
   fail "cmdline dir-source not refused (rc=${cat_rc})"
fi
catl_rc=0
PERSISTENT_BOOT_CMDLINE_FILE="${dir_cmdline}" persistent_boot_luks_uuid > /dev/null 2>&1 || catl_rc=$?
if [ "${catl_rc}" -eq 2 ]; then
   pass "luks_uuid: returns 2 (ambiguous) on a directory cmdline source"
else
   fail "luks_uuid dir-source not refused as ambiguous (rc=${catl_rc})"
fi

## A symlinked boot_dir is refused.
mkdir --parents -- "${workdir}/realboot"
ln --symbolic -- "${workdir}/realboot" "${workdir}/linkboot"
sym_rc=0
persistent_boot_write_grub_cfg "${workdir}/linkboot" 'quiet' > /dev/null 2>&1 || sym_rc=$?
if [ "${sym_rc}" -eq 1 ]; then
   pass "write_grub_cfg: refuses a symlinked boot_dir"
else
   fail "write_grub_cfg symlinked boot_dir not refused (rc=${sym_rc})"
fi

## An empty boot_dir is refused by both sinks (never sweep/write the host root).
wg_rc=0
persistent_boot_write_grub_cfg '' 'quiet' > /dev/null 2>&1 || wg_rc=$?
if [ "${wg_rc}" -eq 1 ]; then
   pass "write_grub_cfg: refuses an empty boot_dir"
else
   fail "write_grub_cfg empty-dir not refused (rc=${wg_rc})"
fi
pr_rc=0
persistent_boot_prune '' "${workdir}" > /dev/null 2>&1 || pr_rc=$?
if [ "${pr_rc}" -eq 0 ]; then
   pass "prune: no-op on an empty boot_dir"
else
   fail "prune empty-dir not handled (rc=${pr_rc})"
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
## A crafted version with grub metacharacters must be SKIPPED (injection guard).
touch -- "${boot_dir}/vmlinuz-6.1.0\" }; evil" "${boot_dir}/initrd.img-6.1.0\" }; evil"

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

## The crafted-version pair must not appear (no grub.cfg injection).
if ! grep --quiet 'evil' "${cfg}"; then
   pass "write_grub_cfg: skips an unsafe kernel version (injection guard)"
else
   fail "write_grub_cfg: emitted an unsafe kernel version"
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

## Defense-in-depth sink: a cmdline carrying a newline (a grub command separator) is
## refused (rc 1). boot_dir has valid kernels here, so the pre-guard code would
## PROCEED (rc 0) and splice the newline into a 'linux' line.
nl_cmdline=$'quiet\nmalicious'
nlw_rc=0
persistent_boot_write_grub_cfg "${boot_dir}" "${nl_cmdline}" > /dev/null 2>&1 || nlw_rc=$?
if [ "${nlw_rc}" -eq 1 ]; then
   pass "write_grub_cfg: refuses a cmdline with a newline (control char)"
else
   fail "write_grub_cfg newline-cmdline not refused (rc=${nlw_rc})"
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
