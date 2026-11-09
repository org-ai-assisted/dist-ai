#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Assert boot_installed (vbox-session.bsh) honors its documented return-nonzero
## contract: when the offline sysmaint selection die()s (e.g. an upgrade bricked the boot
## entry, or the disk cannot be mounted), boot_installed must RETURN nonzero -- NOT exit the
## process -- so dm-upgrade-regression's `if ! boot_installed sysmaint` catches it and reaches
## write_report (degraded result) instead of a hard exit past it. No VM, no network.
## installed_disk_path + select_installed_mode_offline are forced via stubs (their real
## bodies are drift-free single source in grub-boot-select.bsh); this tests the CALL-SITE
## subshell / command-substitution wrap in boot_installed AND that BOTH roles select offline
## (user resets any stale one-shot a prior sysmaint boot left on an encrypted disk).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
share_dir="${script_dir}/../dm-smbios-reader-boot-tests"
for lib in gui-drive.bsh grub-boot-select.bsh vbox-session.bsh; do
   [ -r "${share_dir}/${lib}" ] || { printf '%s\n' "ERROR: not found: ${share_dir}/${lib}" >&2; exit 1; }
done

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() {
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

## No-op VBOXMANAGE/GUESTCTL: boot_installed's clean_poweroff/startvm must not touch a VM.
stub="${tmp}/noop"
cat > "${stub}" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${stub}"

## Caller globals the sourced fragments consume (gui-drive.bsh + vbox-session.bsh).
# shellcheck disable=SC2034
vm='testvm'
# shellcheck disable=SC2034
VBOXMANAGE="${stub}"
# shellcheck disable=SC2034
GUESTCTL="${stub}"
# shellcheck disable=SC2034
TESSERACT="${stub}"
# shellcheck disable=SC2034
me='boot_installed_test'
FAIL_RC=5

## Caller globals the offline selector / disk resolver consume.
# shellcheck disable=SC2034
passphrase_file=''

## The caller-provided die: prints to stderr and EXITs (mirrors dm-upgrade-regression's
## die). The offline selector calls `die "${FAIL_RC}" "..."`, so $1 is the exit code.
die() {
   printf '%s\n' "${2:-}" >&2
   exit "$1"
}

# shellcheck source=../dm-smbios-reader-boot-tests/gui-drive.bsh
source "${share_dir}/gui-drive.bsh"
# shellcheck source=../dm-smbios-reader-boot-tests/grub-boot-select.bsh
source "${share_dir}/grub-boot-select.bsh"
# shellcheck source=../dm-smbios-reader-boot-tests/vbox-session.bsh
source "${share_dir}/vbox-session.bsh"

## Neutralize the VM-touching parts of boot_installed so only the call-site contract
## is under test. clean_poweroff would poll a real VM; stub to a no-op.
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
clean_poweroff() {
   return 0
}

pass=0
fail=0
assert_eq() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}" "  got:  ${got}" "  want: ${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

## Resolve the disk to a stable sentinel so the sysmaint branch reaches the selector; the
## stub below decides pass/fail. Overridden per-case where the resolver itself is under test.
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
installed_disk_path() {
   printf '%s\n' "${tmp}/fake.vdi"
}

## --- negative: select die()s -> boot_installed must RETURN nonzero, not exit --------
## Force the failure branch: an offline selection that die()s like a real unmountable disk.
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
select_installed_mode_offline() {
   die "${FAIL_RC}" "simulated: offline next_entry selection failed (${1})"
}
## Run inside a command substitution with a sentinel: the printf executes ONLY if
## boot_installed RETURNED. If die escapes (unwrapped call site), the $( ) subshell
## exits at die and the sentinel never prints -> out is empty (the canary: FAILS on old code).
out="$( boot_installed sysmaint >/dev/null 2>&1; printf '%s' "RET=${?}" )" || true
assert_eq 'boot_installed sysmaint returns (not exits) when select die()s' "${out}" 'RET=1'

## --- positive: happy path still returns 0 (wrap preserves semantics) ----------------
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
unlock_luks() {
   return 0
}
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
wait_guestcontrol_ready() {
   return 0
}
## Record the mode the selector was asked for (both roles now select offline).
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed, not called directly
select_installed_mode_offline() {
   printf '%s' "${1}" > "${tmp}/select_mode"
   return 0
}
safe-rm --force -- "${tmp}/select_mode"
rc=0
boot_installed sysmaint || rc=$?
assert_eq 'boot_installed sysmaint returns 0 on a clean select' "${rc}" '0'
assert_eq 'boot_installed sysmaint selects the persistent-sysmaint mode' \
   "$(cat -- "${tmp}/select_mode" 2>/dev/null)" 'persistent-sysmaint'

## --- USER role ALSO selects offline (mode=user), so a stale SYSMAINT one-shot on an
## encrypted disk cannot leak into the USER boot (the false-brick regression). ----------
safe-rm --force -- "${tmp}/select_mode"
rc=0
boot_installed user || rc=$?
assert_eq 'boot_installed user returns 0' "${rc}" '0'
assert_eq 'boot_installed user selects the user mode offline (resets any stale one-shot)' \
   "$(cat -- "${tmp}/select_mode" 2>/dev/null)" 'user'

## --- a VM that never powers off: clean_poweroff fails -> boot_installed must RETURN 1 and
## NOT proceed to the offline mount (which would race the still-held disk lock). -----------
# shellcheck disable=SC2317  ## invoked indirectly by boot_installed
clean_poweroff() {
   return 1
}
safe-rm --force -- "${tmp}/select_mode"
rc=0
boot_installed sysmaint || rc=$?
assert_eq 'boot_installed returns 1 when clean_poweroff fails (VM never off)' "${rc}" '1'
assert_eq 'boot_installed does NOT select/mount when the VM is not powered off' \
   "$([ -e "${tmp}/select_mode" ] && printf '%s' called || printf '%s' not-called)" 'not-called'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
