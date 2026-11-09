#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## select_installed_sysmaint_offline (grub-boot-select.bsh) hands the request (disk +
## passphrase + mode) to the vbox-grub-set-next-boot-mode privleap action, then cleans up.
## This sources the REAL function, stubs leaprun (capturing the request it would act on),
## and asserts the request is correct (disk, mode=persistent-sysmaint, passphrase copied)
## and the request files are removed afterwards. No VM, no privleap, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
share_dir="${script_dir}/../dm-smbios-reader-boot-tests"
[ -r "${share_dir}/grub-boot-select.bsh" ] \
   || { printf '%s\n' "FATAL: not found: ${share_dir}/grub-boot-select.bsh" >&2; exit 1; }

tmp="$(mktemp --directory)"

## The function derives the request dir from the caller's passwd home (unspoofable), so
## it lands under the real home. Shared slot: refuse an occupied/symlinked one, clean up
## only what we create (same discipline as the mok-extract / wrapper tests).
home="$(getent passwd "$(id -u)" | cut -d: -f6)"
req="${home}/.cache/vbox-grub-set-next-boot-mode"
req_preexisted='true'
[ -d "${req}" ] || req_preexisted='false'

# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --force -- "${req}/disk" "${req}/passphrase" "${req}/mode" 2>/dev/null || true
   [ "${req_preexisted}" = 'true' ] || rmdir -- "${req}" 2>/dev/null || true
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

[ -L "${req}" ] && { printf '%s\n' "FATAL: ${req} is a symlink; refusing" >&2; exit 1; }
for leaf in disk passphrase mode; do
   if [ -e "${req}/${leaf}" ] || [ -L "${req}/${leaf}" ]; then
      printf '%s\n' "FATAL: ${req}/${leaf} exists; refusing to clobber a concurrent request" >&2
      exit 1
   fi
done

## Caller globals the fragment consumes, plus a die that exits (mirrors the real caller).
FAIL_RC=5
die() { printf '%s\n' "${2:-}" >&2; exit "$1"; }

# shellcheck source=../dm-smbios-reader-boot-tests/grub-boot-select.bsh
source "${share_dir}/grub-boot-select.bsh"

## Stub leaprun on PATH: capture the request the privleap action WOULD read, then succeed.
capture="${tmp}/captured"
cat > "${tmp}/leaprun" <<STUB
#!/bin/bash
{ printf 'action=%s\n' "\$1"
  printf 'disk=%s\n' "\$(cat -- '${req}/disk' 2>/dev/null)"
  printf 'mode=%s\n' "\$(cat -- '${req}/mode' 2>/dev/null)"
  printf 'passphrase=%s\n' "\$(cat -- '${req}/passphrase' 2>/dev/null)"
} > '${capture}'
exit 0
STUB
chmod +x "${tmp}/leaprun"

pass_file="${tmp}/pass"
printf '%s' 'hunter2' > "${pass_file}"
chmod 0600 -- "${pass_file}"

PATH="${tmp}:${PATH}" select_installed_sysmaint_offline '/home/eph/VirtualBox VMs/x/x.vdi' "${pass_file}"

failures=0
check() {
   if [ "$2" = 'true' ]; then printf '%s\n' "ok: $1"; else printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); fi
}
got_action="$(sed -n 's/^action=//p' "${capture}")"
got_disk="$(sed -n 's/^disk=//p' "${capture}")"
got_mode="$(sed -n 's/^mode=//p' "${capture}")"
got_pass="$(sed -n 's/^passphrase=//p' "${capture}")"
check "delegates to the vbox-grub-set-next-boot-mode action" "$([ "${got_action}" = 'vbox-grub-set-next-boot-mode' ] && printf '%s' true || printf '%s' false)"
check "request disk is the caller's disk path" "$([ "${got_disk}" = '/home/eph/VirtualBox VMs/x/x.vdi' ] && printf '%s' true || printf '%s' false)"
check "request mode is persistent-sysmaint" "$([ "${got_mode}" = 'persistent-sysmaint' ] && printf '%s' true || printf '%s' false)"
check "request passphrase was copied from the passphrase file" "$([ "${got_pass}" = 'hunter2' ] && printf '%s' true || printf '%s' false)"
check "request files removed after the action (no leftover disk)" "$([ ! -e "${req}/disk" ] && printf '%s' true || printf '%s' false)"
check "request files removed after the action (no leftover passphrase)" "$([ ! -e "${req}/passphrase" ] && printf '%s' true || printf '%s' false)"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} select_installed_sysmaint_offline assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all select_installed_sysmaint_offline assertions passed'
