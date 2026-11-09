#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## grub-boot-select.bsh unit tests (no VM, no privleap, no network):
##   * select_installed_sysmaint_offline hands the request (disk + mode, plus an OPTIONAL
##     passphrase and format) to the vbox-grub-set-next-boot-mode privleap action, then
##     cleans up. Stubs leaprun (capturing the request it would act on) and asserts the
##     request is correct and the request files are removed afterwards -- for an encrypted
##     install (passphrase), an unencrypted image (no passphrase), and a non-vdi format.
##   * installed_disk_path resolves a VM's attached writable disk from (stubbed) VBoxManage.

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
   safe-rm --force -- "${req}/disk" "${req}/passphrase" "${req}/mode" "${req}/format" 2>/dev/null || true
   [ "${req_preexisted}" = 'true' ] || rmdir -- "${req}" 2>/dev/null || true
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

[ -L "${req}" ] && { printf '%s\n' "FATAL: ${req} is a symlink; refusing" >&2; exit 1; }
for leaf in disk passphrase mode format; do
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

## Stub leaprun on PATH: capture the request the privleap action WOULD read (including
## whether the optional passphrase/format files are present), then succeed.
capture="${tmp}/captured"
cat > "${tmp}/leaprun" <<STUB
#!/bin/bash
{ printf 'action=%s\n' "\$1"
  printf 'disk=%s\n' "\$(cat -- '${req}/disk' 2>/dev/null)"
  printf 'mode=%s\n' "\$(cat -- '${req}/mode' 2>/dev/null)"
  if [ -f '${req}/passphrase' ]; then printf 'passphrase=%s\n' "\$(cat -- '${req}/passphrase')"; else printf 'passphrase=<absent>\n'; fi
  if [ -f '${req}/format' ]; then printf 'format=%s\n' "\$(cat -- '${req}/format')"; else printf 'format=<absent>\n'; fi
} > '${capture}'
exit 0
STUB
chmod +x "${tmp}/leaprun"

failures=0
check() {
   if [ "$2" = 'true' ]; then printf '%s\n' "ok: $1"; else printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); fi
}
field() { sed -n "s/^$1=//p" "${capture}"; }

## 1. Encrypted install: disk + passphrase file, default (vdi) format.
pass_file="${tmp}/pass"
printf '%s' 'hunter2' > "${pass_file}"
chmod 0600 -- "${pass_file}"
PATH="${tmp}:${PATH}" select_installed_sysmaint_offline '/home/eph/VirtualBox VMs/x/x.vdi' "${pass_file}"
check "delegates to the vbox-grub-set-next-boot-mode action" "$([ "$(field action)" = 'vbox-grub-set-next-boot-mode' ] && printf '%s' true || printf '%s' false)"
check "request disk is the caller's disk path" "$([ "$(field disk)" = '/home/eph/VirtualBox VMs/x/x.vdi' ] && printf '%s' true || printf '%s' false)"
check "request mode is persistent-sysmaint" "$([ "$(field mode)" = 'persistent-sysmaint' ] && printf '%s' true || printf '%s' false)"
check "request passphrase copied from the passphrase file" "$([ "$(field passphrase)" = 'hunter2' ] && printf '%s' true || printf '%s' false)"
check "no format file -> default vdi (format absent)" "$([ "$(field format)" = '<absent>' ] && printf '%s' true || printf '%s' false)"
check "request files removed afterwards (no leftover disk)" "$([ ! -e "${req}/disk" ] && printf '%s' true || printf '%s' false)"
check "request files removed afterwards (no leftover passphrase)" "$([ ! -e "${req}/passphrase" ] && printf '%s' true || printf '%s' false)"

## 2. Unencrypted image (no passphrase), explicit vmdk format (a Whonix OVA disk).
PATH="${tmp}:${PATH}" select_installed_sysmaint_offline '/home/eph/VirtualBox VMs/ws/ws.vmdk' '' vmdk
check "no passphrase -> passphrase file absent in the request" "$([ "$(field passphrase)" = '<absent>' ] && printf '%s' true || printf '%s' false)"
check "format vmdk written to the request" "$([ "$(field format)" = 'vmdk' ] && printf '%s' true || printf '%s' false)"
check "disk is the unencrypted .vmdk path" "$([ "$(field disk)" = '/home/eph/VirtualBox VMs/ws/ws.vmdk' ] && printf '%s' true || printf '%s' false)"
check "format file removed afterwards" "$([ ! -e "${req}/format" ] && printf '%s' true || printf '%s' false)"

## 3. A stale optional file from a prior request must NOT leak into a later one: plant a
## passphrase, then run WITHOUT one -> it must be cleared (passphrase absent).
printf '%s' 'stale' > "${req}/passphrase"
PATH="${tmp}:${PATH}" select_installed_sysmaint_offline '/home/eph/VirtualBox VMs/ws/ws.vmdk' '' vmdk
check "stale passphrase cleared before a no-passphrase request" "$([ "$(field passphrase)" = '<absent>' ] && printf '%s' true || printf '%s' false)"

## 4. installed_disk_path: picks the first attached writable disk image, skipping
## none/emptydrive and an optical .iso. Stub VBoxManage with a realistic machinereadable dump.
VBOXMANAGE="${tmp}/VBoxManage"
cat > "${VBOXMANAGE}" <<'STUB'
#!/bin/bash
## Only answer `showvminfo <vm> --machinereadable`.
cat <<'OUT'
name="testvm"
"IDE Controller-0-0"="none"
"SATA-0-0"="/home/eph/VirtualBox VMs/testvm/testvm.vdi"
"SATA-1-0"="/var/lib/image-tests/iso/kicksecure.iso"
VMState="poweroff"
OUT
STUB
chmod +x "${VBOXMANAGE}"
got_disk="$(installed_disk_path testvm)"
check "installed_disk_path resolves the SATA writable .vdi" "$([ "${got_disk}" = '/home/eph/VirtualBox VMs/testvm/testvm.vdi' ] && printf '%s' true || printf '%s' false)"

## 5. installed_disk_path: a .vmdk OVA disk resolves too.
cat > "${VBOXMANAGE}" <<'STUB'
#!/bin/bash
cat <<'OUT'
name="ws"
"SATA Controller-0-0"="/home/eph/VirtualBox VMs/ws/ws-disk001.vmdk"
VMState="poweroff"
OUT
STUB
chmod +x "${VBOXMANAGE}"
check "installed_disk_path resolves a .vmdk OVA disk" "$([ "$(installed_disk_path ws)" = '/home/eph/VirtualBox VMs/ws/ws-disk001.vmdk' ] && printf '%s' true || printf '%s' false)"

## 6. installed_disk_path: no writable disk (only optical / none) -> die loud, never empty.
cat > "${VBOXMANAGE}" <<'STUB'
#!/bin/bash
cat <<'OUT'
name="empty"
"IDE Controller-0-0"="none"
"SATA-0-0"="emptydrive"
VMState="poweroff"
OUT
STUB
chmod +x "${VBOXMANAGE}"
rc=0
( installed_disk_path empty ) >/dev/null 2>&1 || rc=$?
check "installed_disk_path dies (rc!=0) when no writable disk is attached" "$([ "${rc}" != '0' ] && printf '%s' true || printf '%s' false)"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} grub-boot-select.bsh assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all grub-boot-select.bsh assertions passed'
