#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-vm-lib.bsh unit tests (no VM, no privleap, no network): the VBox VM-disk helpers
## shared by the vbox-disk-mount VM wrapper and the offline boot-mode selector.
##   * installed_disk_path resolves a VM's first attached writable disk from (stubbed) VBoxManage,
##     skipping none/emptydrive and optical .iso media; dies loud when none is attached.
##   * disk_format_for maps a disk-path extension to its pinned qemu-nbd format.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
if [ -r "${script_dir}/../../libexec/image-test/vbox-vm-lib.bsh" ]; then
   lib="${script_dir}/../../libexec/image-test/vbox-vm-lib.bsh"
else
   lib='/usr/libexec/image-test/vbox-vm-lib.bsh'
fi
[ -r "${lib}" ] || { printf '%s\n' "FATAL: not found: ${lib}" >&2; exit 1; }

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT

## Caller globals the fragment consumes, plus a die that exits (mirrors the real caller).
FAIL_RC=5
die() { printf '%s\n' "${2:-}" >&2; exit "$1"; }

# shellcheck source=../../libexec/image-test/vbox-vm-lib.bsh
source "${lib}"

failures=0
check() {
   if [ "$2" = 'true' ]; then printf '%s\n' "ok: $1"; else printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); fi
}

## 1. installed_disk_path: picks the first attached writable disk image, skipping
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

## 2. installed_disk_path: a .vmdk OVA disk resolves too.
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

## 3. installed_disk_path: no writable disk (only optical / none) -> die loud, never empty.
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

## 4. disk_format_for maps the disk extension to the qemu-nbd format (so a resolved non-vdi
## disk is not forced to a wrong format), defaulting unknown/.vdi to vdi. Case-insensitive.
check "disk_format_for .vdi -> vdi" "$([ "$(disk_format_for '/x/a.vdi')" = 'vdi' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .vmdk (uppercase input) -> vmdk" "$([ "$(disk_format_for '/x/b.VMDK')" = 'vmdk' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .qcow2 -> qcow2" "$([ "$(disk_format_for '/x/c.qcow2')" = 'qcow2' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .vhd -> vpc (QEMU VHD driver, not vdi)" \
   "$([ "$(disk_format_for '/x/e.vhd')" = 'vpc' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .VHD -> vpc" "$([ "$(disk_format_for '/x/f.VHD')" = 'vpc' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .raw -> raw" "$([ "$(disk_format_for '/x/g.raw')" = 'raw' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for .img -> raw" "$([ "$(disk_format_for '/x/h.IMG')" = 'raw' ] && printf '%s' true || printf '%s' false)"
check "disk_format_for unknown -> vdi" "$([ "$(disk_format_for '/x/d.bin')" = 'vdi' ] && printf '%s' true || printf '%s' false)"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} vbox-vm-lib.bsh assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all vbox-vm-lib.bsh assertions passed'
