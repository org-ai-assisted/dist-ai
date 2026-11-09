#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## nbd_connect opens the disk with qemu-nbd AS ROOT. Pinning the format is not enough for a
## multi-file format: a crafted VMDK FLAT extent (or a qcow2 backing file) can reference an
## external HOST path (RW ... FLAT "/etc/shadow"), so qemu-nbd's root open becomes arbitrary host
## read/write. nbd_connect must reject a NON-vdi image that is not self-contained BEFORE opening
## it. Source the real vbox-disk-lib.bsh, stub qemu-nbd, and assert: a crafted vmdk is refused and
## qemu-nbd is never reached; a clean vdi and a clean qcow2 open normally. No root, no nbd.
##
## Needs qemu-img (the self-contained probe + fixture creation); SKIPS if absent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! type -P qemu-img >/dev/null 2>&1; then
   printf '%s\n' "SKIP: qemu-img absent" >&2
   exit 77  ## style-ok: allow-skip: qemu-utils is the self-contained probe + fixture dependency
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${VBOX_DISK_LIB:-}"
if [ -z "${lib}" ]; then
   if [ -f "${test_dir}/../../libexec/image-test/vbox-disk-lib.bsh" ]; then
      lib="${test_dir}/../../libexec/image-test/vbox-disk-lib.bsh"
   else
      lib='/usr/libexec/image-test/vbox-disk-lib.bsh'
   fi
fi
[ -r "${lib}" ] || { printf '%s\n' "FATAL: vbox-disk-lib.bsh not found at ${lib}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() { safe-rm --recursive --force -- "${work}"; }
trap test_cleanup EXIT

# shellcheck disable=SC2317  ## may be reached by a lib function (nbd_connect rejects -> die)
die() { printf '%s\n' "die: $1" >&2; exit 97; }
# shellcheck source=../../libexec/image-test/vbox-disk-lib.bsh
source "${lib}"

nbd_log="${work}/nbd.called"
true > "${nbd_log}"
## Stub qemu-nbd: record that the real open WOULD have happened; never touch a device.
# shellcheck disable=SC2317  ## invoked by nbd_connect
qemu-nbd() { printf '%s\n' "called $*" >> "${nbd_log}"; }

pass=0
fail=0
check() {
   if [ "$2" = "$3" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1" "  got:  $2" "  want: $3" >&2
      fail=$(( fail + 1 ))
   fi
}

## Fixtures: a crafted monolithicFlat VMDK whose extent points at a HOST file, plus a clean vdi
## and a clean qcow2 (both self-contained).
host_target="${work}/host_target"
printf '%s' 'HOST-SECRET' > "${host_target}"
cat > "${work}/evil.vmdk" <<DESC
# Disk DescriptorFile
version=1
CID=12345678
parentCID=ffffffff
createType="monolithicFlat"
RW 2048 FLAT "${host_target}" 0
DESC
qemu-img create -f vdi "${work}/clean.vdi" 1M >/dev/null
qemu-img create -f qcow2 "${work}/clean.qcow2" 1M >/dev/null

## 1. Crafted vmdk referencing a host file -> REFUSED, qemu-nbd never reached.
true > "${nbd_log}"
rc=0
( nbd_connect /dev/nbd-fake "${work}/evil.vmdk" vmdk rw ) >/dev/null 2>&1 || rc=$?
check 'crafted vmdk (external extent) is refused' "$([ "${rc}" -ne 0 ] && printf '%s' yes || printf '%s' no)" 'yes'
check 'qemu-nbd NOT reached for the crafted vmdk' "$([ ! -s "${nbd_log}" ] && printf '%s' yes || printf '%s' no)" 'yes'

## 1b. Crafted qcow2 whose external data_file references a host file -> REFUSED. The data_file
## lives at format-specific.data.data-file, NOT a backing file or a VMDK extent, so a
## field-specific check misses it; the recursive self-containment walk must still catch it.
qcow2_data="${work}/qcow2_data"
printf '%s' 'HOST-DATA' > "${qcow2_data}"
qemu-img create -f qcow2 -o data_file="${qcow2_data}",data_file_raw=on "${work}/evil.qcow2" 16 >/dev/null
true > "${nbd_log}"
rc=0
( nbd_connect /dev/nbd-fake "${work}/evil.qcow2" qcow2 rw ) >/dev/null 2>&1 || rc=$?
check 'crafted qcow2 (external data_file) is refused' "$([ "${rc}" -ne 0 ] && printf '%s' yes || printf '%s' no)" 'yes'
check 'qemu-nbd NOT reached for the crafted qcow2' "$([ ! -s "${nbd_log}" ] && printf '%s' yes || printf '%s' no)" 'yes'

## 2. Clean vdi -> opened (vdi is single-file, never probed).
true > "${nbd_log}"
nbd_connect /dev/nbd-fake "${work}/clean.vdi" vdi rw >/dev/null 2>&1 || true
check 'clean vdi reaches qemu-nbd' "$([ -s "${nbd_log}" ] && printf '%s' yes || printf '%s' no)" 'yes'

## 3. Clean qcow2 (self-contained, no backing) -> opened (the check must not over-reject).
true > "${nbd_log}"
nbd_connect /dev/nbd-fake "${work}/clean.qcow2" qcow2 rw >/dev/null 2>&1 || true
check 'clean qcow2 (self-contained) reaches qemu-nbd' "$([ -s "${nbd_log}" ] && printf '%s' yes || printf '%s' no)" 'yes'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
