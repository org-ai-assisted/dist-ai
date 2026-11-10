#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## free_nbd() must return a free WHOLE-DISK /dev/nbdN, never a partition node. With 'modprobe
## nbd max_part=16' the kernel publishes partition nodes nbdNpM; an unused slot reads size 0 and
## sorts before a free whole disk (nbd0p1 < nbd1 under LC_ALL=C). Without the nbd[0-9]+ filter,
## free_nbd would hand back nbd0p1 -- a PARTITION of the BUSY nbd0 -- so the connect fails and
## the EXIT trap disconnects that partition, not a device the engine holds. Source the real lib,
## point NBD_SYSFS_BASE at a fake sysfs tree, and assert free_nbd picks the free whole disk. No
## root, no nbd module, no disk.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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

## die is provided by the sourcing tool in production; free_nbd calls it when nothing is free.
# shellcheck disable=SC2317  ## reached by free_nbd on the no-free path
die() { printf '%s\n' "die: $1" >&2; exit 98; }
# shellcheck source=../../libexec/image-test/vbox-disk-lib.bsh
source "${lib}"

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

## Fake /sys/class/block: nbd0 CONNECTED (nonzero size) with an unused partition slot nbd0p1
## (size 0, the trap node), and nbd1 a FREE whole disk (size 0). Glob order under LC_ALL=C is
## nbd0, nbd0p1, nbd1 -- so a partition-blind scan would return nbd0p1 first.
sysfs="${work}/sys"
mkdir --parents -- \
   "${sysfs}/nbd0" "${sysfs}/nbd0p1" "${sysfs}/nbd1" "${sysfs}/nbd1p1"
printf '%s\n' '2097152' > "${sysfs}/nbd0/size"    ## nbd0 busy
printf '%s\n' '0'       > "${sysfs}/nbd0p1/size"  ## free partition slot of the BUSY nbd0 (trap)
printf '%s\n' '0'       > "${sysfs}/nbd1/size"    ## nbd1 free whole disk (the correct answer)
printf '%s\n' '0'       > "${sysfs}/nbd1p1/size"  ## nbd1's partition slot (also size 0)

got="$(NBD_SYSFS_BASE="${sysfs}" free_nbd)"
check 'free_nbd returns the free whole disk nbd1, never a partition of busy nbd0' \
   "${got}" '/dev/nbd1'

## And when the only free node is a whole disk after several busy disks, it is still found.
printf '%s\n' '2097152' > "${sysfs}/nbd1/size"    ## now nbd1 busy too
mkdir --parents -- "${sysfs}/nbd2"
printf '%s\n' '0'       > "${sysfs}/nbd2/size"    ## nbd2 free whole disk
got2="$(NBD_SYSFS_BASE="${sysfs}" free_nbd)"
check 'free_nbd skips busy whole disks and their partition slots to find nbd2' \
   "${got2}" '/dev/nbd2'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
