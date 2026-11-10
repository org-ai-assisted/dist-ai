#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## candidate_filesystems() activates a guest LVM-in-LUKS volume group, then the EXIT-trap
## cleanup() deactivates it. The activation can PARTIALLY succeed: vgchange activates one LV
## and then returns nonzero (a second LV with an unsupported segment). Under errexit that
## aborts candidate_filesystems; cleanup must still deactivate the already-activated VG, or the
## LV + nbd + LUKS mapping leak. This requires vg_activated/vg_dev be recorded BEFORE the
## vgchange call (an assignment AFTER it never runs on the abort). Source the real
## vbox-disk-lib.bsh, stub the LVM tools (vgchange FAILS on --activate y, mimicking partial
## activation), run the enumeration under errexit with a cleanup EXIT trap exactly as
## image-mount does, and assert cleanup deactivated the guest VG. No root, no LVM, no disk.

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

## die is provided by the sourcing tool in production; the lib only calls it inside functions.
# shellcheck disable=SC2317  ## may be reached by a lib function on an unexpected path
die() { printf '%s\n' "die: $1" >&2; exit 98; }
# shellcheck source=../../libexec/image-test/vbox-disk-lib.bsh
source "${lib}"

argv_log="${work}/lvm.argv"
true > "${argv_log}"

## Stub the LVM tools. vgchange RECORDS its argv and FAILS on --activate y -- a partial
## activation (one LV up, then nonzero). lvs would list LVs but must never be reached, since the
## failing activation aborts candidate_filesystems first.
# shellcheck disable=SC2317  ## invoked by candidate_filesystems
pvs() { printf '%s\n' 'guestvg'; }
# shellcheck disable=SC2317
vgchange() {
   printf '%s\n' "vgchange $*" >> "${argv_log}"
   case "$*" in
      *'--activate y'*)
         return 5
         ;;
      *)
         return 0
         ;;
   esac
}
# shellcheck disable=SC2317
lvs() { printf '%s\n' "lvs $*" >> "${argv_log}"; printf '%s\n' '/dev/guestvg/root'; }

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
contains() {
   case "$2" in
      *"$3"*)
         printf '%s' 'yes'
         ;;
      *)
         printf '%s' 'no'
         ;;
   esac
}

mapped='/dev/mapper/tluks'
# shellcheck disable=SC2034  ## read by candidate_filesystems/cleanup via the sourced lib
luks_name='tluks'

## Drive the enumeration exactly as image-mount does: errexit on, 'trap cleanup EXIT'. The
## partial-activation vgchange aborts candidate_filesystems, the subshell's EXIT trap runs
## cleanup, and the '|| true' is on the SUBSHELL (not the function) so errexit stays live INSIDE
## it. cleanup appends to argv_log, which survives the subshell.
fs_out="${work}/fs"
(
   trap cleanup EXIT
   candidate_filesystems > "${fs_out}"
) || true

## The activation was attempted (we reached the failing path)...
activate_line="$(grep '^vgchange.*--activate y' -- "${argv_log}" || true)"
check 'vgchange --activate y was attempted (partial-activation path reached)' \
   "$(contains x "${activate_line}" "--devices ${mapped} --activate y")" 'yes'

## ...and despite its nonzero exit, cleanup deactivated the guest VG -- scoped with --devices.
## On the pre-fix code (record AFTER activate), vg_activated is empty at the abort, so cleanup
## skips this and the VG/nbd/LUKS leak; the grep then finds nothing and this check FAILS.
deactivate_line="$(grep '^vgchange.*--activate n' -- "${argv_log}" || true)"
check 'cleanup deactivated the partially-activated VG, scoped with --devices' \
   "$(contains x "${deactivate_line}" "--devices ${mapped} --activate n")" 'yes'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
