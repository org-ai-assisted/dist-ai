#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## candidate_filesystems() activates a guest LVM-in-LUKS volume group by NAME. Without a
## --devices scope, a guest VG named like a HOST VG (e.g. ubuntu-vg) activates the HOST VG and
## exposes its LVs to the mount. Source the real vbox-disk-lib.bsh, stub the LVM tools to record
## their argv, and assert every LVM op (activate, list, and the cleanup deactivate) is scoped to
## the guest mapping with --devices. No root, no LVM, no disk.

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

## Stub the LVM tools: report a guest VG name, record the activate/list/deactivate argv.
# shellcheck disable=SC2317  ## invoked by candidate_filesystems/cleanup
pvs() { printf '%s\n' 'guestvg'; }
# shellcheck disable=SC2317
vgchange() { printf '%s\n' "vgchange $*" >> "${argv_log}"; }
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
# shellcheck disable=SC2034  ## read by candidate_filesystems via the sourced lib (dynamic source)
luks_name='tluks'

## Enumerate: pvs reports a VG, so candidate_filesystems activates it and lists its LVs. Run it
## in THIS shell (redirect to a file, as the real tools do) so its vg_activated/vg_dev
## assignments survive for cleanup -- a command substitution would discard them in a subshell.
fs_out="${work}/fs"
candidate_filesystems > "${fs_out}"
out="$(cat -- "${fs_out}")"
check 'candidate_filesystems echoes the guest LV path' "${out}" '/dev/guestvg/root'

activate_line="$(grep '^vgchange.*--activate y' -- "${argv_log}" || true)"
check 'vgchange activate is scoped to the guest mapping with --devices' \
   "$(contains x "${activate_line}" "--devices ${mapped} --activate y")" 'yes'

lvs_line="$(grep '^lvs ' -- "${argv_log}" || true)"
check 'lvs is scoped to the guest mapping with --devices' \
   "$(contains x "${lvs_line}" "--devices ${mapped}")" 'yes'

## Teardown: cleanup deactivates the activated VG -- scoped to the guest mapping too, so it
## cannot deactivate a same-named HOST VG.
true > "${argv_log}"
cleanup
deactivate_line="$(grep '^vgchange.*--activate n' -- "${argv_log}" || true)"
check 'cleanup vgchange deactivate is scoped with --devices' \
   "$(contains x "${deactivate_line}" "--devices ${mapped} --activate n")" 'yes'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
