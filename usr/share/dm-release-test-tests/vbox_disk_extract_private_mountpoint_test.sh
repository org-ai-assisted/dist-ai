#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-disk-extract must mount the guest filesystem inside a 0700 PARENT: once mounted, the
## mountpoint takes the guest root's 0755 mode, so a world-traversable parent would expose the
## decrypted tree to other local users. Drive the REAL tool with stubbed host plumbing (no root,
## no nbd, no disk); the mount stub records the mode of its mountpoint's PARENT. Assert 0700.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${VBOX_DISK_EXTRACT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/vbox-disk-extract" ]; then
      subject="${test_dir}/../../bin/vbox-disk-extract"
   else
      subject='/usr/bin/vbox-disk-extract'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: vbox-disk-extract not found at ${subject}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() { safe-rm --recursive --force -- "${work}"; }
trap test_cleanup EXIT

parent_mode_log="${work}/parent_mode"

## Source the real tool (its BASH_SOURCE guard keeps main from running), then stub every host
## action so main reaches the mount loop with no root / nbd / disk.
# shellcheck disable=SC1090
source "${subject}"

# shellcheck disable=SC2317  ## all stubs below are invoked indirectly by main()
id() { printf '%s' '0'; }
# shellcheck disable=SC2317
modprobe() { :; }
# shellcheck disable=SC2317
free_nbd() { printf '%s' '/dev/nbd-fake'; }
# shellcheck disable=SC2317
nbd_connect() { :; }
# shellcheck disable=SC2317
settle_partitions() { :; }
# shellcheck disable=SC2317
candidate_filesystems() { printf '%s\n' '/dev/fake-fs'; }
# shellcheck disable=SC2317
qemu-nbd() { :; }  ## reached by cleanup (nbd_dev set)
# shellcheck disable=SC2317
umount() { :; }
# shellcheck disable=SC2317
install() { :; }
# shellcheck disable=SC2317
chown() { :; }
## Record the mode of the mountpoint's PARENT (the last arg is the mountpoint), then "succeed".
# shellcheck disable=SC2317
mount() {
   local mnt=""
   for mnt in "$@"; do :; done  ## mnt = last positional = the mountpoint
   stat --format='%a' -- "$(dirname -- "${mnt}")" > "${parent_mode_log}"
   return 0
}

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

disk="${work}/disk.vdi"
printf '%s' '' > "${disk}"

## Force a WORLD-TRAVERSABLE (1777) base for the tool's own mktemp, so the test reflects the
## production exposure regardless of the runner's TMPDIR (which here happens to be a private
## 0700 dir). The fix's 0700 parent must hold even when mktemp's base is world-traversable.
export TMPDIR="${work}/pub"
mkdir --mode=1777 -- "${TMPDIR}"

## main dies "not found" (the stub mount exposes no real file); that is expected -- we only
## need it to have reached the mount with its 0700-parent mountpoint.
( main --disk "${disk}" --format vdi --source /nonexistent --dest "${work}/out" ) >/dev/null 2>&1 || true

[ -f "${parent_mode_log}" ] || { printf '%s\n' "FAIL: mount was never reached" >&2; exit 1; }
check 'vbox-disk-extract mounts inside a 0700 parent (decrypted tree not world-traversable)' \
   "$(cat -- "${parent_mode_log}")" '700'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
