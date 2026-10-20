#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistence-setup --target usb-freespace --force deletes the 'persistence' +
## 'persistbootx' overlay GPT entries via delete_overlay_partitions(). It MUST
## refuse when an overlay partition is still mounted or held (an open LUKS mapping,
## or the overlay backing the running live system): deleting a busy partition's
## table entry leaves the kernel unable to re-read it, so recreation fails AFTER the
## entries are gone and the stick loses its overlay -- data loss.
##
## Drives the REAL sourced script (main() is behind a was_executed guard, so sourcing
## defines the functions without running it). lsblk / sgdisk / udevadm / partprobe are
## invoked by bare name, so a PATH-prepended shim records sgdisk -d and feeds controlled
## lsblk output; a fake disk path is used and no real device is touched.
## CANARY: the pre-guard delete_overlay_partitions ran sgdisk -d unconditionally, so the
## 'busy -> no sgdisk -d' cases FAIL on the old code.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-setup"
else
   subject='/usr/bin/persistence-setup'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

## persistence-setup sources helper-scripts via HELPER_SCRIPTS_PATH; derive it from the
## sibling checkout when the suite did not wire it.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

## Drift-guard: the function + refusal message this test pins.
for sentinel in \
   'overlay_partition_busy()' \
   'delete_overlay_partitions()' \
   'refusing --force reformat'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090
source "${subject}"
if [ "$(type -t delete_overlay_partitions)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'delete_overlay_partitions' function" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir persistence-setup-force.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

shimdir="${work}/bin"
mkdir --parents -- "${shimdir}"
export PS_RECORD="${work}/record"
## MOUNT_OUT is the MOUNTPOINT the lsblk shim reports per case (empty = unmounted).
export MOUNT_OUT=""

## lsblk shim: dispatch on the requested --output columns.
##   NAME,PARTN,PARTLABEL -> delete_overlay_partitions enumerates: two overlay rows.
##   MOUNTPOINT           -> overlay_partition_busy mount check: MOUNT_OUT.
##   KNAME                -> disk_is_held holder scan: basename of the queried node
##                           (a nonexistent block name, so the real /sys scan finds no holder).
# shellcheck disable=SC2016  ## placeholders are literal in the emitted shim, expanded when it runs
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'args=" $* "'
   printf '%s\n' 'if [[ "${args}" == *" NAME,PARTN,PARTLABEL "* ]]; then'
   printf '%s\n' '   printf "%s\n" "/dev/fakedisk3 3 persistence" "/dev/fakedisk4 4 persistbootx"'
   printf '%s\n' 'elif [[ "${args}" == *" MOUNTPOINT "* ]]; then'
   printf '%s\n' '   if [ -n "${MOUNT_OUT}" ]; then printf "%s\n" "${MOUNT_OUT}"; fi'
   printf '%s\n' 'elif [[ "${args}" == *" KNAME "* ]]; then'
   printf '%s\n' '   last="${!#}"'
   printf '%s\n' '   printf "%s\n" "${last##*/}"'
   printf '%s\n' 'fi'
   printf '%s\n' 'exit 0'
} > "${shimdir}/lsblk"
chmod 0770 -- "${shimdir}/lsblk"

## sgdisk spy: record every call (the delete loop runs `sgdisk -d <n> <device>`).
# shellcheck disable=SC2016  ## ${PS_RECORD}/$* are literal in the emitted shim
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "sgdisk $*" >> "${PS_RECORD}"'
   printf '%s\n' 'exit 0'
} > "${shimdir}/sgdisk"
chmod 0770 -- "${shimdir}/sgdisk"

## udevadm/partprobe: no-op (the function only settles/re-reads through them).
for cmd in udevadm partprobe; do
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'exit 0'
   } > "${shimdir}/${cmd}"
   chmod 0770 -- "${shimdir}/${cmd}"
done
export PATH="${shimdir}:${PATH}"

## The whole disk delete_overlay_partitions operates on (matches the shim rows' parent).
## Consumed by the sourced subject's delete_overlay_partitions, across a boundary
## shellcheck does not follow.
# shellcheck disable=SC2034
device='/dev/fakedisk'

pass_count=0
fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}

## true iff a non-zero exit (a die/refusal).
refused() {
   if [ "$1" -ne 0 ]; then printf '%s' true; else printf '%s' false; fi
}
## true iff exactly N `sgdisk -d` calls were recorded.
sgdisk_deletes_are() {
   local got
   got="$(grep --count --fixed-strings -- 'sgdisk -d' "${PS_RECORD}" || true)"
   if [ "${got}" = "$1" ]; then printf '%s' true; else printf '%s' false; fi
}

## Run the REAL function in a subshell so a die() exit ends only the subshell.
run_guard() {
   local rc=0
   ( delete_overlay_partitions ) >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## --- BUSY via mountpoint: an overlay partition is mounted -> refuse, delete nothing ---
true > "${PS_RECORD}"
MOUNT_OUT='/run/initramfs/live/persistence'
rc="$(run_guard)"
check "busy(mount): refuses with non-zero exit"              "$(refused "${rc}")"
check "busy(mount): deletes nothing (no sgdisk -d) [CANARY]" "$(sgdisk_deletes_are 0)"

## --- FREE: no overlay partition mounted or held -> delete both overlay partitions ---
true > "${PS_RECORD}"
MOUNT_OUT=''
rc="$(run_guard)"
check "free: completes (rc 0)"                               "$([ "${rc}" -eq 0 ] && printf '%s' true || printf '%s' false)"
check "free: deletes both overlay partitions (2x sgdisk -d)" "$(sgdisk_deletes_are 2)"

## --- BUSY via holder: an open LUKS/dm mapping -> refuse, delete nothing ---
## Force disk_is_held true (an open mapping has no mountpoint on the partition itself).
## Done LAST so the override cannot affect the FREE case above.
disk_is_held() { return 0; }
true > "${PS_RECORD}"
MOUNT_OUT=''
rc="$(run_guard)"
check "busy(held): refuses with non-zero exit"               "$(refused "${rc}")"
check "busy(held): deletes nothing (no sgdisk -d) [CANARY]"  "$(sgdisk_deletes_are 0)"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup force busy-guard: ${pass_count} pass, ${fail_count} fail, 0 skip ====="
[ "${fail_count}" -eq 0 ]
