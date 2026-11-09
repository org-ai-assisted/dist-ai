#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-test vbox-disk-mount's argument contract and teardown-safety seam without root, a
## VM, or a real disk: source the real tool (its BASH_SOURCE guard keeps main from running)
## and drive parse_args + cleanup directly. The real read-write mount is covered separately
## in the sandbox (vbox_disk_mount_roundtrip, root + loopback LUKS).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${VBOX_DISK_MOUNT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/vbox-disk-mount" ]; then
      subject="${test_dir}/../../bin/vbox-disk-mount"
   else
      subject='/usr/bin/vbox-disk-mount'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: vbox-disk-mount not found at ${subject}" >&2; exit 1; }
# shellcheck source=../../bin/vbox-disk-mount
source "${subject}"

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap test_cleanup EXIT

pass=0
fail=0
check() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "ok: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}" "  got:  ${got}" "  want: ${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

## Map a captured exit code to a word, so check() compares strings (errexit-safe, no
## printf-literal). parse_args' die exits nonzero = 'rejected'.
outcome() {
   if [ "$1" -eq 0 ]; then
      printf '%s' 'accepted'
   else
      printf '%s' 'rejected'
   fi
}

disk="${work}/disk.vdi"
printf '%s' '' > "${disk}"

## --- argument rejection (die -> nonzero exit, captured in a subshell) ----------------
rc=0; ( parse_args ) >/dev/null 2>&1 || rc=$?
check 'no arguments rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args foo ) >/dev/null 2>&1 || rc=$?
check 'a first argument other than run rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args run -- echo hi ) >/dev/null 2>&1 || rc=$?
check 'missing --disk rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args run --disk "${disk}" ) >/dev/null 2>&1 || rc=$?
check 'missing command after -- rejected' "$(outcome "${rc}")" 'rejected'

## --- happy parse: disk + command captured (stub id -> root so the root check passes) ---
# shellcheck disable=SC2317  ## shadows the id command for parse_args's root check
id() {
   printf '%s' '0'
}
disk=""
cmd=()
format=""
parse_args run --disk "${work}/disk.vdi" -- echo hello world
check 'disk captured from --disk' "${disk}" "${work}/disk.vdi"
check 'command after -- captured verbatim' "${cmd[*]}" 'echo hello world'
check 'format defaults to vdi (pinned, never probed)' "${format}" 'vdi'

disk=""
cmd=()
format=""
parse_args run --disk "${work}/disk.vdi" --format qcow2 -- echo x
check 'format overridden by --format' "${format}" 'qcow2'

## --- teardown seam: cleanup with no state (empty since sourcing) is a safe no-op under
## nounset, proving the lib's :- guards hold for a tool that set no state. ----
rc=0
cleanup || rc=$?
check 'cleanup tolerates empty state' "${rc}" '0'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
