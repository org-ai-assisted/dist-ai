#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/pre' UNSHARE_PID_NS: the build runs
## grml-debootstrap / cowbuilder / VM-image steps under this wrapper, which MUST create a
## private MOUNT namespace, not only a PID namespace. Without '--mount --propagation
## private' the build's transient loop-partition mounts land in the HOST mount namespace
## with shared propagation; a concurrently-starting peer (e.g. an AI-review bwrap
## '--unshare-all' sandbox) then clones the host mount table and PINS the loop partition in
## its own namespace. The build's end-of-image 'kpartx -d' fails ("device busy") and the
## whole build aborts (observed on the OVH build host, 'kpartx -d "${ORIG_TARGET}"' rc=1).
##
## Drives the REAL help-steps/pre value (parsed from the file, not a copy), so dropping the
## flags regresses this test. Two assertions:
##   - static:     the UNSHARE_PID_NS default carries '--mount' and '--propagation private';
##   - behavioral: a bind mount made under that REAL wrapper is INVISIBLE to the host mount
##                 namespace (isolated), while a bare 'unshare --pid' wrapper LEAKS it
##                 (the canary proving the behavioral check can detect the bug).
##
## Needs mount capability; the dm-help-steps-tests runner re-execs under root for exactly
## this class of test. A non-root invocation is a HARD ERROR, never a silent skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

pre_path="${dm_checkout}/help-steps/pre"
if [ ! -r "${pre_path}" ]; then
   printf '%s\n' "FATAL: help-steps/pre not found at ${pre_path} (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

## Parse the REAL default assignment:
##   [ -v UNSHARE_PID_NS ] || UNSHARE_PID_NS="unshare ... --"
## Take the value between the first UNSHARE_PID_NS=" and the next ". Pure parameter
## expansion (no awk/sed) so a stray '--' token cannot be misread as a file operand.
assign_line="$(grep -F 'UNSHARE_PID_NS="unshare' -- "${pre_path}" | head -n 1 || true)"
if [ -z "${assign_line}" ]; then
   printf '%s\n' "FATAL: no UNSHARE_PID_NS=\"unshare ...\" assignment in ${pre_path}." >&2
   exit 1
fi
real_wrapper="${assign_line#*UNSHARE_PID_NS=\"}"
real_wrapper="${real_wrapper%%\"*}"
printf '%s\n' "UNSHARE_PID_NS (real) = ${real_wrapper}"

## --- static assertions on the real value ---
case "${real_wrapper}" in
   *' --mount '*|*' --mount')
      pass 'UNSHARE_PID_NS creates a mount namespace (--mount)'
      ;;
   *)
      fail "UNSHARE_PID_NS lacks --mount: ${real_wrapper}"
      ;;
esac
case "${real_wrapper}" in
   *'--propagation private'*)
      pass 'UNSHARE_PID_NS sets private mount propagation'
      ;;
   *)
      fail "UNSHARE_PID_NS lacks --propagation private: ${real_wrapper}"
      ;;
esac

## --- behavioral: mount capability required (root gate, like mount_cleanup) ---
if [ ! "${EUID}" = '0' ]; then
   printf '%s\n' "FATAL: not root -- the bind-mount isolation check needs mount capability." >&2
   printf '%s\n' "       (dm-help-steps-tests re-execs under sudo; run it, not this test bare.)" >&2
   exit 1
fi

work="$(mktemp --directory)"
mp="${work}/dst"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { umount -- "${mp}" >/dev/null 2>&1 || true; safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT
mkdir -p -- "${work}/src" "${mp}"
touch -- "${work}/src/marker"

## Does THIS (host) mount namespace currently contain a bind mount at ${mp}?
host_sees() { grep -F -- " ${mp} " /proc/self/mountinfo >/dev/null 2>&1; }

## Run the bind under ${wrapper} (word-split intentionally), hold it briefly, and report
## whether the host namespace observed the mount while it was live. Returns 0 == isolated.
isolated_under() {
   local wrapper="$1" ready wpid i
   umount -- "${mp}" >/dev/null 2>&1 || true
   ready="${work}/ready"; safe-rm --force -- "${ready}"
   # shellcheck disable=SC2086  ## ${wrapper} is a command + flags, must word-split
   ${wrapper} bash -c "mount --bind '${work}/src' '${mp}'; : > '${ready}'; sleep 2" &
   wpid=$!
   i=0
   while [ ! -f "${ready}" ] && [ "${i}" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
   if host_sees; then
      wait "${wpid}" 2>/dev/null || true
      return 1
   fi
   wait "${wpid}" 2>/dev/null || true
   return 0
}

## Canary: the OLD wrapper (pid-ns only) MUST leak, or the behavioral check proves nothing.
if isolated_under 'unshare --pid --fork --kill-child --'; then
   fail 'canary: a bare pid-ns wrapper did NOT leak -- the isolation check cannot detect the bug'
else
   pass 'canary: a bare pid-ns wrapper leaks the mount into the host namespace (bug reproduced)'
fi

## Fix: the REAL wrapper MUST isolate -- the host never sees the build's mount.
if isolated_under "${real_wrapper}"; then
   pass 'the real UNSHARE_PID_NS isolates the mount (no concurrent peer can pin it)'
else
   fail 'the real UNSHARE_PID_NS still leaks the mount into the host namespace'
fi

printf '%s\n' "unshare_mount_isolation_test.sh: $(( 4 - test_failures )) pass, ${test_failures} fail, 0 skip"
[ "${test_failures}" -eq 0 ]
