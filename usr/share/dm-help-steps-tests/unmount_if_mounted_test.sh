#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## unmount_if_mounted (variables.d/05_lib.bsh) is the shared primitive the chroot
## teardown callers (help-steps/unchroot-raw, help-steps/unmount-raw) use in place
## of a plain 'umount'. Those callers pass paths that MAY OR MAY NOT be mounted
## (bind mounts that were never set up, an already-unmounted CHROOT_FOLDER) and run
## under 'set -o errexit', so the function must:
##   1. NO-OP when the path is not a mountpoint (a plain 'umount' there would exit
##      non-zero and errexit would break the build) -- the load-bearing guard;
##   2. call 'umount' when it IS a mountpoint;
##   3. propagate a failing 'umount' (return non-zero) so errexit fails the build.
##
## The real function is SOURCED. 'mountpoint' and 'umount' are stubbed so the test
## needs no root and no real mounts; SUDO_TO_ROOT is emptied so the stub bash
## functions (not external binaries) are what the function calls.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

lib="${dm_checkout}/variables.d/05_lib.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

## Empty so '${SUDO_TO_ROOT} mountpoint ...' resolves the stub bash functions
## below rather than dispatching through 'sudo'/'env' to the real binaries.
# shellcheck disable=SC2034  # read by the sourced unmount_if_mounted, not directly here
SUDO_TO_ROOT=""

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## --- stubs -----------------------------------------------------------------
## Controls + recorders reset before each case. mountpoint(1) exit codes:
## 0 = is a mountpoint, 32 = not a mountpoint, other = error.
stub_mp_rc=0           ## exit code the mountpoint stub returns
stub_umount_rc=0       ## exit code the umount stub returns
mountpoint_called=0    ## times the mountpoint stub ran
umount_called=0        ## times the umount stub ran
umount_last_path=""    ## last path the umount stub saw

reset_stubs() {
   stub_mp_rc=0
   stub_umount_rc=0
   mountpoint_called=0
   umount_called=0
   umount_last_path=""
}

## Shadow the real commands. Last argument is the path (callers pass
## '--quiet -- PATH' / '--verbose -- PATH').
# shellcheck disable=SC2317  # invoked indirectly, from the sourced unmount_if_mounted
mountpoint() {
   mountpoint_called=$(( mountpoint_called + 1 ))
   return "${stub_mp_rc}"
}
# shellcheck disable=SC2317  # invoked indirectly, from the sourced unmount_if_mounted
umount() {
   umount_called=$(( umount_called + 1 ))
   umount_last_path="${!#}"
   return "${stub_umount_rc}"
}

## A real existing target so the 'test -e' existence pre-check passes and the
## mountpoint stub decides the outcome. (SUDO_TO_ROOT="" above, so 'test' is the
## shell builtin against the real filesystem.)
work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT
target="${work_dir}/target"
touch -- "${target}"

## --- case 1: not a mountpoint (exit 32) -> no-op, umount NEVER called -------
reset_stubs
stub_mp_rc=32
if unmount_if_mounted "${target}" ; then
   if [ "${umount_called}" = "0" ]; then
      pass "not a mountpoint (32): returns 0 and does not call umount"
   else
      fail "not a mountpoint (32): umount was called ${umount_called} time(s)"
   fi
else
   fail "not a mountpoint (32): expected return 0, got non-zero"
fi

## --- case 2: is a mountpoint (0), umount succeeds --------------------------
reset_stubs
stub_mp_rc=0
stub_umount_rc=0
if unmount_if_mounted "${target}" ; then
   if [ "${umount_called}" = "1" ] && [ "${umount_last_path}" = "${target}" ]; then
      pass "mounted: calls umount once on the path and returns 0"
   else
      fail "mounted: umount_called=${umount_called} path='${umount_last_path}'"
   fi
else
   fail "mounted+umount ok: expected return 0, got non-zero"
fi

## --- case 3: mountpoint ERROR (exit 1) on an existing path -> PROPAGATE -----
## The finding: 'mountpoint --quiet ... || return 0' swallowed a genuine error
## (exit 1: bad invocation / system error) as "not mounted", returning success
## and skipping umount, so a caller could delete across an undetermined mount.
reset_stubs
stub_mp_rc=1
if unmount_if_mounted "${target}" ; then
   fail "mountpoint error (1): swallowed as success -- must propagate the error"
else
   if [ "${umount_called}" = "0" ]; then
      pass "mountpoint error (1): propagates non-zero and does not umount"
   else
      fail "mountpoint error (1): umount ran despite an undetermined mount state"
   fi
fi

## --- case 4: nonexistent path -> no-op, mountpoint NEVER consulted ----------
## A missing target is nothing to unmount, and must not be conflated with the
## exit-1 error above (mountpoint shares exit 1 for a nonexistent path).
reset_stubs
stub_mp_rc=1
if unmount_if_mounted "${work_dir}/absent" ; then
   if [ "${mountpoint_called}" = "0" ] && [ "${umount_called}" = "0" ]; then
      pass "absent path: no-op (return 0), mountpoint not consulted"
   else
      fail "absent path: mountpoint_called=${mountpoint_called} umount_called=${umount_called}"
   fi
else
   fail "absent path: expected return 0, got non-zero"
fi

## --- case 5: is a mountpoint, umount fails -> propagate non-zero -----------
reset_stubs
stub_mp_rc=0
stub_umount_rc=1
if unmount_if_mounted "${target}" ; then
   fail "mounted+umount fails: expected non-zero return, got 0"
else
   pass "mounted+umount fails: propagates non-zero (errexit would fail the build)"
fi

summary_line="===== unmount_if_mounted: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
