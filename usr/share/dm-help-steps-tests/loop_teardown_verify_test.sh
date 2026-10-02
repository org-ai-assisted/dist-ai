#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## loop_teardown_verify (help-steps/misc-helpers.bsh) is the shared teardown-
## verification primitive for the raw-image build: help-steps/unmount-raw and the
## mount-test self-test in build-steps.d/1100_sanity-tests both call it after
## 'kpartx -d' to release and verify the loop devices backing an image.
##
## REGRESSION: building a non-Qubes image inside a Qubes/Xen build VM (and inside
## docker) aborted with a benign "teardown did not release cleanly" error. In
## those environments 'kpartx -d' reports a partition map "in use. Not removing"
## and leaves the backing loop device attached; the previous code did a ONE-SHOT
## 'losetup --associated' check immediately after and treated the still-attached
## loop as a fatal failure. Its intended rescue -- an explicit per-device
## 'losetup -d -- <dev>' -- was itself broken: util-linux's detach mode parses the
## '--' AS the device ("losetup: /dev/--: detach failed"), so the detach silently
## no-opped under '|| true' and the loop stayed attached.
##
## loop_teardown_verify must:
##   1. release a loop that an explicit 'losetup --detach <dev>' (NO '--') frees,
##      returning 0 (the benign Qubes/docker false positive);
##   2. release a loop that only clears on a later poll (udev/kernel async), via
##      its bounded re-poll, returning 0 -- WITHOUT depending on udev firing;
##   3. still return NON-ZERO for a genuinely stuck loop that remains associated
##      after every explicit-detach attempt (no masking of a real failure);
##   4. return 0 and attempt no detach when nothing is associated.
##
## The real function is SOURCED. 'losetup'/'kpartx'/'udevadm'/'sleep' are stubbed
## so the test needs no root and no real loop devices; SUDO_TO_ROOT is emptied so
## the stub bash functions (not external binaries) are what the function calls.

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

lib="${dm_checkout}/help-steps/misc-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

## Empty so '${SUDO_TO_ROOT} losetup ...' resolves the stub bash functions below
## rather than dispatching through 'sudo'/'env' to the real binaries.
# shellcheck disable=SC2034  # read by the sourced loop_teardown_verify, not directly here
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
## State controlling what the stubbed 'losetup --associated' reports and how the
## stubbed 'losetup --detach' / re-poll change it. Reset before each case.
##
## loop_teardown_verify reads 'losetup --associated' inside a command
## substitution '$(...)', which runs in a SUBSHELL -- so that stub's in-memory
## mutations would be lost. The poll counter is therefore FILE-backed (survives
## the subshell), and the clear-on-Nth-poll decision is made from it. The
## 'losetup --detach' / kpartx stubs run in the function's here-string loop (no
## subshell), so their parent-shell counters persist normally.
stub_assoc=""            ## device 'losetup --associated' reports ("" = none)
stub_detach_releases=0   ## 1: a 'losetup --detach' call clears stub_assoc (benign)
stub_clear_after_polls=0 ## >0: report empty once --associated has been polled N times
detach_called=0          ## times 'losetup --detach' ran
detach_last=""           ## last device 'losetup --detach' saw
kpartx_called=0          ## times the kpartx stub ran

poll_file="$(mktemp)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --force -- "${poll_file}"; }
trap cleanup EXIT

reset_stubs() {
   stub_assoc=""
   stub_detach_releases=0
   stub_clear_after_polls=0
   detach_called=0
   detach_last=""
   kpartx_called=0
   printf '%s' "0" > "${poll_file}"
}

## losetup stub. Dispatches on the first word:
##   --associated <img> --noheadings --output NAME  -> print stub_assoc (if any)
##   --detach <dev>                                 -> record + maybe release
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
losetup() {
   local poll_now
   case "${1:-}" in
      --associated)
         poll_now="$(cat -- "${poll_file}" 2>/dev/null || printf '%s' 0)"
         poll_now=$(( poll_now + 1 ))
         printf '%s' "${poll_now}" > "${poll_file}"
         if [ "${stub_clear_after_polls}" -gt 0 ] && [ "${poll_now}" -ge "${stub_clear_after_polls}" ]; then
            true "released by the time of this re-poll, report nothing"
         elif [ -n "${stub_assoc}" ]; then
            printf '%s\n' "${stub_assoc}"
         fi
         ;;
      --detach)
         detach_called=$(( detach_called + 1 ))
         detach_last="${2:-}"
         if [ "${stub_detach_releases}" = "1" ]; then
            stub_assoc=""
         fi
         ;;
      *)
         true "any other losetup invocation (e.g. --all) is a harmless no-op here"
         ;;
   esac
}

# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
kpartx() {
   kpartx_called=$(( kpartx_called + 1 ))
}

# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
udevadm() {
   true
}

## Make the bounded re-poll instant -- exercises the real retry code with no
## wall-clock cost.
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
sleep() {
   true
}

img="/path/to/image.raw"

## --- case 1: already clean -> return 0, no detach attempted -----------------
reset_stubs
stub_assoc=""
if loop_teardown_verify "${img}" ; then
   if [ "${detach_called}" = "0" ]; then
      pass "already clean: returns 0 without attempting a detach"
   else
      fail "already clean: detach attempted ${detach_called} time(s)"
   fi
else
   fail "already clean: expected return 0, got non-zero"
fi

## --- case 2: benign -- explicit 'losetup --detach' releases the loop --------
## (the Qubes/docker false positive: kpartx -d left it attached, losetup -d frees it)
reset_stubs
stub_assoc="/dev/loop7"
stub_detach_releases=1
if loop_teardown_verify "${img}" ; then
   if [ "${detach_called}" -ge "1" ] && [ "${detach_last}" = "/dev/loop7" ]; then
      pass "benign (detach frees it): returns 0 after an explicit losetup --detach"
   else
      fail "benign: detach_called=${detach_called} detach_last='${detach_last}'"
   fi
else
   fail "benign (detach frees it): expected return 0, got non-zero (one-shot regression)"
fi

## --- case 3: benign -- clears only on a later poll (udev/kernel async) -------
## Proves the bounded re-poll absorbs a transient reference without relying on
## udev firing (detach itself does NOT clear it here).
reset_stubs
stub_assoc="/dev/loop7"
stub_detach_releases=0
stub_clear_after_polls=2
if loop_teardown_verify "${img}" ; then
   pass "benign (clears on re-poll): returns 0 via the bounded retry"
else
   fail "benign (clears on re-poll): expected return 0, got non-zero"
fi

## --- case 4: genuinely stuck -> return NON-ZERO, no masking -----------------
## The loop stays associated no matter how many times it is detached/re-polled.
reset_stubs
stub_assoc="/dev/loop7"
stub_detach_releases=0
stub_clear_after_polls=0
if loop_teardown_verify "${img}" ; then
   fail "genuine stuck: expected non-zero return, got 0 (fix would MASK a real failure)"
else
   if [ "${detach_called}" -ge "1" ]; then
      pass "genuine stuck: returns non-zero after attempting explicit detach (no mask)"
   else
      fail "genuine stuck: returned non-zero but never attempted a detach"
   fi
fi

## --- case 5: empty image argument -> return non-zero (programming guard) -----
reset_stubs
if loop_teardown_verify "" ; then
   fail "empty image: expected non-zero return, got 0"
else
   pass "empty image: returns non-zero"
fi

summary_line="===== loop_teardown_verify: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
