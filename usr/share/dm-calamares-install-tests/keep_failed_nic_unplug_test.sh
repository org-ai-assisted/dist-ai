#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-calamares-install's --keep-failed NIC-unplug fail-closed discovery.
##
## THE BUG IT GUARDS (leak-integrity fail-open): on_exit kept a FAILED VM running for inspection
## only when EVERY configured NIC was unplugged, else powered it off ("fail safe"). It discovered
## NICs with `mapfile -t nics < <(vm_nic_indices ... || true)`, discarding the exit status. If
## VBoxManage showvminfo emitted PARTIAL output then died (pipefail -> vm_nic_indices nonzero),
## the `|| true` accepted the TRUNCATED list as complete: the discovered NICs unplugged, but an
## undiscovered one stayed CONNECTED while on_exit reported "network unplugged" -- a NAT-connected
## failed test VM = a leak. on_exit now captures discovery's exit status and fails CLOSED (powers
## the VM off) when discovery fails or is truncated.
##
## Drives the REAL on_exit (sourced define-only), with VBoxManage + the guestcontrol launch-log
## stubbed and vm_nic_indices forced into its failure / success branches. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

## --- stubs -------------------------------------------------------------------------------
## VBoxManage: record each invocation; setlinkstate + poweroff "succeed".
# shellcheck disable=SC2317
VBOXMANAGE_stub() {
   printf '%s\n' "$*" >> "${VBOX_LOG}"
   return 0
}
# shellcheck disable=SC2034  ## read by the sourced on_exit in the run_on_exit subshell
VBOXMANAGE="VBOXMANAGE_stub"
## guestcontrol launch-log fetch: empty, so on_exit's launch-log block no-ops.
# shellcheck disable=SC2317
gc_gui_launch_log() {
   printf '%s' ""
}
## vm_nic_indices: forced per-case via FAKE_NIC. 'fail' = partial output THEN nonzero (the bug
## trigger: showvminfo died mid-list); 'full' = two NICs, clean; empty handled too.
# shellcheck disable=SC2317
vm_nic_indices() {
   case "${FAKE_NIC:-}" in
      fail)
         ## printed nic1, then "died"
         printf '%s\n' 1
         return 1
         ;;
      full)
         printf '%s\n' 1 2
         return 0
         ;;
      *)
         return 0
         ;;
   esac
}

## Globals on_exit reads.
# shellcheck disable=SC2034
VBOX_LOG="${work}/vbox.log"
# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
HOME="${work}"
# shellcheck disable=SC2034
shot=""
# shellcheck disable=SC2034
shot_dir=""
# shellcheck disable=SC2034
check_log="${work}/checklog"
# shellcheck disable=SC2034
vm_started="true"
# shellcheck disable=SC2034
keep_failed="true"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## Trigger on_exit with rc=5 (the `|| on_exit` form passes $?=5 without toggling errexit).
run_on_exit() {
   true > "${VBOX_LOG}"
   ( bash -c 'exit 5' || on_exit ) >"${work}/stderr" 2>&1 || true
}

## --- Case FAIL: truncated discovery -> fail CLOSED (power off), not kept-and-leaking ---------
FAKE_NIC='fail' run_on_exit
got=0; has 'poweroff' "$(cat -- "${VBOX_LOG}")" || got=1
check "truncated NIC discovery -> VM powered OFF (fail-closed, no leak)" "${got}"
got=0; if has 'running for inspection, network unplugged' "$(cat -- "${work}/stderr")"; then got=1; fi
check "truncated NIC discovery -> does NOT claim 'network unplugged'" "${got}"

## --- Case FULL: all NICs discovered + unplugged -> kept running, no poweroff ------------------
FAKE_NIC='full' run_on_exit
got=0; has 'running for inspection, network unplugged' "$(cat -- "${work}/stderr")" || got=1
check "all NICs unplugged -> VM kept running for inspection" "${got}"
got=0; if has 'poweroff' "$(cat -- "${VBOX_LOG}")"; then got=1; fi
check "all NICs unplugged -> VM NOT powered off" "${got}"
got=0; has 'setlinkstate1 off' "$(cat -- "${VBOX_LOG}")" && has 'setlinkstate2 off' "$(cat -- "${VBOX_LOG}")" || got=1
check "all NICs unplugged -> every discovered NIC was unplugged" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
