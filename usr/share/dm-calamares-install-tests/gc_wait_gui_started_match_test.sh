#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins gc_wait_gui_started's MATCH mode (vbox-session.bsh). The panel-respawn poll in
## gui_freeze_guest_clock runs right after a SIGKILL of lxqt-panel, so it MUST match the
## process by exact NAME (pgrep -x): a -f (full command-line) poll self-matches the invoking
## guest shell -- whose own command line carries the pattern 'lxqt-panel' -- and would report
## the panel back up WITHOUT a real respawn, leaving a story frame with no panel. Generic GUI
## launches (a program started with a path/args, e.g. 'calamares') keep the default -f.
##
## Drives the REAL gc_wait_gui_started (sourced define-only from the shipped dm-calamares-install,
## which sources vbox-session.bsh) with gc_run stubbed to capture the pgrep command it builds.
## No VM, no guest.

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

## Globals the sourced script reads at define time.
# shellcheck disable=SC2034
vm="testvm"
export VBOX_EXEC_LOCAL="/bin/true"

# shellcheck disable=SC1090
source "${subject}"

cmdlog="${work}/cmdlog"

## gc_run stub: record the guest command string ($2) that gc_wait_gui_started builds, and
## succeed so the poll returns on its first iteration (no sleep, no real pgrep).
# shellcheck disable=SC2317
gc_run() {
   printf '%s\n' "$2" >> "${cmdlog}"
   return 0
}

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() {
   case "$2" in
      *"$1"*)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

## --- exact (-x) mode: the panel-respawn poll -------------------------------------------------
true > "${cmdlog}"
gc_wait_gui_started user 'lxqt-panel' 30 '-x'
log="$(cat -- "${cmdlog}")"
got=0
has 'pgrep -x -- lxqt-panel' "${log}" || got=1
check "exact mode builds 'pgrep -x -- lxqt-panel' (no self-match of the invoking shell)" "${got}"
got=0
has 'pgrep -f' "${log}" && got=1
check "exact mode does NOT build a -f poll" "${got}"

## --- default mode: a generic GUI launch (e.g. calamares) keeps full-cmdline matching ---------
true > "${cmdlog}"
gc_wait_gui_started live 'calamares' 30
log="$(cat -- "${cmdlog}")"
got=0
has 'pgrep -f -- calamares' "${log}" || got=1
check "default mode keeps 'pgrep -f -- calamares' (generic launch, matched by command line)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
